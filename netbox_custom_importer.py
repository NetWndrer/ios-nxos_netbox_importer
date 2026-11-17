import os
import logging
import getpass
import requests
import pynetbox
import ipaddress
import time
import urllib3
import re
import threading
from abc import ABC, abstractmethod
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL verification warnings if user disables verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================================
# CONFIG
# ==========================================================
NETBOX_URL = "http://127.0.0.1:8001"
MAX_WORKERS = min(15, (os.cpu_count() or 2) * 5)
SSH_RETRIES = 3
SSH_TIMEOUT = 30
SSH_READ_TIMEOUT = 30
RETRY_BACKOFF_BASE = 1
VERIFY_SSL = os.getenv("NETBOX_VERIFY_SSL", "false").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# Device Type Overwrite Settings (Safe-by-default: opt-in via env var or toggle)
OVERWRITE_DEVICE_TYPE = os.getenv("OVERWRITE_DEVICE_TYPE", "false").lower() == "true"
AUTO_CREATE_DEVICE_TYPES = os.getenv("AUTO_CREATE_DEVICE_TYPES", "false").lower() == "true"
DEFAULT_MANUFACTURER_NAME = "Cisco"

# Exclude device types/platforms from SSH collection.
# Write slugs exactly as they appear in NetBox (e.g. "pan-os", "cisco-wlc"); they are normalized
# (case, '-', '_', '/', spaces stripped) before comparison, the same way device slugs are.
# Note: devices whose platform is not IOS/IOS-XE/NX-OS are skipped automatically and never SSH'd to,
# so this list is only needed to skip platforms that WOULD otherwise match (e.g. an "ios"-named slug).
EXCLUDED_PLATFORMS = ["aci", "apic", "pan-os", "uiw"]
EXCLUDED_DEVICE_TYPES = []  # Device type slugs to skip (normalized the same way)

LOG_LEVEL_NAME = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL_NAME, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Lock for thread-safe creation/caching of NetBox Device Types
DEVICE_TYPE_LOCK = threading.Lock()

# ==========================================================
# ACCOUNT LOCKOUT PROTECTION
# ==========================================================
# Authentication failures are NEVER retried per device (only timeouts are). Across all threads, once
# AUTH_FAILURE_LIMIT devices reject the credentials, the circuit breaker trips and every device not yet
# connected is skipped. Keep this below your TACACS/RADIUS/AD lockout threshold.
AUTH_FAILURE_LIMIT = max(1, int(os.getenv("AUTH_FAILURE_LIMIT", "2")))
# Pre-flight: try up to this many devices (sequentially) to prove the credentials before threading.
CRED_CHECK_MAX_DEVICES = max(1, int(os.getenv("CRED_CHECK_MAX_DEVICES", "3")))

AUTH_ABORT_EVENT = threading.Event()
_AUTH_FAILURE_LOCK = threading.Lock()
_AUTH_FAILURE_COUNT = 0


def record_auth_failure(device_name):
    """Count an authentication failure; trip the global circuit breaker once the limit is reached."""
    global _AUTH_FAILURE_COUNT
    with _AUTH_FAILURE_LOCK:
        _AUTH_FAILURE_COUNT += 1
        count = _AUTH_FAILURE_COUNT
        if count >= AUTH_FAILURE_LIMIT and not AUTH_ABORT_EVENT.is_set():
            AUTH_ABORT_EVENT.set()
            logger.error(
                f"[LOCKOUT-GUARD] {count} authentication failure(s) (latest: {device_name}) reached "
                f"AUTH_FAILURE_LIMIT={AUTH_FAILURE_LIMIT}. Skipping all remaining devices to protect the account."
            )
    return count

# ==========================================================
# SLUG NORMALIZATION
# ==========================================================
def normalize_slug(slug):
    """Normalize slugs for robust, case-insensitive string matching"""
    if not slug:
        return ""
    return str(slug).lower().replace("-", "").replace("_", "").replace("/", "").replace(" ", "").strip()


def get_platform_family(platform_slug):
    """Map a NetBox platform slug to a supported collector family: 'ios', 'nxos', or None if unsupported.
    Single source of truth used by device selection, the credential pre-check, get_driver and the worker."""
    slug_lower = str(platform_slug or "").lower().strip()
    norm = normalize_slug(platform_slug)
    if not norm:
        return None
    if slug_lower in ("ios-xe", "iosxe") or "iosxe" in norm or "ios" in norm:
        return "ios"
    if slug_lower in ("nx-os", "nxos") or "nxos" in norm:
        return "nxos"
    return None


def slugify_model(model_str):
    """Convert a hardware model/PID string into a valid NetBox URL-safe slug"""
    if not model_str:
        return ""
    slug = re.sub(r'[^a-z0-9]+', '-', str(model_str).lower()).strip('-')
    return slug


# ==========================================================
# INTERFACE NAME NORMALIZATION
# ==========================================================
def normalize_interface_name(name):
    """Normalize Cisco interface abbreviations to canonical full names."""
    if not name:
        return ""

    name = name.strip()

    # Order matters: longer/more specific prefixes must precede shorter ones that share
    # leading letters (e.g. 'twe' TwentyFiveGig before 'tw' TwoGig). Every pattern must be
    # followed by a digit (lookahead below) so an abbreviation never matches the start of a
    # longer name (e.g. 'Tw' inside 'TwoGigabitEthernet' or 'Te' inside 'TenGigE').
    MAPPING = {
        r'^(gigabitethernet|gigabit|gige|gig|gi)': 'GigabitEthernet',
        r'^(tengigabitethernet|tengigabit|tengige|tengig|teng|ten|te)': 'TenGigabitEthernet',
        r'^(twentyfivegigabitethernet|twentyfivegigabit|twentyfivegige|twentyfivegig|twentyfiveg|twe)': 'TwentyFiveGigabitEthernet',
        r'^(twogigabitethernet|twogige|tw)': 'TwoGigabitEthernet',              # Cat9k mGig 2.5G
        r'^(fivegigabitethernet|fivegige|fi)': 'FiveGigabitEthernet',           # Cat9k mGig 5G
        r'^(appgigabitethernet|ap)': 'AppGigabitEthernet',                      # Cat9k app-hosting port
        r'^(fortygigabitethernet|fortygigabit|fortygige|fortyg|fo)': 'FortyGigabitEthernet',
        r'^(hundredgigabitethernet|hundredgigabit|hundredgige|hundredgig|hundredg|hu)': 'HundredGigabitEthernet',
        r'^(fastethernet|fast|fa)': 'FastEthernet',
        r'^(ethernet|eth)': 'Ethernet',
        r'^(port-channel|po)': 'Port-channel',
        r'^(vlan|vl)': 'Vlan',
        r'^(loopback|lo)': 'Loopback',
        r'^(mgmt-ethernet|management|mgmt)': 'mgmt',
        r'^(me)': 'Management',
    }

    for pattern, canonical in MAPPING.items():
        match = re.match(pattern + r'(?=\s*\d)', name, re.IGNORECASE)
        if match:
            suffix = name[match.end():].strip()
            return f"{canonical}{suffix}"

    return name


# Canonical physical Ethernet prefixes (post-normalization). On switches, an interface with one of
# these prefixes must also appear in 'show interfaces status' or it is treated as a phantom port.
PHYSICAL_INTERFACE_PREFIXES = (
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigabitEthernet",
    "FortyGigabitEthernet",
    "HundredGigabitEthernet",
    "FastEthernet",
    "Ethernet"
)

# ==========================================================
# DRIVER FACTORY
# ==========================================================
def get_driver(platform_slug, ip, username, password):
    """Create Netmiko connection handler based on platform"""
    family = get_platform_family(platform_slug)
    if family == "ios":
        device_type = 'cisco_ios'
    elif family == "nxos":
        device_type = 'cisco_nxos'
    else:
        raise ValueError(f"Unsupported platform: {platform_slug}")

    conn = ConnectHandler(
        device_type=device_type,
        host=ip,
        username=username,
        password=password,
        # Increased timeout to handle slow TACACS authentication
        conn_timeout=60,
        # Timeout for the authentication process itself
        auth_timeout=60,
        # Time to wait for the banner before sending username
        banner_timeout=60,
        # Keep this for responsiveness after connection
        global_delay_factor=1.5
    )
    # Set read_timeout on the connection object for Netmiko 4.x compatibility
    conn.read_timeout = SSH_READ_TIMEOUT
    return conn

# ==========================================================
# INTERFACE TYPE CLASSIFICATION
# ==========================================================
def classify_interface_type(name):
    """Classify interface type based on Cisco/NX-OS naming conventions"""
    name_lower = name.lower()

    # Check LAG/Port-channel
    if name_lower.startswith("po") or "port-channel" in name_lower:
        return "lag"
    # Check Virtual interfaces
    elif name_lower.startswith("vl") or "vlan" in name_lower or name_lower.startswith("lo") or "loopback" in name_lower:
        return "virtual"
    # Check Mgmt interfaces
    elif name_lower.startswith("mgmt") or name_lower.startswith("me"):
        return "1000base-t"

    # Cat9k multigigabit / app-hosting ports (checked before the generic 'tw' 25G match below)
    if name_lower.startswith(("twogig", "tw")) and not name_lower.startswith(("twe", "twentyfive")):
        return "2.5gbase-t"
    if name_lower.startswith(("fivegig", "fi")):
        return "5gbase-t"
    if name_lower.startswith(("appgig", "ap")):
        return "virtual"

    # Match Ethernet interface speeds using exact prefixes/patterns to prevent overlapping
    # Check 100G interfaces
    if re.search(r'^(hu|hundred|hundredg)', name_lower):
        return "100gbase-x-cxp"
    # Check 40G interfaces
    elif re.search(r'^(fo|forty|fortyg)', name_lower):
        return "40gbase-x-qsfpp"
    # Check 25G interfaces
    elif re.search(r'^(tw|twentyfive|twentyfiveg)', name_lower):
        return "25gbase-x-sfp28"
    # Check 10G interfaces
    elif re.search(r'^(te|ten|teng|xe)', name_lower):
        return "10gbase-x-sfpp"

    # Check 1G / FastEthernet / Ethernet
    if re.search(r'^(gi|gig|gigabit|fa|fast|eth|ethernet)', name_lower):
        return "1000base-t"

    return "1000base-t"  # fallback


def classify_interface_type_by_speed(name, speed_str):
    """Determine the physical interface type slug based on interface name and operational speed"""
    name_lower = name.lower()

    # Check LAG/Port-channel
    if name_lower.startswith("po") or "port-channel" in name_lower:
        return "lag"
    # Check Virtual interfaces
    elif name_lower.startswith("vl") or "vlan" in name_lower or name_lower.startswith("lo") or "loopback" in name_lower:
        return "virtual"
    # Check Mgmt interfaces
    elif name_lower.startswith("mgmt") or name_lower.startswith("me"):
        return "1000base-t"

    # Check subinterface parent-child relationship (if there is a dot, it's virtual)
    if "." in name_lower:
        return "virtual"

    # mGig / app-hosting ports: the name states the port's max capability, while the
    # operational speed only reflects what was negotiated (often 1G), so trust the name.
    if name_lower.startswith(("twogigabitethernet", "fivegigabitethernet", "appgigabitethernet")):
        return classify_interface_type(name)

    # If speed string is available, map it directly to correct NetBox interface types
    if speed_str:
        speed_mbps = parse_speed(speed_str)
        if speed_mbps:
            if speed_mbps >= 100000:
                return "100gbase-x-cxp"
            elif speed_mbps >= 40000:
                return "40gbase-x-qsfpp"
            elif speed_mbps >= 25000:
                return "25gbase-x-sfp28"
            elif speed_mbps >= 10000:
                return "10gbase-x-sfpp"
            elif speed_mbps >= 5000:
                return "5gbase-t"
            elif speed_mbps >= 2500:
                return "2.5gbase-t"
            elif speed_mbps >= 1000:
                return "1000base-t"
            elif speed_mbps >= 100:
                return "100base-tx"

    # Fallback to name-based classification (with Nexus heuristics)
    return classify_interface_type(name)


# ==========================================================
# MANAGEMENT AND LOGICAL INTERFACE CHECK
# ==========================================================
def is_management_or_logical_interface(name):
    """Check if an interface is a logical/virtual interface or a dedicated management port."""
    if not name:
        return False
    name_lower = name.lower()

    # Virtual / logical prefixes
    logical_prefixes = ("vlan", "port-channel", "loopback", "tunnel", "null", "virtual", "po", "vl", "lo", "tu", "nu")
    if name_lower.startswith(logical_prefixes):
        return True

    # Dedicated management port patterns
    if name_lower.startswith(("mgmt", "management", "gigabitethernet0/0", "gigabitethernet0")):
        return True

    # me interface followed by digit or slash (e.g., me0, me1, me/0)
    if name_lower.startswith("me") and (len(name_lower) == 2 or name_lower[2].isdigit() or name_lower[2] == "/"):
        return True

    # Subinterfaces (e.g., GigabitEthernet1/0/1.100) are logical/virtual
    if "." in name_lower:
        return True

    return False


# ==========================================================
# INTERFACE TYPE RECONCILIATION GUARD
# ==========================================================
TYPE_SPEED_RANK = {
    "": 0,
    "other": 0,
    "100base-tx": 1,
    "1000base-t": 2,
    "2.5gbase-t": 3,
    "5gbase-t": 4,
    "10gbase-x-sfpp": 5,
    "25gbase-x-sfp28": 6,
    "40gbase-x-qsfpp": 7,
    "100gbase-x-cxp": 8
}

def should_update_type(current_type, correct_type):
    """Determine if an interface type should be updated in NetBox, safeguarding optical/LAG/virtual types."""
    if not correct_type:
        return False

    curr = str(current_type or "").lower().strip()
    corr = str(correct_type or "").lower().strip()

    if curr == corr:
        return False
    if curr in ("virtual", "lag"):
        return False

    # Prevent speed demotions (e.g. from 10G to 1G fallback when port is down)
    curr_rank = TYPE_SPEED_RANK.get(curr, 0)
    corr_rank = TYPE_SPEED_RANK.get(corr, 0)
    if curr_rank > corr_rank:
        return False

    GENERIC_TYPES = {
        "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-x-sfpp", "25gbase-x-sfp28",
        "40gbase-x-qsfpp", "100gbase-x-cxp", "100base-tx", "other", ""
    }

    if curr not in GENERIC_TYPES:
        speed_bands = [("100g",), ("40g",), ("25g",), ("10g",), ("1000base", "1g")]
        for band in speed_bands:
            if any(b in curr for b in band) and any(b in corr for b in band):
                return False

    return True


# ==========================================================
# SPEED VALUE CONVERTER (With 5% tolerance parsing)
# ==========================================================
def parse_speed(speed_val):
    """Convert switch speed output string to NetBox speed integer in Mbps with unit awareness"""
    if not speed_val:
        return None

    speed_str = str(speed_val).lower().strip()

    # Strip negotiation status prefixes like "a-", "auto-", etc.
    speed_str = re.sub(r'^(?:speed\s*:?\s*|a-|auto-)', '', speed_str).strip()

    if "auto" in speed_str or speed_str == "" or speed_str == "unassigned":
        return None

    # Match values like "100 g", "100g", "100gbps", "100 gbps"
    match_g = re.search(r'([\d.]+)\s*(?:g|gbps)', speed_str)
    if match_g:
        try:
            return int(float(match_g.group(1)) * 1000)
        except ValueError:
            pass

    # Match values like "1000 m", "1000m", "1000mbps", "1000 mbps"
    match_m = re.search(r'([\d.]+)\s*(?:m|mbps)', speed_str)
    if match_m:
        try:
            return int(float(match_m.group(1)))
        except ValueError:
            pass

    # Match values like "1000000 k", "1000000k", "1000000kbps", "1000000 kbps"
    match_k = re.search(r'([\d.]+)\s*(?:k|kbps|kbit)', speed_str)
    if match_k:
        try:
            return int(float(match_k.group(1)) / 1000)
        except ValueError:
            pass

    # Fallback to extract pure digits
    digits = "".join(filter(str.isdigit, speed_str))
    if not digits:
        return None

    try:
        speed_int = int(digits)
    except ValueError:
        return None

    # Heuristics for raw integers
    # 1. Very large values (bps): e.g., 10,000,000,000 bps (10G) or 100,000,000,000 bps (100G)
    if speed_int >= 1000000000:
        return int(speed_int / 1000000)
    # 2. Medium-large values (Kbps): e.g., 1,000,000 Kbps (1G), 10,000,000 Kbps (10G), 100,000,000 Kbps (100G)
    if speed_int >= 10000:
        if speed_int in [10000, 25000, 40000, 100000]:
            return speed_int
        return int(speed_int / 1000)

    # 3. Small values (Mbps): e.g. 10, 100, 1000
    valid_speeds = [10, 100, 1000, 2500, 5000, 10000, 25000, 40000, 100000]
    for speed in valid_speeds:
        if abs(speed_int - speed) / speed <= 0.05:
            return speed

    return None


# ==========================================================
# FALLBACK MANUAL PARSERS & HELPERS
# ==========================================================
def parse_raw_cli(raw_output):
    """Fallback manual parser for show ip interface brief when TextFSM fails or is missing"""
    parsed = []
    if not raw_output or not isinstance(raw_output, str):
        return parsed

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or "interface" in line.lower() or "ip-address" in line.lower() or "ip interface" in line.lower() or "status" in line.lower():
            continue

        # Match lines like:
        # IOS: GigabitEthernet0/0         192.168.1.1     YES NVRAM  up                    up
        # NX-OS: mgmt0                10.12.1.1       protocol-up/link-up/admin-up
        tokens = line.split()
        if len(tokens) >= 2:
            interface = tokens[0]
            ipaddr = tokens[1]

            # Simple validation on interface names
            if "/" in interface or "." in interface or interface.lower().startswith(("gi", "fa", "te", "tw", "fi", "ap", "fo", "hu", "et", "po", "vl", "lo", "mg", "me")):
                status_field = " ".join(tokens[2:]) if len(tokens) > 2 else "up"
                parsed.append({
                    "interface": interface,
                    "ipaddr": ipaddr,
                    "status": status_field
                })
    return parsed


def parse_inventory_raw(raw_text):
    """Fallback manual parser for 'show inventory' across IOS-XE and NX-OS when TextFSM fails."""
    items = []
    if not raw_text or not isinstance(raw_text, str):
        return items

    # Standard Cisco 'show inventory' blocks look like:
    # NAME: "Chassis", DESCR: "Nexus9000 C93180YC-FX Chassis"
    # PID: N9K-C93180YC-FX     , VID: V02 , SN: FDO21345678
    pattern = re.compile(
        r'NAME:\s*"?([^",\r\n]+)"?\s*,\s*DESCR:\s*"?([^"\r\n]+)"?\s*[\r\n]+'
        r'\s*PID:\s*([^,\r\n]*?)\s*,\s*VID:\s*([^,\r\n]*?)\s*,\s*SN:\s*([^\r\n]*)',
        re.IGNORECASE
    )
    for match in pattern.finditer(raw_text):
        items.append({
            "name": match.group(1).strip(),
            "descr": match.group(2).strip(),
            "pid": match.group(3).strip(),
            "vid": match.group(4).strip(),
            "sn": match.group(5).strip()
        })
    return items


def parse_version_raw(raw_text, is_nxos=False):
    """Fallback manual parser for 'show version' when TextFSM fails or returns raw string."""
    info = {
        "os_version": "",
        "image": "",
        "bootloader": "",
        "serial": "",
        "model": ""
    }
    if not raw_text or not isinstance(raw_text, str):
        return info

    if is_nxos:
        # NX-OS version
        ver_match = re.search(r'(?:NXOS:\s*version|system:\s*version)\s+([^\s\r\n]+)', raw_text, re.IGNORECASE)
        if ver_match:
            info["os_version"] = ver_match.group(1).strip()

        # NX-OS image
        img_match = re.search(r'NXOS image file is:\s*([^\s\r\n]+)', raw_text, re.IGNORECASE)
        if img_match:
            info["image"] = img_match.group(1).strip()

        # NX-OS serial
        sn_match = re.search(r'Processor Board ID\s+(\S+)', raw_text, re.IGNORECASE)
        if sn_match:
            info["serial"] = sn_match.group(1).strip()

        # NX-OS hardware model (e.g., "cisco Nexus9000 C93180YC-FX chassis" or "cisco Nexus 9000 C9336C-FX2 Chassis")
        hw_match = re.search(r'^\s*cisco\s+(?:Nexus\s*\d+\s+)?(\S+)\s+chassis', raw_text, re.IGNORECASE | re.MULTILINE)
        if hw_match:
            info["model"] = hw_match.group(1).strip()
    else:
        # IOS / IOS-XE version
        ver_match = re.search(r'Version\s+([^,\s\r\n]+)', raw_text, re.IGNORECASE)
        if ver_match:
            info["os_version"] = ver_match.group(1).strip()

        # IOS / IOS-XE image
        img_match = re.search(r'System image file is\s+"?([^"\s\r\n]+)"?', raw_text, re.IGNORECASE)
        if img_match:
            info["image"] = img_match.group(1).strip()

        # IOS / IOS-XE serial (prefer 'System Serial Number', fallback to 'Processor board ID')
        sn_match = re.search(r'System Serial Number\s*:\s*(\S+)', raw_text, re.IGNORECASE)
        if not sn_match:
            sn_match = re.search(r'Processor board ID\s+(\S+)', raw_text, re.IGNORECASE)
        if sn_match:
            info["serial"] = sn_match.group(1).strip()

        # IOS / IOS-XE model (prefer 'Model Number', fallback to processor line)
        model_match = re.search(r'Model Number\s*:\s*(\S+)', raw_text, re.IGNORECASE)
        if not model_match:
            model_match = re.search(r'^[Cc]isco\s+(\S+)\s+\([^\)]+\)\s+processor', raw_text, re.MULTILINE)
        if model_match:
            info["model"] = model_match.group(1).strip()

    return info


def is_chassis_inventory_item(item, index=0):
    """Determine if a 'show inventory' entry represents the base chassis/switch rather than a component."""
    name = (item.get("name") or "").strip().lower()
    descr = (item.get("descr") or "").strip().lower()
    pid = (item.get("pid") or "").strip().upper()

    if not pid and not item.get("sn"):
        return False

    # Exclude known non-chassis components (transceivers, PSUs, fans, linecards/modules, stack cables, slots)
    non_chassis_keywords = (
        "xcvr", "transceiver", "sfp", "qsfp", "psu", "power supply",
        "fan", "fantray", "subslot", "module", "sup", "supervisor", "uplink", "slot"
    )
    if any(k in name for k in non_chassis_keywords):
        return False

    if pid.startswith(("PWR-", "FAN-", "CAB-", "STACK-", "SFP-", "QSFP-", "GLC-", "CVR-")):
        return False

    # Explicit chassis indicators across IOS, IOS-XE (Catalyst/IE/ISR/ASR), and NX-OS
    if (
        "chassis" in name
        or "chassis" in descr
        or name in ("1", "switch 1")
        or name.startswith("switch 1 ")
        or "stack" in name
    ):
        return True

    # On standalone routers/switches, the first entry (index 0) is the chassis unless it looks like an interface
    if index == 0 and not is_transceiver_inventory_item(item):
        return True

    return False


def is_transceiver_inventory_item(item):
    """Detect transceivers across both NX-OS and IOS-XE.
    On IOS-XE, show inventory names transceivers after the port (e.g., 'Te1/1/1' or 'TenGigabitEthernet1/1/1')
    and puts the optic type in DESCR/PID (e.g., 'SFP-10GBase-SR', '1000BaseSX SFP').
    """
    name = (item.get("name") or "").strip().lower()
    descr = (item.get("descr") or "").strip().lower()
    pid = (item.get("pid") or "").strip().upper()

    xcvr_keywords = ("xcvr", "transceiver", "sfp", "qsfp", "cfp", "qdd", "osfp")
    if any(k in name for k in xcvr_keywords):
        return True

    # Check if name looks like a physical port (e.g., Gi1/0/1, Te1/1/1, TenGigabitEthernet1/1/1, Ethernet1/50)
    is_port_name = bool(re.match(
        r'^[a-z]+\d+(/\d+)+$',
        name
    ))
    optic_descr_keywords = (
        "sfp", "qsfp", "xcvr", "transceiver", "1000base", "10gbase",
        "25gbase", "40gbase", "100gbase", "400gbase", "base-t", "base-x", "twinax"
    )
    optic_pid_prefixes = ("SFP-", "QSFP-", "GLC-", "CVR-", "ONS-", "CXP-", "CPA-")

    if is_port_name and (any(k in descr for k in optic_descr_keywords) or pid.startswith(optic_pid_prefixes)):
        return True

    if pid.startswith(optic_pid_prefixes) and "chassis" not in name and "module" not in name:
        return True

    return False


def extract_first_str(val):
    """Safely extract a clean string from a value that might be a string or a list of strings (TextFSM List)."""
    if isinstance(val, list):
        for item in val:
            if item and str(item).strip():
                return str(item).strip()
        return ""
    if val is None:
        return ""
    return str(val).strip()


def parse_nxos_transceiver_raw(raw_text):
    """Fallback manual parser for show interface transceiver when TextFSM fails on NX-OS.
    Handles both block-style (per interface) and table-style outputs.
    """
    transceivers = []
    if not raw_text or not isinstance(raw_text, str):
        return transceivers

    # Detect if it's table-style
    lines = raw_text.splitlines()
    is_table = False

    # Simple check for table headers
    for line in lines[:15]:
        line_lower = line.lower()
        if "interface" in line_lower and ("serial" in line_lower or "s/n" in line_lower or "part" in line_lower):
            is_table = True
            break

    if is_table:
        for line in lines:
            line_strip = line.strip()
            if not line_strip or "interface" in line_strip.lower() or "---" in line_strip:
                continue
            tokens = line_strip.split()
            if len(tokens) >= 3:
                intf = tokens[0]
                if intf.lower().startswith(("eth", "ethernet", "mgmt")):
                    sn_val = ""
                    pid_val = "SFP"

                    # Search for serial number token (typically 11-12 chars uppercase alphanumeric)
                    for t in tokens[1:]:
                        if re.match(r'^[A-Z]{3}[0-9A-Z]{8,9}$', t):
                            sn_val = t
                            break

                    if sn_val:
                        # Find a part number (contains dash/digits, different from serial)
                        for t in tokens[1:]:
                            if t != sn_val and ("-" in t or any(c.isdigit() for c in t)) and len(t) > 4:
                                pid_val = t
                                break
                        transceivers.append({
                            "interface": intf,
                            "presence": "present",
                            "type": pid_val,
                            "part_number": pid_val,
                            "serial_number": sn_val
                        })
    else:
        current_intf = None
        presence = None
        type_val = None
        pn = None
        sn = None

        for line in lines:
            line_strip = line.strip()
            if not line_strip:
                continue

            tokens = line_strip.split()
            if tokens and tokens[0].lower().startswith(("ethernet", "eth", "mgmt")):
                if current_intf and (presence == "present" or sn):
                    transceivers.append({
                        "interface": current_intf,
                        "presence": presence or "present",
                        "type": type_val or pn or "SFP",
                        "part_number": pn or type_val or "SFP",
                        "serial_number": sn
                    })
                current_intf = tokens[0]
                presence = None
                type_val = None
                pn = None
                sn = None

                if "transceiver is present" in line_strip:
                    presence = "present"
            elif "transceiver is present" in line_strip:
                presence = "present"
            elif "type is" in line_strip:
                type_val = line_strip.split("type is")[-1].strip()
            elif "part number is" in line_strip:
                pn = line_strip.split("part number is")[-1].strip()
            elif "serial number is" in line_strip:
                sn = line_strip.split("serial number is")[-1].strip()

        if current_intf and (presence == "present" or sn):
            transceivers.append({
                "interface": current_intf,
                "presence": presence or "present",
                "type": type_val or pn or "SFP",
                "part_number": pn or type_val or "SFP",
                "serial_number": sn
            })

    return transceivers


def get_admin_state_from_brief(status_str, platform_slug):
    """Determine administrative enabled state from show ip interface brief status column"""
    if not status_str:
        return True
    status_lower = str(status_str).lower()
    slug_lower = str(platform_slug or "").lower().strip()
    norm = normalize_slug(platform_slug)

    if slug_lower in ("nx-os", "nxos") or "nxos" in norm:
        if "admin-down" in status_lower:
            return False
        if "admin-up" in status_lower:
            return True
    else:
        if "administratively down" in status_lower:
            return False

    return True


# ==========================================================
# NETBOX DEVICE TYPE RESOLUTION & CACHE
# ==========================================================
def build_device_type_cache(nb):
    """Pre-load all DeviceTypes and Manufacturers from NetBox into a fast lookup structure."""
    cache = {
        "by_exact": {},       # lowercased model or part_number -> list of DeviceType records
        "by_norm": {},        # normalize_slug(model / part_number / slug) -> list of DeviceType records
        "all": [],            # list of all DeviceType records
        "manufacturers": {}   # normalize_slug(mfg.name or mfg.slug) -> Manufacturer id
    }
    try:
        for mfg in nb.dcim.manufacturers.all():
            cache["manufacturers"][normalize_slug(mfg.name)] = mfg.id
            cache["manufacturers"][normalize_slug(mfg.slug)] = mfg.id

        for dt in nb.dcim.device_types.all():
            cache["all"].append(dt)
            model_str = (dt.model or "").strip()
            part_str = (getattr(dt, "part_number", "") or "").strip()
            slug_str = (dt.slug or "").strip()

            if model_str:
                cache["by_exact"].setdefault(model_str.lower(), []).append(dt)
                cache["by_norm"].setdefault(normalize_slug(model_str), []).append(dt)
            if part_str:
                cache["by_exact"].setdefault(part_str.lower(), []).append(dt)
                cache["by_norm"].setdefault(normalize_slug(part_str), []).append(dt)
            if slug_str:
                cache["by_norm"].setdefault(normalize_slug(slug_str), []).append(dt)

        logger.info(f"Pre-loaded {len(cache['all'])} device types from NetBox.")
    except Exception as e:
        logger.warning(f"Failed to pre-load device types from NetBox: {e}")

    return cache


def candidate_model_variants(raw_model):
    """Generate candidate PID/model variations, including friendly Cisco naming conventions."""
    if not raw_model:
        return []

    clean = raw_model.strip()
    variants = []

    def add_variant(v):
        if v and v not in variants:
            variants.append(v)

    add_variant(clean)

    # Strip common Cisco ordering/license suffixes like /K9
    no_k9 = re.sub(r'/K9$', '', clean, flags=re.IGNORECASE).strip()
    add_variant(no_k9)

    # Generate both PID-style and friendly-name variants
    for base in list(variants):
        upper = base.upper()

        # Nexus PIDs: e.g. N9K-C93180YC-FX <-> C93180YC-FX <-> Nexus 93180YC-FX
        nx_match = re.match(r'^(?:N[3579]K-)?C([3579]\d{3}\S*)$', upper)
        if nx_match:
            core_num = nx_match.group(1)  # e.g. "93180YC-FX"
            series = core_num[0]          # e.g. "9"
            add_variant(f"N{series}K-C{core_num}")
            add_variant(f"C{core_num}")
            add_variant(f"Nexus {core_num}")
            add_variant(f"Nexus C{core_num}")

        # Catalyst PIDs: e.g. C9300-48P / WS-C3850-48P <-> Catalyst 9300-48P / Catalyst 3850-48P
        cat_match = re.match(r'^(?:WS-)?C(\d{4}\S*)$', upper)
        if cat_match:
            core_num = cat_match.group(1)  # e.g. "9300-48P" or "3850-48P"
            add_variant(f"C{core_num}")
            add_variant(f"Catalyst {core_num}")
            add_variant(f"Catalyst C{core_num}")
            if core_num.startswith(("29", "35", "36", "37", "38", "45", "65")):
                add_variant(f"WS-C{core_num}")

    return variants


def _disambiguate_candidates(candidates, cisco_mfg_id, discovered_model=""):
    """Deduplicate candidate DeviceTypes by ID; if multiple remain, prefer Cisco manufacturer
    and tiebreak by exact part_number match against the discovered PID.
    """
    unique_by_id = {}
    for dt in candidates:
        unique_by_id[dt.id] = dt
    unique_list = list(unique_by_id.values())

    if len(unique_list) <= 1:
        return unique_list

    # If multiple device types matched (e.g., Cisco vs Meraki), filter to Cisco manufacturer if possible
    if cisco_mfg_id:
        cisco_only = [
            dt for dt in unique_list
            if getattr(dt, "manufacturer", None) and dt.manufacturer.id == cisco_mfg_id
        ]
        if len(cisco_only) == 1:
            return cisco_only
        if cisco_only:
            unique_list = cisco_only

    # Tiebreaker: if multiple candidates remain (e.g. 'N9K-C93180YC-FX' vs 'Nexus 93180YC-FX' with part_number set),
    # prefer the candidate whose part_number exactly matches the discovered PID.
    if discovered_model and len(unique_list) > 1:
        pid_low = discovered_model.strip().lower()
        exact_part_matches = [
            dt for dt in unique_list
            if (getattr(dt, "part_number", "") or "").strip().lower() == pid_low
        ]
        if len(exact_part_matches) == 1:
            return exact_part_matches

    return unique_list


def resolve_or_create_device_type(nb, device_name, discovered_model, fallback_mfg_id, dt_cache):
    """Resolve a discovered hardware PID/model to a NetBox DeviceType object.
    Returns (device_type_obj, match_method_or_warning_str).
    Refuses ambiguous matches when multiple NetBox DeviceTypes match.
    """
    if not discovered_model or not dt_cache:
        return None, "No model or cache available"

    variants = candidate_model_variants(discovered_model)

    with DEVICE_TYPE_LOCK:
        cisco_mfg_id = dt_cache["manufacturers"].get(normalize_slug(DEFAULT_MANUFACTURER_NAME))

        # Step 1: Exact match on model or part_number
        step1_hits = []
        for v in variants:
            v_low = v.lower()
            if v_low in dt_cache["by_exact"]:
                step1_hits.extend(dt_cache["by_exact"][v_low])
        step1_hits = _disambiguate_candidates(step1_hits, cisco_mfg_id, discovered_model)
        if len(step1_hits) == 1:
            dt = step1_hits[0]
            logger.debug(f"[{device_name}] Matched DeviceType '{dt.model}' (ID: {dt.id}) via Step 1 (exact match)")
            return dt, "exact"
        elif len(step1_hits) > 1:
            names = ", ".join(f"{d.model} (ID:{d.id})" for d in step1_hits)
            return None, f"Ambiguous exact DeviceType match for '{discovered_model}': [{names}]"

        # Step 2: Normalized slug match on model, part_number, or slug
        step2_hits = []
        for v in variants:
            v_norm = normalize_slug(v)
            if v_norm and v_norm in dt_cache["by_norm"]:
                step2_hits.extend(dt_cache["by_norm"][v_norm])
        step2_hits = _disambiguate_candidates(step2_hits, cisco_mfg_id, discovered_model)
        if len(step2_hits) == 1:
            dt = step2_hits[0]
            logger.debug(f"[{device_name}] Matched DeviceType '{dt.model}' (ID: {dt.id}) via Step 2 (normalized match)")
            return dt, "normalized"
        elif len(step2_hits) > 1:
            names = ", ".join(f"{d.model} (ID:{d.id})" for d in step2_hits)
            return None, f"Ambiguous normalized DeviceType match for '{discovered_model}': [{names}]"

        # Step 3: Fuzzy suffix match against cached device types (refuses if >1 candidate)
        step3_hits = []
        for v in variants:
            v_norm = normalize_slug(v)
            if len(v_norm) >= 5:
                for dt in dt_cache["all"]:
                    dt_model_norm = normalize_slug(dt.model)
                    dt_part_norm = normalize_slug(getattr(dt, "part_number", ""))
                    if dt_model_norm.endswith(v_norm) or (dt_part_norm and dt_part_norm.endswith(v_norm)):
                        step3_hits.append(dt)
        step3_hits = _disambiguate_candidates(step3_hits, cisco_mfg_id, discovered_model)
        if len(step3_hits) == 1:
            dt = step3_hits[0]
            logger.info(f"[{device_name}] Matched DeviceType '{dt.model}' (ID: {dt.id}) via Step 3 (fuzzy suffix match on '{discovered_model}')")
            return dt, "fuzzy-suffix"
        elif len(step3_hits) > 1:
            names = ", ".join(f"{d.model} (ID:{d.id})" for d in step3_hits)
            return None, f"Refusing ambiguous fuzzy suffix match for '{discovered_model}': multiple candidates [{names}]"

        # Step 4: Optional Auto-Create if not found in NetBox
        if not AUTO_CREATE_DEVICE_TYPES:
            return None, f"Discovered hardware model '{discovered_model}' not found in NetBox Device Types"

        # Prefer Cisco first since all collectors in this script target Cisco platforms
        mfg_id = cisco_mfg_id or fallback_mfg_id
        if not mfg_id:
            return None, f"Cannot auto-create DeviceType '{discovered_model}': Cisco manufacturer ID not found in NetBox"

        clean_model = discovered_model.strip()
        model_slug = slugify_model(clean_model)

        if DRY_RUN:
            logger.info(f"[DRY-RUN] [{device_name}] Would auto-create new DeviceType in NetBox: model={clean_model}, slug={model_slug}")
            class MockDeviceType:
                def __init__(self, model):
                    self.id = -1
                    self.model = model
            return MockDeviceType(clean_model), "auto-create (dry-run)"

        try:
            new_dt = nb.dcim.device_types.create(
                manufacturer=mfg_id,
                model=clean_model,
                slug=model_slug,
                part_number=clean_model
            )
            dt_cache["all"].append(new_dt)
            dt_cache["by_exact"].setdefault(clean_model.lower(), []).append(new_dt)
            dt_cache["by_norm"].setdefault(normalize_slug(clean_model), []).append(new_dt)
            logger.info(f"[DEVICE-TYPE] Auto-created new DeviceType in NetBox: {clean_model} (ID: {new_dt.id})")
            return new_dt, "auto-created"
        except Exception as e:
            return None, f"Failed to auto-create DeviceType '{clean_model}': {e}"


# ==========================================================
# DEVICE COLLECTOR STRATEGY PATTERN
# ==========================================================
class DeviceCollector(ABC):
    """Base class for OS-specific data collection"""

    def __init__(self, device_name, conn):
        self.device_name = device_name
        self.conn = conn

    @abstractmethod
    def collect_interface_details(self):
        """Collect interface speed, duplex, description, MTU, status"""
        pass

    @abstractmethod
    def collect_inventory(self):
        """Collect hardware/transceiver info"""
        pass

    @abstractmethod
    def collect_software_info(self):
        """Collect OS version, hardware model, and serial details"""
        pass


class IOSXECollector(DeviceCollector):
    """Collector for IOS-XE devices (Catalyst, IE, ISR/ASR series)"""

    def collect_interface_details(self):
        """Parse show interfaces for IOS-XE"""
        try:
            output = self.conn.send_command("show interfaces", use_textfsm=True)
            if not isinstance(output, list):
                logger.warning(f"[{self.device_name}] Invalid interface output")
                return {}

            interfaces = {}
            for intf in output:
                name = intf.get("interface", "")
                if name:
                    # Normalize interface name key
                    name_norm = normalize_interface_name(name)
                    try:
                        mtu_val = int(intf.get("mtu", 1500))
                    except (ValueError, TypeError):
                        mtu_val = 1500

                    # admin state in cisco_ios_show_interfaces textfsm is link_status (e.g. "administratively down")
                    link_status = intf.get("link_status", "").lower()
                    enabled_val = "administratively down" not in link_status and "admin" not in link_status

                    interfaces[name_norm] = {
                        "description": intf.get("description", ""),
                        "mtu": mtu_val,
                        "state": intf.get("protocol_status", "down").lower(),
                        "enabled": enabled_val,
                    }

            # get speed/duplex and track present status ports to filter phantom expansion interfaces
            status_ports = set()
            has_status_info = False
            status = self.conn.send_command("show interfaces status", use_textfsm=True)
            if isinstance(status, list) and len(status) > 0:
                has_status_info = True
                for intf in status:
                    name = intf.get("port", "")
                    # Normalize interface name key
                    name_norm = normalize_interface_name(name)
                    if name_norm:
                        status_ports.add(name_norm)
                    if name_norm in interfaces:
                        status_val = intf.get("status", "").lower()
                        is_disabled = "disabled" in status_val and "err-disabled" not in status_val
                        interfaces[name_norm].update({
                            "speed": intf.get("speed", ""),
                            "duplex": intf.get("duplex", ""),
                            "type": intf.get("type", ""),
                            "enabled": not is_disabled if status_val else interfaces[name_norm]["enabled"]
                        })

            # Filter out phantom expansion/modular interfaces on IOS-XE switches
            if has_status_info:
                physical_prefixes = PHYSICAL_INTERFACE_PREFIXES
                filtered_interfaces = {}
                for name, details in interfaces.items():
                    # If it is a physical Ethernet interface, it must exist in show interfaces status,
                    # unless it is an OOB management interface or logical interface.
                    if name.startswith(physical_prefixes):
                        if name not in status_ports and not is_management_or_logical_interface(name):
                            logger.info(f"[{self.device_name}] Filtering out phantom interface: {name}")
                            continue
                    filtered_interfaces[name] = details
                interfaces = filtered_interfaces

            logger.debug(f"[{self.device_name}] Collected {len(interfaces)} interface details")
            return interfaces

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect interface details: {e}")
            return {}

    def collect_inventory(self):
        """Parse show inventory for IOS-XE with raw fallback, broad chassis detection, and IOS-XE optic detection"""
        try:
            output = self.conn.send_command("show inventory", use_textfsm=True)
            if not isinstance(output, list) or not output:
                raw_inv = output if isinstance(output, str) and output else self.conn.send_command("show inventory")
                output = parse_inventory_raw(raw_inv)

            if not isinstance(output, list):
                return {}

            inventory = {
                "chassis": [],
                "modules": [],
                "transceivers": []
            }

            for idx, item in enumerate(output):
                name = (item.get("name") or "").strip()
                name_lower = name.lower()
                pid = (item.get("pid") or "").strip()
                sn = (item.get("sn") or "").strip()

                if is_chassis_inventory_item(item, index=idx):
                    inventory["chassis"].append({"name": name, "pid": pid, "sn": sn})
                elif is_transceiver_inventory_item(item):
                    inventory["transceivers"].append({"name": name, "pid": pid, "sn": sn})
                elif "module" in name_lower or "card" in name_lower or "subslot" in name_lower or "slot" in name_lower:
                    inventory["modules"].append({"name": name, "pid": pid, "sn": sn})

            # Exclude base modules (e.g. fixed switch Slot 1) that duplicate the chassis serial number
            chassis_sns = {c["sn"] for c in inventory["chassis"] if c.get("sn")}
            if chassis_sns:
                inventory["modules"] = [m for m in inventory["modules"] if not (m.get("sn") and m["sn"] in chassis_sns)]

            logger.debug(
                f"[{self.device_name}] Collected hardware inventory "
                f"(chassis={len(inventory['chassis'])}, modules={len(inventory['modules'])}, xcvrs={len(inventory['transceivers'])})"
            )
            return inventory

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect inventory: {e}")
            return {}

    def collect_software_info(self):
        """Parse show version for IOS-XE (handles TextFSM 'serial'/'hardware' lists + raw fallback)"""
        try:
            output = self.conn.send_command("show version", use_textfsm=True)
            if isinstance(output, list) and len(output) > 0:
                version_info = output[0]
                # Note: ntc-templates cisco_ios_show_version uses 'serial' (List) and 'hardware' (List)
                raw_serial = version_info.get("serial") or version_info.get("serial_number")
                raw_model = version_info.get("hardware") or version_info.get("model")
                return {
                    "os_version": extract_first_str(version_info.get("version")),
                    "image": extract_first_str(version_info.get("image_name") or version_info.get("running_image")),
                    "bootloader": extract_first_str(version_info.get("bootloader")),
                    "serial": extract_first_str(raw_serial),
                    "model": extract_first_str(raw_model)
                }

            # Fallback to raw CLI regex parser if TextFSM failed
            raw_text = output if isinstance(output, str) and output else self.conn.send_command("show version")
            return parse_version_raw(raw_text, is_nxos=False)

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect software info: {e}")
            return {}


class NXOSCollector(DeviceCollector):
    """Collector for NX-OS devices"""

    def collect_interface_details(self):
        """Parse show interface for NX-OS"""
        try:
            output = self.conn.send_command("show interface", use_textfsm=True)
            if not isinstance(output, list):
                logger.warning(f"[{self.device_name}] Invalid interface output")
                return {}

            interfaces = {}
            for intf in output:
                name = intf.get("interface", "")
                if name:
                    # Normalize interface name key
                    name_norm = normalize_interface_name(name)
                    try:
                        mtu_val = int(intf.get("mtu", 1500))
                    except (ValueError, TypeError):
                        mtu_val = 1500

                    interfaces[name_norm] = {
                        "description": intf.get("description", ""),
                        "mtu": mtu_val,
                        "state": intf.get("state", "down").lower(),
                        "enabled": intf.get("admin_state", "up").lower() == "up",
                        "speed": intf.get("speed", ""),
                        "duplex": intf.get("duplex", ""),
                    }

            logger.debug(f"[{self.device_name}] Collected {len(interfaces)} interface details")
            return interfaces

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect interface details: {e}")
            return {}

    def collect_inventory(self):
        """Parse show inventory and show interface transceiver for NX-OS"""
        try:
            # 1. Start with standard show inventory (with raw fallback)
            output = self.conn.send_command("show inventory", use_textfsm=True)
            if not isinstance(output, list) or not output:
                raw_inv = output if isinstance(output, str) and output else self.conn.send_command("show inventory")
                output = parse_inventory_raw(raw_inv)

            inventory = {
                "chassis": [],
                "modules": [],
                "transceivers": []
            }

            if isinstance(output, list):
                for idx, item in enumerate(output):
                    name = (item.get("name") or "").strip()
                    name_lower = name.lower()
                    pid = (item.get("pid") or "").strip()
                    sn = (item.get("sn") or "").strip()

                    if is_chassis_inventory_item(item, index=idx):
                        inventory["chassis"].append({"name": name, "pid": pid, "sn": sn})
                    elif is_transceiver_inventory_item(item):
                        inventory["transceivers"].append({"name": name, "pid": pid, "sn": sn})
                    elif "module" in name_lower or "card" in name_lower or "slot" in name_lower:
                        inventory["modules"].append({"name": name, "pid": pid, "sn": sn})

                # Exclude base modules (e.g. fixed Nexus 9K 'Slot 1') that duplicate the chassis serial number
                chassis_sns = {c["sn"] for c in inventory["chassis"] if c.get("sn")}
                if chassis_sns:
                    inventory["modules"] = [m for m in inventory["modules"] if not (m.get("sn") and m["sn"] in chassis_sns)]

            # 2. Supplemental: Execute "show interface transceiver" to guarantee SFP collection
            try:
                xcvr_output = self.conn.send_command("show interface transceiver", use_textfsm=True)

                # If TextFSM failed, fall back to manual raw parsing of transceiver data
                if not isinstance(xcvr_output, list) or not xcvr_output:
                    raw_xcvr = self.conn.send_command("show interface transceiver")
                    xcvr_output = parse_nxos_transceiver_raw(raw_xcvr)

                if isinstance(xcvr_output, list):
                    seen_sns = {x["sn"] for x in inventory["transceivers"] if x.get("sn")}
                    for xcvr in xcvr_output:
                        # Standard fields mapped from TextFSM or raw parser
                        presence = xcvr.get("presence") or "present"
                        sn_val = xcvr.get("serial_number") or xcvr.get("sn") or ""
                        pid_val = xcvr.get("part_number") or xcvr.get("pid") or xcvr.get("type") or "SFP"
                        intf_name = xcvr.get("interface", "")

                        sn_val = sn_val.strip()
                        pid_val = pid_val.strip()

                        if presence == "present" and sn_val and sn_val not in seen_sns:
                            inventory["transceivers"].append({
                                "name": f"{intf_name} Transceiver",
                                "pid": pid_val,
                                "sn": sn_val
                            })
                            seen_sns.add(sn_val)
            except Exception as e:
                logger.debug(f"[{self.device_name}] Supplemental transceiver collection failed: {e}")

            logger.debug(f"[{self.device_name}] Collected hardware inventory (chassis={len(inventory['chassis'])})")
            return inventory

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect inventory: {e}")
            return {}

    def collect_software_info(self):
        """Parse show version for NX-OS (handles TextFSM 'serial'/'platform' + raw fallback)"""
        try:
            output = self.conn.send_command("show version", use_textfsm=True)
            if isinstance(output, list) and len(output) > 0:
                version_info = output[0]
                # Note: ntc-templates cisco_nxos_show_version uses 'serial', 'os', and 'platform'
                raw_serial = version_info.get("serial") or version_info.get("serial_number")
                raw_model = version_info.get("platform") or version_info.get("hardware") or version_info.get("model")
                raw_os = version_info.get("os") or version_info.get("nxos_version")
                raw_image = version_info.get("boot_image") or version_info.get("system_image_file")
                return {
                    "os_version": extract_first_str(raw_os),
                    "image": extract_first_str(raw_image),
                    "serial": extract_first_str(raw_serial),
                    "model": extract_first_str(raw_model)
                }

            # Fallback to raw CLI regex parser if TextFSM failed
            raw_text = output if isinstance(output, str) and output else self.conn.send_command("show version")
            return parse_version_raw(raw_text, is_nxos=True)

        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect software info: {e}")
            return {}

# ==========================================================
# IP VALIDATION
# ==========================================================
def validate_ip(ip_addr):
    """Validate IP address format before assignment"""
    try:
        ip_only = ip_addr.split('/')[0]
        ipaddress.ip_address(ip_only)
        return True
    except ValueError:
        return False

# ==========================================================
# IP SUBNET PREFIX LOOKUP (N+1 Query Reduction)
# ==========================================================
def infer_subnet_mask(nb, ip_only, prefix_cache=None):
    """Query NetBox prefixes to find the parent subnet prefix and infer the mask (utilizes global pre-loaded cache)"""
    if prefix_cache is not None:
        try:
            ip_obj = ipaddress.ip_address(ip_only)
            # Check if this IP falls into any of our cached networks
            for net_obj, mask in prefix_cache.items():
                if ip_obj in net_obj:
                    logger.debug(f"[IP] Using cached mask /{mask} (matched parent network {net_obj}) for {ip_only}")
                    return mask
        except ValueError:
            pass

    try:
        # parent prefixes that contain this IP
        prefixes = list(nb.ipam.prefixes.filter(contains=ip_only))
        if prefixes:
            # Sort by mask length descending (find the most specific subnet)
            prefixes.sort(key=lambda p: p.prefix.prefixlen, reverse=True)
            parent_prefix_str = prefixes[0].prefix.prefix  # e.g., "10.0.0.0/24"
            parent_mask = prefixes[0].prefix.prefixlen
            logger.debug(f"[IP] Inferred mask /{parent_mask} from parent prefix {parent_prefix_str} for {ip_only}")

            if prefix_cache is not None:
                try:
                    net_obj = ipaddress.ip_network(parent_prefix_str, strict=False)
                    prefix_cache[net_obj] = parent_mask
                except ValueError:
                    pass
            return parent_mask
    except Exception as e:
        logger.warning(f"[IP] Subnet prefix lookup failed for {ip_only}: {e}")

    return 32  # default fallback to /32

# ==========================================================
# IP ASSIGNMENT
# ==========================================================
def assign_ip(nb, ip_addr, interface, prefix_cache=None):
    """Assign IP to interface with robust prefix handling and existing-check (utilizes global prefix cache)"""
    ip_only = ip_addr.split('/')[0]
    if not validate_ip(ip_only):
        logger.error(f"[IP] Invalid IP address format: {ip_addr}")
        return False

    try:
        # Search if the host IP already exists in NetBox
        existing_ips = list(nb.ipam.ip_addresses.filter(address=ip_only))

        if existing_ips:
            ip = existing_ips[0]
            logger.debug(f"[IP] Found existing IP {ip.address} in NetBox")
        else:
            # Infer correct subnet mask prefix instead of defaulting to /32
            mask = infer_subnet_mask(nb, ip_only, prefix_cache)
            cidr_addr = f"{ip_only}/{mask}"

            if DRY_RUN:
                logger.info(f"[DRY-RUN] Would create new NetBox IP: {cidr_addr}")
                return True
            ip = nb.ipam.ip_addresses.create(address=cidr_addr)
            logger.debug(f"[IP] Created new IP {cidr_addr}")

        # Verify if IP is already assigned to the target interface
        if ip.assigned_object_type == "dcim.interface" and ip.assigned_object_id == interface.id:
            logger.debug(f"[IP] IP {ip.address} is already assigned to {interface.name}")
            return True

        if DRY_RUN:
            logger.info(f"[DRY-RUN] Would assign {ip.address} to interface {interface.name}")
            return True

        ip.assigned_object_type = "dcim.interface"
        ip.assigned_object_id = interface.id
        ip.save()
        logger.info(f"[IP] Assigned {ip.address} to interface {interface.name}")
        return True

    except Exception as e:
        logger.error(f"[IP] Failed to assign {ip_addr} to {interface.name}: {e}")
        return False

# ==========================================================
# INTERFACE ENRICHMENT
# ==========================================================
def enrich_interface_in_netbox(nb, interface, interface_details):
    """Update NetBox interface with collected details if changes exist"""
    try:
        updates = {}

        # Check description
        desc = interface_details.get("description", "")
        if desc and interface.description != desc:
            updates["description"] = desc

        # Check MTU
        try:
            mtu_val = int(interface_details.get("mtu", 1500))
        except (ValueError, TypeError):
            mtu_val = 1500
        if mtu_val and interface.mtu != mtu_val:
            updates["mtu"] = mtu_val

        # Check speed
        if "speed" in interface_details:
            speed_val = parse_speed(interface_details["speed"])
            if speed_val and interface.speed != speed_val:
                updates["speed"] = speed_val

        # Check enabled status
        enabled_val = interface_details.get("enabled", True)
        if interface.enabled != enabled_val:
            updates["enabled"] = enabled_val

        # Check and update physical interface type if it changed (safeguards optical types)
        current_type = ""
        if interface.type:
            current_type = getattr(interface.type, "value", str(interface.type)) or ""
        correct_type = classify_interface_type_by_speed(interface.name, interface_details.get("speed"))

        if should_update_type(current_type, correct_type):
            updates["type"] = correct_type

        if DRY_RUN:
            if updates:
                logger.info(f"[DRY-RUN] Would update interface {interface.name} with: {updates}")
            return

        if updates:
            for key, val in updates.items():
                setattr(interface, key, val)
            interface.save()
            logger.info(f"[INTERFACE] Updated {interface.name} in NetBox: {updates}")

    except Exception as e:
        logger.warning(f"[INTERFACE] Failed to enrich {interface.name}: {e}")

# ==========================================================
# DEVICE WORKER (Thread-safe & Session-isolated)
# ==========================================================
def process_single_device(nb, device_dict, ssh_user, ssh_pass, prefix_cache=None, dt_cache=None):
    """Thread worker utilizing shared NetBox API client to optimize connection efficiency"""
    device_name = device_dict["name"]
    device_id = device_dict["id"]
    device_ip = device_dict["ip"]
    platform_slug = device_dict["platform_slug"]
    device_serial_existing = device_dict["serial"]
    device_type_id_existing = device_dict.get("device_type_id")
    device_type_model_existing = device_dict.get("device_type_model", "")
    manufacturer_id_existing = device_dict.get("manufacturer_id")

    result = {
        "device": device_name,
        "status": "failed",
        "error": None,
        "interfaces_synced": 0,
        "serial_updated": False,
        "device_type_updated": False,
        "warnings": []
    }

    logger.info(f"[{device_name}] Starting sync on {device_ip} ({platform_slug})")

    # Select collector class mapping
    family = get_platform_family(platform_slug)
    if family == "ios":
        collector_class = IOSXECollector
    elif family == "nxos":
        collector_class = NXOSCollector
    else:
        logger.warning(f"[{device_name}] No collector implemented for platform: {platform_slug}")
        result["status"] = "skipped"
        result["error"] = f"Unsupported platform slug: {platform_slug}"
        return result

    conn = None
    output = []
    interface_details = {}
    inventory = {}
    software_info = {}

    # Create thread-local copy of prefix_cache to prevent concurrent write race conditions
    prefix_cache = dict(prefix_cache) if prefix_cache else {}

    # Core retry block wrapping SSH connection instantiation (get_driver).
    # Only timeouts/transport errors are retried; an authentication failure ends this device immediately.
    for attempt in range(SSH_RETRIES):
        if AUTH_ABORT_EVENT.is_set():
            logger.warning(f"[{device_name}] Skipped: lockout guard tripped (too many authentication failures)")
            result["status"] = "skipped"
            result["error"] = "Lockout guard tripped"
            return result
        try:
            logger.info(f"[{device_name}] Connecting (Attempt {attempt+1}/{SSH_RETRIES})")
            conn = get_driver(platform_slug, device_ip, ssh_user, ssh_pass)

            logger.info(f"[{device_name}] Connected successfully! Fetching IP interface brief...")
            # Isolate show ip interface brief in its own try/except so a ReadTimeout or command error
            # does not abort the device before serial/device_type/inventory collection can run.
            try:
                brief_out = conn.send_command("show ip interface brief", use_textfsm=True, read_timeout=15)

                # Failsafe fallback: if TextFSM doesn't return structured list data, use fallback raw parsing
                if not isinstance(brief_out, list) or not brief_out:
                    logger.debug(f"[{device_name}] TextFSM parsing on show ip interface brief empty/failed. Attempting raw CLI parsing...")
                    raw_output = brief_out if isinstance(brief_out, str) and brief_out else conn.send_command("show ip interface brief", read_timeout=15)
                    brief_out = parse_raw_cli(raw_output)
            except Exception as e:
                logger.warning(f"[{device_name}] show ip interface brief failed: {e}")
                brief_out = []

            output = brief_out if isinstance(brief_out, list) else []
            break

        except NetMikoAuthenticationException as e:
            # Do NOT retry: every retry is another failed login counted against the account
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            failures = record_auth_failure(device_name)
            logger.error(f"[{device_name}] Authentication failed (not retried; {failures}/{AUTH_FAILURE_LIMIT} run-wide): {e}")
            result["error"] = "SSH Authentication error"
            return result

        except NetMikoTimeoutException as e:
            logger.warning(f"[{device_name}] SSH connection attempt {attempt+1} timed out: {e}")
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                conn = None

            if attempt < SSH_RETRIES - 1:
                backoff_time = RETRY_BACKOFF_BASE * (2 ** attempt)
                logger.info(f"[{device_name}] Retrying connection in {backoff_time}s...")
                time.sleep(backoff_time)
            else:
                logger.error(f"[{device_name}] SSH connection failed after {SSH_RETRIES} attempts.")
                result["error"] = "SSH Timeout/Authentication error"
                return result
        except Exception as e:
            logger.error(f"[{device_name}] Driver initialization encountered unexpected error: {e}")
            result["error"] = f"Driver error: {e}"
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            return result

    # Pull details under the active session (decoupled from whether show ip interface brief returned rows)
    try:
        collector = collector_class(device_name, conn)

        interface_details = collector.collect_interface_details()
        inventory = collector.collect_inventory()
        software_info = collector.collect_software_info()

        if software_info:
            logger.info(
                f"[{device_name}] CLI Software Info -> OS: {software_info.get('os_version', 'N/A')}, "
                f"Model: {software_info.get('model') or 'N/A'}, Serial: {software_info.get('serial') or 'N/A'}"
            )
        if inventory:
            chassis_summary = [
                f"{c.get('name')} (PID={c.get('pid')}, SN={c.get('sn')})"
                for c in inventory.get("chassis", [])
            ]
            xcvr_summary = [
                f"{x.get('name')} (PID={x.get('pid')}, SN={x.get('sn')})"
                for x in inventory.get("transceivers", [])
            ]
            logger.info(
                f"[{device_name}] CLI Inventory Parsed -> "
                f"Chassis ({len(chassis_summary)}): {chassis_summary}, "
                f"Modules: {len(inventory.get('modules', []))}, "
                f"Transceivers ({len(xcvr_summary)}): {xcvr_summary}"
            )

        if not output and not interface_details and not inventory and not software_info:
            logger.error(f"[{device_name}] All CLI collection commands returned empty output")
            result["error"] = "All CLI parsers returned empty"
            return result

    except Exception as e:
        logger.error(f"[{device_name}] Error while communicating with device: {e}")
        result["error"] = f"Collection block crashed: {e}"
        return result
    finally:
        # Ensure connection is closed cleanly under all circumstances
        if conn:
            try:
                conn.disconnect()
                logger.debug(f"[{device_name}] SSH disconnected cleanly")
            except Exception:
                pass

    # ==========================================================
    # NETBOX SYNCHRONIZATION (Executes post-SSH disconnection)
    # ==========================================================

    # Query active device object using the shared NetBox API client
    try:
        device = nb.dcim.devices.get(device_id)
        if not device:
            logger.error(f"[{device_name}] Device not found in NetBox during sync block")
            result["error"] = "NetBox device lost"
            return result

    except Exception as e:
        logger.error(f"[{device_name}] Thread NetBox device lookup failed: {e}")
        result["error"] = f"NetBox device lookup failed: {e}"
        return result

    # 1a. Update Device Serial Number FIRST (isolated single-field PATCH so device_type never blocks serial sync)
    device_serial = ""
    if inventory and inventory.get("chassis"):
        for ch in inventory["chassis"]:
            if ch.get("sn"):
                device_serial = ch["sn"].strip()
                break
    if not device_serial and software_info and software_info.get("serial"):
        device_serial = software_info["serial"].strip()

    if not device_serial:
        logger.warning(f"[{device_name}] Could not extract a serial number from 'show inventory' or 'show version'")
    elif device_serial_existing == device_serial:
        logger.info(f"[{device_name}] Serial number in NetBox already matches CLI ('{device_serial}') - no change needed")
    else:
        if DRY_RUN:
            logger.info(f"[DRY-RUN] [{device_name}] Would update serial number: '{device_serial_existing}' -> '{device_serial}'")
            result["serial_updated"] = True
        else:
            original_serial = device.serial
            try:
                device.serial = device_serial
                device.save()
                logger.info(f"[{device_name}] Updated serial number in NetBox: '{device_serial_existing}' -> '{device_serial}'")
                result["serial_updated"] = True
            except Exception as e:
                device.serial = original_serial  # revert dirty attribute so it doesn't ride along on the next save()
                err_detail = getattr(e, "error", str(e))
                logger.error(f"[{device_name}] NetBox rejected serial update ('{device_serial_existing}' -> '{device_serial}'): {err_detail}")
                result["warnings"].append(f"Serial sync failed ('{device_serial}'): {err_detail}")

    # 1b. Determine Hardware Model / Device Type and Overwrite in a SECOND isolated single-field PATCH
    discovered_model = ""
    if inventory and inventory.get("chassis"):
        for ch in inventory["chassis"]:
            if ch.get("pid"):
                discovered_model = ch["pid"].strip()
                break
    if not discovered_model and software_info and software_info.get("model"):
        discovered_model = software_info["model"].strip()

    if not discovered_model:
        logger.warning(f"[{device_name}] Could not extract hardware model/PID from 'show inventory' or 'show version'")
    elif not OVERWRITE_DEVICE_TYPE:
        if normalize_slug(discovered_model) != normalize_slug(device_type_model_existing):
            logger.info(
                f"[{device_name}] Hardware model differs (CLI: '{discovered_model}' vs NetBox: '{device_type_model_existing}'), "
                f"but OVERWRITE_DEVICE_TYPE is disabled (skipping device_type update)"
            )
        else:
            logger.info(f"[{device_name}] Hardware model in NetBox already matches CLI ('{device_type_model_existing}')")
    else:
        resolved_dt, match_info = resolve_or_create_device_type(
            nb=nb,
            device_name=device_name,
            discovered_model=discovered_model,
            fallback_mfg_id=manufacturer_id_existing,
            dt_cache=dt_cache
        )
        if resolved_dt:
            if resolved_dt.id != device_type_id_existing:
                if DRY_RUN:
                    logger.info(
                        f"[DRY-RUN] [{device_name}] Would overwrite device_type: "
                        f"'{device_type_model_existing}' -> '{resolved_dt.model}' "
                        f"(discovered: '{discovered_model}', matched via: {match_info})"
                    )
                    result["device_type_updated"] = True
                else:
                    original_dt = device.device_type
                    try:
                        device.device_type = resolved_dt.id
                        device.save()
                        logger.info(
                            f"[{device_name}] Overwrote device_type in NetBox: "
                            f"'{device_type_model_existing}' -> '{resolved_dt.model}' "
                            f"(ID: {resolved_dt.id}, matched via: {match_info})"
                        )
                        result["device_type_updated"] = True
                    except Exception as e:
                        device.device_type = original_dt  # revert dirty attribute on failure
                        err_detail = getattr(e, "error", str(e))
                        logger.error(
                            f"[{device_name}] NetBox rejected device_type overwrite "
                            f"('{device_type_model_existing}' -> '{resolved_dt.model}'): {err_detail}"
                        )
                        result["warnings"].append(f"Device type overwrite failed ({resolved_dt.model}): {err_detail}")
            else:
                logger.info(
                    f"[{device_name}] Device type in NetBox already matches CLI "
                    f"('{resolved_dt.model}', matched via: {match_info}) - no change needed"
                )
        else:
            logger.warning(f"[{device_name}] {match_info} (current: '{device_type_model_existing}')")
            result["warnings"].append(f"{match_info} (current: '{device_type_model_existing}')")

    # 2. Synchronize Physical Inventory Items (Modules and Transceivers) to NetBox
    if inventory:
        try:
            existing_items = {item.name: item for item in nb.dcim.inventory_items.filter(device_id=device_id)}

            # Combine modules and transceivers to sync (skipping any module whose SN duplicates the chassis SN)
            items_to_sync = []
            for mod in inventory.get("modules", []):
                mod_sn = (mod.get("sn") or "").strip()
                if device_serial and mod_sn and mod_sn == device_serial:
                    continue
                items_to_sync.append({
                    "name": mod.get("name") or f"Module {mod.get('pid')}",
                    "part_id": mod.get("pid") or "",
                    "serial": mod_sn,
                    "label": "Module"
                })
            for xcvr in inventory.get("transceivers", []):
                # Ensure the interface prefix inside transceiver descriptions is fully normalized
                raw_xcvr_name = xcvr.get("name") or ""
                name_parts = raw_xcvr_name.split()
                if name_parts and name_parts[0]:
                    norm_intf_part = normalize_interface_name(name_parts[0])
                    xcvr_name = f"{norm_intf_part} {' '.join(name_parts[1:])}".strip()
                else:
                    xcvr_name = raw_xcvr_name or f"Transceiver {xcvr.get('pid')}"

                items_to_sync.append({
                    "name": xcvr_name,
                    "part_id": xcvr.get("pid") or "",
                    "serial": xcvr.get("sn") or "",
                    "label": "Transceiver"
                })

            for item_data in items_to_sync:
                item_name = item_data["name"]
                pid = item_data["part_id"]
                sn = item_data["serial"]
                label = item_data["label"]

                if item_name in existing_items:
                    existing_item = existing_items[item_name]
                    updates = {}
                    if existing_item.part_id != pid:
                        updates["part_id"] = pid
                    if existing_item.serial != sn:
                        updates["serial"] = sn
                    if existing_item.label != label:
                        updates["label"] = label

                    if updates:
                        if DRY_RUN:
                            logger.info(f"[DRY-RUN] Would update inventory item {item_name}: {updates}")
                        else:
                            for k, v in updates.items():
                                setattr(existing_item, k, v)
                            existing_item.save()
                            logger.info(f"[{device_name}] Updated inventory item {item_name} in NetBox: {updates}")
                else:
                    if DRY_RUN:
                        logger.info(f"[DRY-RUN] Would create inventory item {item_name} (Part: {pid}, Serial: {sn})")
                    else:
                        nb.dcim.inventory_items.create(
                            device=device_id,
                            name=item_name,
                            part_id=pid,
                            serial=sn,
                            label=label
                        )
                        logger.info(f"[{device_name}] Created inventory item {item_name} in NetBox")
        except Exception as e:
            logger.warning(f"[{device_name}] Failed to sync inventory items: {e}")
            result["warnings"].append(f"Inventory sync failed: {e}")

    # 3. Fetch existing interfaces from NetBox
    try:
        existing = {i.name: i for i in nb.dcim.interfaces.filter(device_id=device_id)}
    except Exception as e:
        logger.error(f"[{device_name}] Failed to query existing interfaces from NetBox: {e}")
        result["error"] = "NetBox query failed"
        return result

    # 4. Normalize and Separate main interfaces and subinterfaces
    # Ensure all interface keys mapped from CLI output are fully canonicalized
    brief_by_name = {}
    for intf in output:
        raw_name = intf.get("interface")
        if raw_name:
            norm_name = normalize_interface_name(raw_name)
            intf["interface"] = norm_name  # Canonicalize name reference
            brief_by_name[norm_name] = intf

    if interface_details:
        for name, details in interface_details.items():
            name_norm = normalize_interface_name(name)
            if name_norm not in brief_by_name:
                # Include interfaces without IP addresses if they are operationally up (up/up)
                is_up = details.get("state", "down").lower() == "up"
                if is_up:
                    brief_by_name[name_norm] = {
                        "interface": name_norm,
                        "ipaddr": None,
                        "status": "up"
                    }

    # Filter out phantom interfaces from the sync list (brief_by_name)
    if interface_details:
        physical_prefixes = PHYSICAL_INTERFACE_PREFIXES
        filtered_brief = {}
        for name, intf in brief_by_name.items():
            # If it is a physical Ethernet interface, it must exist in interface_details to be synchronized,
            # unless it is an OOB management interface or logical/virtual interface.
            if name.startswith(physical_prefixes):
                if name not in interface_details and not is_management_or_logical_interface(name):
                    logger.info(f"[{device_name}] Skipping sync for phantom interface: {name}")
                    continue
            filtered_brief[name] = intf
        brief_by_name = filtered_brief

    parent_interfaces = []
    subinterfaces = []

    for name, intf in brief_by_name.items():
        if "." in name:
            subinterfaces.append(intf)
        else:
            parent_interfaces.append(intf)

    # 5. Pass 1: Synchronize discovered main/parent interfaces
    synced_count = 0
    for intf in parent_interfaces:
        name = intf.get("interface")
        ip = intf.get("ipaddr")
        status_col = intf.get("status")

        try:
            # Determine administrative state from brief status column as default fallback
            brief_admin_enabled = get_admin_state_from_brief(status_col, platform_slug)

            # Check if interface already exists in NetBox using canonical name
            if name in existing:
                netbox_intf = existing[name]
                logger.debug(f"[{device_name}] Interface {name} already exists in NetBox, checking updates")
            else:
                # Classify interface type mapping based on name and operational speed
                speed_str = interface_details.get(name, {}).get("speed")
                if_type = classify_interface_type_by_speed(name, speed_str)

                if DRY_RUN:
                    logger.info(f"[DRY-RUN] Would create interface {name} ({if_type}) on {device_name}")
                    continue
                else:
                    netbox_intf = nb.dcim.interfaces.create(
                        device=device_id,
                        name=name,
                        type=if_type,
                        enabled=brief_admin_enabled
                    )
                    logger.info(f"[{device_name}] Created interface {name} ({if_type})")
                    existing[name] = netbox_intf

            # Enrich interface speed, duplex, description, MTU, status (for both existing and new interfaces)
            if name in interface_details:
                enrich_interface_in_netbox(nb, netbox_intf, interface_details[name])
            else:
                # Fallback: if details not found in show interfaces, still correct interface type based on name heuristics
                current_type = ""
                if netbox_intf.type:
                    current_type = getattr(netbox_intf.type, "value", str(netbox_intf.type)) or ""
                correct_type = classify_interface_type(name)

                if should_update_type(current_type, correct_type):
                    if DRY_RUN:
                        logger.info(f"[DRY-RUN] Would correct interface type of {name} from {current_type} to {correct_type}")
                    else:
                        netbox_intf.type = correct_type
                        netbox_intf.save()
                        logger.info(f"[INTERFACE] Corrected interface type of {name} from {current_type} to {correct_type}")

            # Assign IP address if configured on interface
            if ip and ip != "unassigned":
                if not assign_ip(nb, ip, netbox_intf, prefix_cache):
                    result["warnings"].append(f"IP assignment failed for {name}: {ip}")

            synced_count += 1

        except Exception as e:
            logger.error(f"[{device_name}] Failed to synchronize interface {name}: {e}")
            result["warnings"].append(f"Interface {name} sync failed: {e}")

    # 6. Pass 2: Synchronize subinterfaces with parent/child relationships
    for intf in subinterfaces:
        name = intf.get("interface")
        ip = intf.get("ipaddr")
        status_col = intf.get("status")

        try:
            parent_name = name.split(".")[0]
            parent_id_val = None

            # Ensure parent interface exists first
            if parent_name in existing:
                parent_id_val = existing[parent_name].id
            else:
                # Parent interface not found, let's create it as a fallback with default type
                if DRY_RUN:
                    logger.info(f"[DRY-RUN] Would create parent interface fallback {parent_name} for subinterface {name}")
                else:
                    parent_intf_obj = nb.dcim.interfaces.create(
                        device=device_id,
                        name=parent_name,
                        type=classify_interface_type(parent_name)
                    )
                    existing[parent_name] = parent_intf_obj
                    parent_id_val = parent_intf_obj.id
                    logger.info(f"[{device_name}] Created parent interface fallback: {parent_name}")

            # Determine administrative state from brief status column as default fallback
            brief_admin_enabled = get_admin_state_from_brief(status_col, platform_slug)

            if name in existing:
                netbox_intf = existing[name]
                logger.debug(f"[{device_name}] Subinterface {name} already exists in NetBox, checking updates")

                # Verify if parent is already set correctly on existing subinterface
                if not DRY_RUN and parent_id_val and (not netbox_intf.parent or netbox_intf.parent.id != parent_id_val):
                    netbox_intf.parent = parent_id_val
                    netbox_intf.save()
                    logger.info(f"[{device_name}] Updated parent reference for subinterface {name}")
            else:
                # Subinterfaces in NetBox are always virtual type
                if_type = "virtual"

                if DRY_RUN:
                    logger.info(f"[DRY-RUN] Would create subinterface {name} ({if_type}) with parent {parent_name}")
                    continue
                else:
                    netbox_intf = nb.dcim.interfaces.create(
                        device=device_id,
                        name=name,
                        type=if_type,
                        parent=parent_id_val,
                        enabled=brief_admin_enabled
                    )
                    logger.info(f"[{device_name}] Created subinterface {name} with parent {parent_name}")
                    existing[name] = netbox_intf

            # Enrich subinterface details
            if name in interface_details:
                enrich_interface_in_netbox(nb, netbox_intf, interface_details[name])

            # Assign IP address
            if ip and ip != "unassigned":
                if not assign_ip(nb, ip, netbox_intf, prefix_cache):
                    result["warnings"].append(f"IP assignment failed for subinterface {name}: {ip}")

            synced_count += 1

        except Exception as e:
            logger.error(f"[{device_name}] Failed to synchronize subinterface {name}: {e}")
            result["warnings"].append(f"Subinterface {name} sync failed: {e}")

    result["status"] = "success"
    result["interfaces_synced"] = synced_count
    return result

# ==========================================================
# MAIN
# ==========================================================
def main():
    global OVERWRITE_DEVICE_TYPE, DRY_RUN
    os.environ['NO_PROXY'] = '127.0.0.1,localhost'

    token = input("NetBox Token: ").strip()
    ssh_user = input("SSH Username: ").strip()
    ssh_pass = getpass.getpass("SSH Password: ")

    # Optional targeting filters
    site_filter = os.getenv("NETBOX_SITE", "").strip()
    role_filter = os.getenv("NETBOX_ROLE", "").strip()
    tag_filter = os.getenv("NETBOX_TAG", "").strip()
    device_filter = os.getenv("NETBOX_DEVICE", "").strip()
    device_type_filter = os.getenv("NETBOX_DEVICE_TYPE", "").strip()

    if not any([site_filter, role_filter, tag_filter, device_filter, device_type_filter]):
        print("\nOptional Targeting Filters (Leave blank and press Enter to skip):")
        device_filter = input("Device Name Filter: ").strip()
        if not device_filter:
            site_filter = input("Site Slug Filter: ").strip()
            role_filter = input("Role Slug Filter: ").strip()
            tag_filter = input("Tag Slug Filter: ").strip()
            device_type_filter = input("Device Type Slug Filter: ").strip()

    if "OVERWRITE_DEVICE_TYPE" not in os.environ:
        ow_ans = input("Overwrite NetBox Device Type with discovered hardware model? [y/N]: ").strip().lower()
        if ow_ans in ("y", "yes", "true", "1"):
            OVERWRITE_DEVICE_TYPE = True

    if "DRY_RUN" not in os.environ:
        dr_ans = input("Run in DRY-RUN mode (log changes without saving to NetBox)? [y/N]: ").strip().lower()
        if dr_ans in ("y", "yes", "true", "1"):
            DRY_RUN = True

    logger.info(f"Connecting to NetBox at {NETBOX_URL} (SSL verify: {VERIFY_SSL})")
    if DRY_RUN:
        logger.warning("DRY-RUN MODE ENABLED - No changes will be written back to NetBox")
    if OVERWRITE_DEVICE_TYPE:
        logger.info("OVERWRITE_DEVICE_TYPE ENABLED - Discovered hardware models will overwrite NetBox device_type")

    nb = pynetbox.api(NETBOX_URL, token=token)
    nb.http_session.verify = VERIFY_SSL

    # Tune connection pool limits to support MAX_WORKERS concurrent threads
    adapter = requests.adapters.HTTPAdapter(pool_connections=MAX_WORKERS + 5, pool_maxsize=MAX_WORKERS + 5)
    nb.http_session.mount("http://", adapter)
    nb.http_session.mount("https://", adapter)

    logger.info("Retrieving active devices from NetBox...")

    try:
        filter_params = {"status": "active"}
        if device_filter:
            filter_params["name"] = device_filter
        if site_filter:
            filter_params["site"] = site_filter
        if role_filter:
            filter_params["role"] = role_filter
        if tag_filter:
            filter_params["tag"] = tag_filter
        if device_type_filter:
            filter_params["device_type"] = device_type_filter

        logger.info(f"Querying NetBox with parameters: {filter_params}")
        devices = nb.dcim.devices.filter(**filter_params)

        # Normalize exclusion lists with the same function applied to device slugs
        excluded_platforms = {normalize_slug(s) for s in EXCLUDED_PLATFORMS if s}
        excluded_device_types = {normalize_slug(s) for s in EXCLUDED_DEVICE_TYPES if s}

        # Flatten NetBox lazy-loading objects into standard thread-safe dictionaries
        device_list = []
        for d in devices:
            # Filters: platform slug and device type slug exclusion
            if d.primary_ip and d.platform:
                p_slug = normalize_slug(d.platform.slug)
                dt_slug = normalize_slug(d.device_type.slug) if d.device_type else ""

                if p_slug in excluded_platforms:
                    logger.debug(f"[{d.name}] Skipped: platform '{d.platform.slug}' is in EXCLUDED_PLATFORMS")
                    continue
                if dt_slug in excluded_device_types:
                    logger.debug(f"[{d.name}] Skipped: device type '{d.device_type.slug}' is in EXCLUDED_DEVICE_TYPES")
                    continue
                # Never SSH to a device we have no collector for (prevents wasted logins / lockout exposure)
                if get_platform_family(d.platform.slug) is None:
                    logger.info(f"[{d.name}] Skipped: unsupported platform '{d.platform.slug}'")
                    continue

                mfg_id = None
                if d.device_type and getattr(d.device_type, "manufacturer", None):
                    mfg_id = d.device_type.manufacturer.id

                device_list.append({
                    "id": d.id,
                    "name": d.name,
                    "ip": str(d.primary_ip.address).split('/')[0],
                    "platform_slug": d.platform.slug,
                    "serial": d.serial or "",
                    "device_type_id": d.device_type.id if d.device_type else None,
                    "device_type_model": d.device_type.model if d.device_type else "",
                    "manufacturer_id": mfg_id
                })
    except Exception as e:
        logger.error(f"Failed to query devices from NetBox: {e}")
        return

    if not device_list:
        logger.warning("No active devices containing a primary IP and valid platform slug were retrieved.")
        return

    # Prove the SSH credentials on a device BEFORE spawning threads, to prevent multi-threaded account lockouts.
    # Sequential, one login attempt per device: any authentication failure aborts the run immediately;
    # unreachable devices are skipped; if no device could prove the credentials, the run is aborted.
    logger.info(
        f"[LOCKOUT-GUARD] Validating credentials on up to {CRED_CHECK_MAX_DEVICES} device(s) before threading "
        f"(run-wide auth failure limit: {AUTH_FAILURE_LIMIT})..."
    )
    creds_verified = False
    for cred_test_device in device_list[:CRED_CHECK_MAX_DEVICES]:
        test_name = cred_test_device["name"]
        try:
            test_conn = get_driver(cred_test_device["platform_slug"], cred_test_device["ip"], ssh_user, ssh_pass)
            try:
                test_conn.disconnect()
            except Exception:
                pass
            logger.info(f"[LOCKOUT-GUARD] Credentials verified on {test_name}. Spawning parallel threads.")
            creds_verified = True
            break
        except NetMikoAuthenticationException:
            logger.error(
                f"[LOCKOUT-GUARD] Authentication FAILED on {test_name}. Aborting run to prevent account lockout "
                f"(no other devices were attempted)."
            )
            return
        except Exception as e:
            logger.warning(f"[LOCKOUT-GUARD] Could not reach {test_name} to verify credentials ({e}); trying next device...")

    if not creds_verified:
        logger.error(
            f"[LOCKOUT-GUARD] Could not verify credentials on any of the first {min(CRED_CHECK_MAX_DEVICES, len(device_list))} "
            f"device(s). Aborting rather than launching {MAX_WORKERS} threads with unverified credentials. "
            f"(Raise CRED_CHECK_MAX_DEVICES or target reachable devices.)"
        )
        return

    # Pre-load prefixes globally to avoid sequential N+1 lookups in threads
    global_prefix_cache = {}
    try:
        logger.info("Pre-loading subnet prefixes from NetBox for optimal performance...")
        all_prefixes = list(nb.ipam.prefixes.all())
        for p in all_prefixes:
            try:
                net_obj = ipaddress.ip_network(p.prefix.prefix, strict=False)
                global_prefix_cache[net_obj] = p.prefix.prefixlen
            except ValueError:
                pass
        logger.info(f"Successfully cached {len(global_prefix_cache)} subnet prefixes from NetBox.")
    except Exception as e:
        logger.warning(f"Failed to pre-load subnet prefixes from NetBox (will fallback to sequential lookups): {e}")

    # Pre-load Device Types globally if OVERWRITE_DEVICE_TYPE is enabled
    global_dt_cache = None
    if OVERWRITE_DEVICE_TYPE:
        logger.info("Pre-loading Device Types from NetBox for hardware model reconciliation...")
        global_dt_cache = build_device_type_cache(nb)

    logger.info(f"Processing {len(device_list)} devices utilizing {MAX_WORKERS} concurrent threads")

    results_summary = []

    # Thread Pool Concurrency Execution
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                process_single_device,
                nb,
                d,
                ssh_user,
                ssh_pass,
                global_prefix_cache,
                global_dt_cache
            )
            for d in device_list
        ]

        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    results_summary.append(res)
            except Exception as e:
                logger.error(f"[THREAD ERROR] Thread pool worker threw unexpected exception: {e}")

    # ==========================================================
    # SUMMARY REPORT
    # ==========================================================
    print("\n" + "="*95)
    print(" " * 36 + "SYNCHRONIZATION SUMMARY")
    print("="*95)
    print(f"{'Device Name':<25} | {'Status':<10} | {'Synced Ports':<12} | {'Serial Sync':<12} | {'Type Sync':<12} | {'Error Details':<15}")
    print("-"*95)

    success_count = 0
    skipped_count = 0
    failed_count = 0

    for r in results_summary:
        dev = r.get("device", "Unknown")
        status = r.get("status", "FAILED").upper()
        ports = r.get("interfaces_synced", 0)
        serial = "UPDATED" if r.get("serial_updated") else "NO CHANGE"
        dt_sync = "UPDATED" if r.get("device_type_updated") else "NO CHANGE"
        err = r.get("error") if r.get("error") else "None"

        # Explicitly truncate columns to prevent column misalignment on overflow
        dev_disp = (dev[:22] + "...") if len(dev) > 25 else dev
        err_disp = (err[:12] + "...") if len(err) > 15 else err

        if r.get("status") == "success":
            success_count += 1
        elif r.get("status") == "skipped":
            skipped_count += 1
        else:
            failed_count += 1

        print(f"{dev_disp:<25} | {status:<10} | {ports:<12} | {serial:<12} | {dt_sync:<12} | {err_disp:<15}")

    print("="*95)
    print(f"TOTAL: {len(results_summary)}  |  SUCCESS: {success_count}  |  SKIPPED: {skipped_count}  |  FAILED: {failed_count}")
    print("="*95 + "\n")

    # Detailed non-fatal warnings/errors reporting
    has_warnings = any(r.get("warnings") for r in results_summary if r.get("warnings"))
    if has_warnings:
        print("="*95)
        print(" " * 32 + "DETAILED NON-FATAL WARNINGS/ERRORS")
        print("="*95)
        for r in results_summary:
            dev = r.get("device", "Unknown")
            warnings = r.get("warnings", [])
            if warnings:
                print(f"\n[{dev}] Non-Fatal Issues:")
                for w in warnings:
                    print(f"  - {w}")
        print("="*95 + "\n")

if __name__ == "__main__":
    main()
