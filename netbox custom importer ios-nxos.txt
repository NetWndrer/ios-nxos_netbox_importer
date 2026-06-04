import os
import logging
import getpass
import requests
import pynetbox
import ipaddress
import time
import urllib3
import re
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

# Exclude device types/platforms from SSH collection
EXCLUDED_PLATFORMS = ["aci", "apic"]  # Normalized platform slugs to skip
EXCLUDED_DEVICE_TYPES = []  # Normalized device type slugs to skip

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ==========================================================
# SLUG NORMALIZATION
# ==========================================================
def normalize_slug(slug):
    """Normalize slugs for robust, case-insensitive string matching"""
    if not slug:
        return ""
    return str(slug).lower().replace("-", "").replace("_", "").strip()

# ==========================================================
# DRIVER FACTORY 
# ==========================================================
def get_driver(platform_slug, ip, username, password):
    """Create Netmiko connection handler based on platform"""
    norm = normalize_slug(platform_slug)
    
    if "iosxe" in norm or "ios" in norm:
        device_type = 'cisco_ios'
    elif "nxos" in norm:
        device_type = 'cisco_nxos'
    else:
        raise ValueError(f"Unsupported platform: {platform_slug}")
    
    return ConnectHandler(
        device_type=device_type,
        host=ip,
        username=username,
        password=password,
        conn_timeout=SSH_TIMEOUT,
        read_timeout=SSH_READ_TIMEOUT,
        global_delay_factor=1.5
    )

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
            elif speed_mbps >= 1000:
                return "1000base-t"
            elif speed_mbps >= 100:
                return "100base-tx"

    # Fallback to name-based classification (with Nexus heuristics)
    return classify_interface_type(name)


# ==========================================================
# INTERFACE TYPE RECONCILIATION GUARD
# ==========================================================
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
        
    GENERIC_TYPES = {
        "1000base-t", "10gbase-x-sfpp", "25gbase-x-sfp28",
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
    valid_speeds = [10, 100, 1000, 10000, 25000, 40000, 100000]
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
            if "/" in interface or "." in interface or interface.lower().startswith(("gi", "fa", "te", "tw", "fo", "hu", "et", "po", "vl", "lo", "mg", "me", "et")):
                status_field = " ".join(tokens[2:]) if len(tokens) > 2 else "up"
                parsed.append({
                    "interface": interface,
                    "ipaddr": ipaddr,
                    "status": status_field
                })
    return parsed


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
    norm = normalize_slug(platform_slug)
    
    if "nxos" in norm:
        if "admin-down" in status_lower:
            return False
        if "admin-up" in status_lower:
            return True
    else:
        if "administratively down" in status_lower or "admin" in status_lower:
            return False
            
    return True

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
        """Collect OS version and software details"""
        pass


class IOSXECollector(DeviceCollector):
    """Collector for IOS-XE devices (Catalyst, IE series)"""
    
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
                    try:
                        mtu_val = int(intf.get("mtu", 1500))
                    except (ValueError, TypeError):
                        mtu_val = 1500
                    
                    # admin state in cisco_ios_show_interfaces textfsm is link_status (e.g. "administratively down")
                    link_status = intf.get("link_status", "").lower()
                    enabled_val = "administratively down" not in link_status and "admin" not in link_status
                        
                    interfaces[name] = {
                        "description": intf.get("description", ""),
                        "mtu": mtu_val,
                        "state": intf.get("protocol_status", "down").lower(),
                        "enabled": enabled_val,
                    }
            
            # get speed/duplex
            status = self.conn.send_command("show interfaces status", use_textfsm=True)
            if isinstance(status, list):
                for intf in status:
                    name = intf.get("port", "")
                    if name in interfaces:
                        status_val = intf.get("status", "").lower()
                        is_disabled = "disabled" in status_val and "err-disabled" not in status_val
                        interfaces[name].update({
                            "speed": intf.get("speed", ""),
                            "duplex": intf.get("duplex", ""),
                            "type": intf.get("type", ""),
                            "enabled": not is_disabled if status_val else interfaces[name]["enabled"]
                        })
            
            logger.debug(f"[{self.device_name}] Collected {len(interfaces)} interface details")
            return interfaces
            
        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect interface details: {e}")
            return {}
    
    def collect_inventory(self):
        """Parse show inventory for IOS-XE"""
        try:
            output = self.conn.send_command("show inventory", use_textfsm=True)
            if not isinstance(output, list):
                return {}
            
            inventory = {
                "chassis": [],
                "modules": [],
                "transceivers": []
            }
            
            for item in output:
                name = item.get("name", "").lower()
                pid = item.get("pid", "")
                sn = item.get("sn", "")
                
                if "chassis" in name:
                    inventory["chassis"].append({"pid": pid, "sn": sn})
                elif "module" in name or "card" in name:
                    inventory["modules"].append({"name": item.get("name"), "pid": pid, "sn": sn})
                elif "xcvr" in name or "transceiver" in name:
                    inventory["transceivers"].append({"name": item.get("name"), "pid": pid, "sn": sn})
            
            logger.debug(f"[{self.device_name}] Collected hardware inventory")
            return inventory
            
        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect inventory: {e}")
            return {}
    
    def collect_software_info(self):
        """Parse show version for IOS-XE"""
        try:
            output = self.conn.send_command("show version", use_textfsm=True)
            if not isinstance(output, list) or len(output) == 0:
                return {}
            
            version_info = output[0]
            return {
                "os_version": version_info.get("version", ""),
                "image": version_info.get("image_name", ""),
                "bootloader": version_info.get("bootloader", ""),
                "serial": version_info.get("serial_number", "")
            }
            
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
                    try:
                        mtu_val = int(intf.get("mtu", 1500))
                    except (ValueError, TypeError):
                        mtu_val = 1500
                        
                    interfaces[name] = {
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
            # 1. Start with standard show inventory
            output = self.conn.send_command("show inventory", use_textfsm=True)
            
            inventory = {
                "chassis": [],
                "modules": [],
                "transceivers": []
            }
            
            if isinstance(output, list):
                for item in output:
                    name = item.get("name", "").lower()
                    pid = item.get("pid", "")
                    sn = item.get("sn", "")
                    
                    if "chassis" in name:
                        inventory["chassis"].append({"pid": pid, "sn": sn})
                    elif "module" in name or "card" in name:
                        inventory["modules"].append({"name": item.get("name"), "pid": pid, "sn": sn})
                    elif "transceiver" in name or "sfp" in name or "qsfp" in name or "xcvr" in name:
                        inventory["transceivers"].append({"name": item.get("name"), "pid": pid, "sn": sn})
            
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
                
            logger.debug(f"[{self.device_name}] Collected hardware inventory")
            return inventory
            
        except Exception as e:
            logger.error(f"[{self.device_name}] Failed to collect inventory: {e}")
            return {}
    
    def collect_software_info(self):
        """Parse show version for NX-OS"""
        try:
            output = self.conn.send_command("show version", use_textfsm=True)
            if not isinstance(output, list) or len(output) == 0:
                return {}
            
            version_info = output[0]
            return {
                "os_version": version_info.get("nxos_version", ""),
                "image": version_info.get("system_image_file", ""),
                "serial": version_info.get("serial_number", "")
            }
            
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
# IP SUBNET PREFIX LOOKUP
# ==========================================================
def infer_subnet_mask(nb, ip_only, prefix_cache=None):
    """Query NetBox prefixes to find the parent subnet prefix and infer the mask (with thread subnet cache)"""
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
    """Assign IP to interface with robust prefix handling and existing-check (with thread subnet cache)"""
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
            
        # Check and update physical interface type if it changed (e.g. from 1000base-t fallback to correct speed-specific type)
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
def process_single_device(nb, device_dict, ssh_user, ssh_pass):
    """Thread worker utilizing shared NetBox API client to optimize connection efficiency"""
    device_name = device_dict["name"]
    device_id = device_dict["id"]
    device_ip = device_dict["ip"]
    platform_slug = device_dict["platform_slug"]
    device_serial_existing = device_dict["serial"]
    
    result = {
        "device": device_name,
        "status": "failed",
        "error": None,
        "interfaces_synced": 0,
        "serial_updated": False,
        "warnings": []
    }

    logger.info(f"[{device_name}] Starting sync on {device_ip} ({platform_slug})")

    # Select collector class mapping
    norm_platform = normalize_slug(platform_slug)
    if "iosxe" in norm_platform or "ios" in norm_platform:
        collector_class = IOSXECollector
    elif "nxos" in norm_platform:
        collector_class = NXOSCollector
    else:
        logger.warning(f"[{device_name}] No collector implemented for platform: {platform_slug}")
        result["status"] = "skipped"
        result["error"] = f"Unsupported platform slug: {platform_slug}"
        return result

    conn = None
    output = None
    interface_details = {}
    inventory = {}
    software_info = {}
    prefix_cache = {}  # Thread-local subnet cache to prevent sequential NetBox API lookups

    # Core retry block wrapping BOTH connection instantiation (get_driver) and command execution
    for attempt in range(SSH_RETRIES):
        try:
            logger.info(f"[{device_name}] Connecting (Attempt {attempt+1}/{SSH_RETRIES})")
            conn = get_driver(platform_slug, device_ip, ssh_user, ssh_pass)
            
            logger.info(f"[{device_name}] Connected successfully! Fetching IP interface brief...")
            # Enforce strict command-level timeout and attempt TextFSM
            output = conn.send_command("show ip interface brief", use_textfsm=True, read_timeout=15)
            
            # Failsafe fallback: if TextFSM doesn't return structured list data, use fallback raw parsing
            if not isinstance(output, list) or not output:
                logger.warning(f"[{device_name}] TextFSM parsing on show ip interface brief failed. Attempting fallback raw CLI parsing...")
                raw_output = conn.send_command("show ip interface brief", read_timeout=15)
                output = parse_raw_cli(raw_output)
            break
            
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            logger.warning(f"[{device_name}] SSH Connection/Authentication attempt {attempt+1} failed: {e}")
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

    # Connection succeeded, validate output format
    # Pull additional details under the active session
    try:
        # Validate output format (must be list of parsed interface dicts)
        if not isinstance(output, list) or not output:
            logger.error(f"[{device_name}] Unexpected interface output format or empty parsed list")
            result["error"] = "TextFSM/Raw parse failure"
            return result

        collector = collector_class(device_name, conn)
        
        # Collect switch metrics with explicit command-level timeouts to prevent thread hanging
        interface_details = collector.collect_interface_details()
        inventory = collector.collect_inventory()
        software_info = collector.collect_software_info()
        
        if software_info:
            logger.info(f"[{device_name}] OS Version: {software_info.get('os_version', 'N/A')}")

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
    
    # 1. Update device Serial Number if discovered
    device_serial = None
    if software_info and software_info.get("serial"):
        device_serial = software_info["serial"]
    elif inventory and inventory.get("chassis"):
        device_serial = inventory["chassis"][0].get("sn")
        
    if device_serial and device_serial_existing != device_serial:
        if DRY_RUN:
            logger.info(f"[DRY-RUN] Would update device serial number to {device_serial}")
            result["serial_updated"] = True
        else:
            try:
                device.serial = device_serial
                device.save()
                logger.info(f"[{device_name}] Updated serial number in NetBox: {device_serial}")
                result["serial_updated"] = True
            except Exception as e:
                logger.warning(f"[{device_name}] Failed to save device serial: {e}")
                result["warnings"].append(f"Serial sync failed: {e}")

    # 2. Synchronize Physical Inventory Items (Modules and Transceivers) to NetBox
    if inventory:
        try:
            existing_items = {item.name: item for item in nb.dcim.inventory_items.filter(device_id=device_id)}
            
            # Combine modules and transceivers to sync
            items_to_sync = []
            for mod in inventory.get("modules", []):
                items_to_sync.append({
                    "name": mod.get("name") or f"Module {mod.get('pid')}",
                    "pid": mod.get("pid") or "",
                    "sn": mod.get("sn") or "",
                    "label": "Module"
                })
            for xcvr in inventory.get("transceivers", []):
                items_to_sync.append({
                    "name": xcvr.get("name") or f"Transceiver {xcvr.get('pid')}",
                    "pid": xcvr.get("pid") or "",
                    "sn": xcvr.get("sn") or "",
                    "label": "Transceiver"
                })
                
            for item_data in items_to_sync:
                item_name = item_data["name"]
                pid = item_data["pid"]
                sn = item_data["sn"]
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

    # 4. Separate main interfaces and subinterfaces
    # Combine entries from show ip interface brief (output) and show interfaces (interface_details)
    brief_by_name = {intf.get("interface"): intf for intf in output if intf.get("interface")}
    
    if interface_details:
        for name, details in interface_details.items():
            if name not in brief_by_name:
                # Include interfaces without IP addresses if they are operationally up (up/up)
                is_up = details.get("state", "down").lower() == "up"
                if is_up:
                    brief_by_name[name] = {
                        "interface": name,
                        "ipaddr": None,
                        "status": "up"
                    }
                    
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
            
            # Check if interface already exists in NetBox
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
    os.environ['NO_PROXY'] = '127.0.0.1,localhost'
    
    token = input("NetBox Token: ").strip()
    ssh_user = input("SSH Username: ").strip()
    ssh_pass = getpass.getpass("SSH Password: ")
    
    # Optional targeting filters
    site_filter = os.getenv("NETBOX_SITE", "").strip()
    role_filter = os.getenv("NETBOX_ROLE", "").strip()
    tag_filter = os.getenv("NETBOX_TAG", "").strip()
    device_filter = os.getenv("NETBOX_DEVICE", "").strip()

    if not any([site_filter, role_filter, tag_filter, device_filter]):
        print("\nOptional Targeting Filters (Leave blank and press Enter to skip):")
        device_filter = input("Device Name Filter: ").strip()
        if not device_filter:
            site_filter = input("Site Slug Filter: ").strip()
            role_filter = input("Role Slug Filter: ").strip()
            tag_filter = input("Tag Slug Filter: ").strip()

    logger.info(f"Connecting to NetBox at {NETBOX_URL} (SSL verify: {VERIFY_SSL})")
    if DRY_RUN:
        logger.warning("DRY-RUN MODE ENABLED - No changes will be written back to NetBox")
    
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
            
        logger.info(f"Querying NetBox with parameters: {filter_params}")
        devices = nb.dcim.devices.filter(**filter_params)
        
        # Flatten NetBox lazy-loading objects into standard thread-safe dictionaries
        device_list = []
        for d in devices:
            # Filters: platform slug and device type slug exclusion
            if d.primary_ip and d.platform:
                p_slug = normalize_slug(d.platform.slug)
                dt_slug = normalize_slug(d.device_type.slug) if d.device_type else ""
                
                if p_slug in EXCLUDED_PLATFORMS:
                    continue
                if dt_slug in EXCLUDED_DEVICE_TYPES:
                    continue
                    
                device_list.append({
                    "id": d.id,
                    "name": d.name,
                    "ip": str(d.primary_ip.address).split('/')[0],
                    "platform_slug": d.platform.slug,
                    "serial": d.serial or ""
                })
    except Exception as e:
        logger.error(f"Failed to query devices from NetBox: {e}")
        return

    if not device_list:
        logger.warning("No active devices containing a primary IP and valid platform slug were retrieved.")
        return

    # Verify SSH credentials on a single device first to prevent multi-threaded TACACS account lockouts!
    logger.info("Performing defensive credentials validation on a single device to check for potential TACACS lockouts...")
    cred_test_device = device_list[0]
    
    try:
        test_conn = get_driver(cred_test_device["platform_slug"], cred_test_device["ip"], ssh_user, ssh_pass)
        test_conn.disconnect()
        logger.info("Credential check validation passed successfully! Spawning parallel threads.")
    except NetMikoAuthenticationException:
        logger.error("Authentication failed on single validation check. Aborting execution to prevent global TACACS account lockout.")
        return
    except Exception as e:
        logger.warning(f"Initial single-device validation encountered a non-authentication connection issue: {e}. Proceeding with threading.")

    logger.info(f"Processing {len(device_list)} devices utilizing {MAX_WORKERS} concurrent threads")

    results_summary = []

    # Thread Pool Concurrency Execution
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(process_single_device, nb, d, ssh_user, ssh_pass)
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
    print("\n" + "="*80)
    print(" " * 31 + "SYNCHRONIZATION SUMMARY")
    print("="*80)
    print(f"{'Device Name':<25} | {'Status':<10} | {'Synced Ports':<12} | {'Serial Sync':<12} | {'Error Details':<20}")
    print("-"*80)
    
    success_count = 0
    skipped_count = 0
    failed_count = 0
    
    for r in results_summary:
        dev = r.get("device", "Unknown")
        status = r.get("status", "FAILED").upper()
        ports = r.get("interfaces_synced", 0)
        serial = "UPDATED" if r.get("serial_updated") else "NO CHANGE"
        err = r.get("error") if r.get("error") else "None"
        
        # Explicitly truncate columns to prevent column misalignment on overflow
        dev_disp = (dev[:22] + "...") if len(dev) > 25 else dev
        err_disp = (err[:17] + "...") if len(err) > 20 else err
        
        if r.get("status") == "success":
            success_count += 1
        elif r.get("status") == "skipped":
            skipped_count += 1
        else:
            failed_count += 1
            
        print(f"{dev_disp:<25} | {status:<10} | {ports:<12} | {serial:<12} | {err_disp:<20}")
        
    print("="*80)
    print(f"TOTAL: {len(results_summary)}  |  SUCCESS: {success_count}  |  SKIPPED: {skipped_count}  |  FAILED: {failed_count}")
    print("="*80 + "\n")
    
    # Detailed non-fatal warnings/errors reporting
    has_warnings = any(r.get("warnings") for r in results_summary if r.get("warnings"))
    if has_warnings:
        print("="*80)
        print(" " * 27 + "DETAILED NON-FATAL WARNINGS/ERRORS")
        print("="*80)
        for r in results_summary:
            dev = r.get("device", "Unknown")
            warnings = r.get("warnings", [])
            if warnings:
                print(f"\n[{dev}] Non-Fatal Issues:")
                for w in warnings:
                    print(f"  - {w}")
        print("="*80 + "\n")

if __name__ == "__main__":
    main()
