# NetBox Custom Network Importer

A multi-threaded Python script that SSHs into Cisco IOS-XE and NX-OS network devices and synchronizes their interface data, IP assignments, hardware inventory, and software information into [NetBox](https://netbox.dev/).

---

## Use Cases

- **Initial NetBox population** — Bootstrap a new NetBox instance with real interface data pulled directly from devices, eliminating manual data entry for large switch fleets.
- **Ongoing sync / drift detection** — Re-run periodically to keep NetBox in sync as interfaces are added, speeds change, or transceivers are swapped.
- **Interface type correction** — Automatically classifies and corrects interface types (1G copper, 10G SFP+, 25G, 40G, 100G) based on operational speed reported by the device, with safeguards against overwriting manually-curated fiber/optical types.
- **IP address management** — Discovers routed IPs from `show ip interface brief`, infers the correct subnet mask from existing NetBox prefixes, and creates/assigns IP address objects accordingly.
- **Hardware inventory tracking** — Collects module and transceiver (SFP/QSFP) serial numbers and part IDs via `show inventory` and `show interface transceiver`, syncing them as NetBox inventory items.
- **Subinterface mapping** — Detects dot-notation subinterfaces (e.g. `GigabitEthernet0/0.100`) and creates them in NetBox with correct parent-child relationships.
- **Targeted runs** — Filter by site, device role, tag, or exact device name to sync a specific subset of your fleet rather than everything at once.
- **Safe dry-run mode** — Preview all changes that would be made without writing anything to NetBox.

---

## Supported Platforms

| Platform | Netmiko Driver | NetBox Platform Slug (examples) |
|---|---|---|
| Cisco IOS-XE (Catalyst, IE series) | `cisco_ios` | `ios-xe`, `cisco-ios`, `ios` |
| Cisco NX-OS (Nexus series) | `cisco_nxos` | `nxos`, `cisco-nxos`, `nx-os` |

Devices with platform slugs containing `aci` or `apic` are automatically skipped.

---

## Prerequisites

### NetBox Requirements
- NetBox instance accessible over HTTP or HTTPS
- A NetBox API token with read/write access to:
  - `dcim.devices`
  - `dcim.interfaces`
  - `dcim.inventory_items`
  - `ipam.ip_addresses`
  - `ipam.prefixes`
- Devices in NetBox must have:
  - Status set to **Active**
  - A **Primary IP** assigned
  - A **Platform** slug set (matching IOS-XE or NX-OS)

### Device Requirements
- SSH access enabled on all target devices
- A user account with privilege level sufficient to run:
  - `show ip interface brief`
  - `show interfaces` / `show interfaces status`
  - `show inventory`
  - `show interface transceiver` *(NX-OS only)*
  - `show version`
- If using TACACS+, ensure the account has enough failed-attempt headroom — the script validates credentials against a single device before launching parallel threads to prevent fleet-wide lockouts.

---

## Dependencies

Install all Python dependencies via pip:

```bash
pip install netmiko pynetbox requests urllib3
```

| Package | Purpose |
|---|---|
| `netmiko` | SSH connections and command execution |
| `pynetbox` | NetBox REST API client |
| `requests` | HTTP session and connection pool management |
| `urllib3` | SSL warning suppression for HTTP NetBox installs |

The following are Python standard library modules and require no installation: `os`, `logging`, `getpass`, `ipaddress`, `time`, `re`, `abc`, `concurrent.futures`.

> **TextFSM / NTC Templates** — Netmiko uses TextFSM templates to parse structured output from `show` commands. These are bundled with `netmiko` via the `ntc-templates` package which is installed automatically as a dependency. If you encounter parsing failures, ensure your `ntc-templates` version is current:
> ```bash
> pip install --upgrade ntc-templates
> ```

---

## Installation

### Ubuntu / Debian

```bash
# 1. Install Python 3 if not already present
sudo apt update && sudo apt install -y python3 python3-pip

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install netmiko pynetbox requests urllib3

# 4. Download the script
wget https://raw.githubusercontent.com/your-repo/netbox-importer/main/netbox_custom_importer.py
# or clone the repo:
# git clone https://github.com/your-repo/netbox-importer.git
```

### Windows

```powershell
# 1. Install Python 3 from https://python.org (check "Add to PATH" during install)

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install netmiko pynetbox requests urllib3
```

---

## Configuration

Open the script and edit the `CONFIG` block near the top:

```python
NETBOX_URL = "http://127.0.0.1:8001"   # Change to your NetBox URL
MAX_WORKERS = min(15, (os.cpu_count() or 2) * 5)  # Max parallel SSH threads
SSH_RETRIES = 3        # Retry attempts per device on connection failure
SSH_TIMEOUT = 30       # SSH connection timeout in seconds
SSH_READ_TIMEOUT = 30  # SSH command read timeout in seconds

EXCLUDED_PLATFORMS = ["aci", "apic"]  # Platform slugs to skip entirely
EXCLUDED_DEVICE_TYPES = []            # Device type slugs to skip entirely
```

### Environment Variables

The following can be set as environment variables instead of editing the script:

| Variable | Default | Description |
|---|---|---|
| `NETBOX_VERIFY_SSL` | `false` | Set to `true` to enable SSL certificate verification |
| `DRY_RUN` | `false` | Set to `true` to preview changes without writing to NetBox |
| `NETBOX_DEVICE` | *(none)* | Target a single device by exact NetBox name |
| `NETBOX_SITE` | *(none)* | Filter devices by NetBox site slug |
| `NETBOX_ROLE` | *(none)* | Filter devices by NetBox device role slug |
| `NETBOX_TAG` | *(none)* | Filter devices by NetBox tag slug |

**Ubuntu / Linux:**
```bash
export NETBOX_VERIFY_SSL=true
export DRY_RUN=true
export NETBOX_SITE=dc-east
python3 netbox_custom_importer.py
```

**Windows (PowerShell):**
```powershell
$env:NETBOX_VERIFY_SSL = "true"
$env:DRY_RUN = "true"
$env:NETBOX_SITE = "dc-east"
python netbox_custom_importer.py
```

---

## Running the Script

```bash
python3 netbox_custom_importer.py      # Linux/macOS
python netbox_custom_importer.py       # Windows
```

On launch, the script will prompt for:

```
NetBox Token:
SSH Username:
SSH Password:

Optional Targeting Filters (Leave blank and press Enter to skip):
Device Name Filter:
Site Slug Filter:
Role Slug Filter:
Tag Slug Filter:
```

> **Note:** The Device Name filter uses exact matching against the NetBox device name field — it is not a substring search. Enter the full device name as it appears in NetBox.

If targeting filters are set via environment variables, the interactive prompts are skipped automatically.

---

## Non-Local NetBox Server

By default the script targets `http://127.0.0.1:8001`. To point at a remote NetBox instance:

1. Update `NETBOX_URL` in the CONFIG block:
   ```python
   NETBOX_URL = "https://netbox.yourdomain.com"
   ```

2. If your NetBox instance uses a valid, trusted SSL certificate, enable verification:
   ```bash
   export NETBOX_VERIFY_SSL=true   # Linux
   $env:NETBOX_VERIFY_SSL = "true" # Windows
   ```

3. If your instance uses a self-signed certificate and you want to suppress warnings while leaving verification disabled, no change is needed — SSL warnings are already suppressed by default.

4. If your environment routes traffic through a proxy, the script explicitly bypasses proxy for `127.0.0.1` and `localhost`. For a remote NetBox server through a proxy, remove or adjust the `NO_PROXY` line in `main()`:
   ```python
   os.environ['NO_PROXY'] = '127.0.0.1,localhost'  # Remove or extend as needed
   ```

---

## Dry Run Mode

Always recommended before the first production run:

```bash
# Linux
DRY_RUN=true python3 netbox_custom_importer.py

# Windows
$env:DRY_RUN = "true"
python netbox_custom_importer.py
```

In dry-run mode the script connects to devices, collects all data, and logs every change it *would* make — but writes nothing to NetBox.

---

## Output

The script logs timestamped progress to the console and prints a summary table on completion:

```
================================================================================
                               SYNCHRONIZATION SUMMARY
================================================================================
Device Name               | Status     | Synced Ports | Serial Sync  | Error Details
--------------------------------------------------------------------------------
switch-core-01            | SUCCESS    | 52           | UPDATED      | None
switch-access-02          | SUCCESS    | 28           | NO CHANGE    | None
nexus-dist-01             | FAILED     | 0            | NO CHANGE    | SSH Timeout/Au...
================================================================================
TOTAL: 3  |  SUCCESS: 2  |  SKIPPED: 0  |  FAILED: 1
================================================================================

================================================================================
                           DETAILED NON-FATAL WARNINGS/ERRORS
================================================================================

[switch-access-02] Non-Fatal Issues:
  - IP assignment failed for GigabitEthernet0/1: 10.0.1.5
```

Non-fatal issues (individual interface failures, IP assignment errors, inventory sync failures) are surfaced in the warnings section without failing the overall device sync.

---

## TACACS+ / AAA Lockout Protection

Before spawning parallel SSH threads, the script validates credentials against a single device. If authentication fails, execution stops immediately and no further connections are attempted. This prevents a misconfigured credential set from triggering fleet-wide TACACS+ lockouts.

If the single-device validation passes, all devices are processed in parallel up to `MAX_WORKERS` concurrent connections.

---

## Troubleshooting

**TextFSM parsing fails / interfaces not discovered**
The script includes a raw CLI fallback parser for `show ip interface brief` when TextFSM templates are missing or fail. If structured collection commands (`show interfaces`, `show inventory`) fail, the script logs a warning and continues with reduced data. Ensure `ntc-templates` is up to date.

**`Unsupported platform` warning for a device**
The device's NetBox platform slug doesn't match `ios`, `ios-xe`, `iosxe`, `nxos`, or similar variants. Check the platform slug in NetBox under the device record and ensure it contains a recognizable keyword.

**Devices skipped with `missing IP or platform`**
Each device must have both a Primary IP and a Platform assigned in NetBox before the script will attempt to connect to it.

**SSL errors connecting to NetBox**
If using HTTPS with a self-signed certificate, either set `NETBOX_VERIFY_SSL=false` (default) or add the certificate to your system trust store and set `NETBOX_VERIFY_SSL=true`.

**Proxy interference**
If SSH connections are being routed through a corporate proxy, ensure your SSH traffic is excluded from proxy routing. The script does not configure SSH proxy settings — this is handled at the OS or Netmiko level.
