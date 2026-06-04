# ios-nxos_netbox_importer
Netbox population tool for Cisco IOS, IOS-XE, and NX-OS devices

NetBox Custom Switch Importer: Execution & Deployment Guide
This documentation provides an end-to-end guide for the production-grade custom NetBox switch importer script (netbox_custom_importer.py). It covers the script's features, architectural mechanics, step-by-step execution instructions, and structural prerequisites.

1. What This Script Does
The netbox_custom_importer.py engine is an automated, multi-threaded synchronization pipeline. It bridges the gap between active live Cisco infrastructure and your NetBox source-of-truth.

Key Capabilities
Active Device Auto-Discovery: Automatically queries your NetBox instance to discover active switches matching target platform profiles while skipping excluded platforms (e.g., ACI, APIC).
Hardware Serial Synchronization: Queries the physical switch's active chassis or hardware inventory, extracts the true motherboard/chassis serial number, and updates NetBox if it is missing or mismatched.
Interface Auto-Provisioning: Discovers physical ports, virtual interfaces (SVIs, Loopbacks), and Link Aggregations (Port-Channels). If an interface is missing in NetBox, it creates it with the correct interface type (e.g., lag, virtual, or speed-specific physical port).
Deep Parameter Enrichment: Keeps existing interfaces in sync by evaluating and updating critical parameters on every run:
Port Description (verbatim sync)
MTU Size (syncs customized frame limits)
Administrative Status (enable/disable state alignment)
Dynamic Speed Tuning: Since modern switches (particularly Nexus 9000) use generic interface names (e.g., Ethernet1/1) regardless of link speeds, the script baselines physical interfaces as 1000base-t (1G) and dynamically updates their operational speed in NetBox (e.g., 10Gbps, 25Gbps, 40Gbps, or 100Gbps) based on live telemetry parsed from the switch.
Intelligent IP Address Assignment: Discovers configured IP addresses on routed interfaces and SVIs, verifies format validity, and creates/assigns them in NetBox IPAM.
Dry-Run vs. Live Commit Modes: Supports a fail-safe execution mode (DRY_RUN = True) that logs all planned changes (serial updates, port creations, IP assignments) without executing any database writes in NetBox.
2. How It Works
The engine is engineered for high performance, high concurrency, and defense-in-depth security. Below is an architectural overview of how it works under the hood.

No diagram type detected matching given configuration for text: No diagram type detected matching given configuration for text: No diagram type detected matching given configuration for text:




Architectural Mechanics
A. Defensive TACACS Validation
Multi-threaded network scripts can accidentally lock out administrative TACACS+ or RADIUS accounts if an incorrect password is provided (as 15 concurrent threads will fail authentication simultaneously and immediately trip security lockout thresholds).

The Solution: The script attempts a synchronous connection to the first device in the list. If it encounters a NetMikoAuthenticationException, the script aborts immediately and never spawns the background threads.
B. Thread-Local Session Isolation
Using a single shared API client across concurrent threads results in packet starvation and write timeouts in python's HTTP library (urllib3).

The Solution: Each thread worker instantiates its own pynetbox.api instance and mounts an independent HTTPAdapter configured with a dedicated connection pool (pool_connections=4, pool_maxsize=4).
C. Local Subnet Mask Inference Cache
Querying NetBox for a parent subnet on every single interface IP is extremely slow.

The Solution: The thread worker maintains a thread-local IP subnet cache. When an IP is discovered without a subnet mask (e.g., bare IPs from show ip interface brief), the script checks if it falls within a previously queried prefix in its local cache. If it does, the mask is inferred without making an API call. A NetBox API lookup is executed only on a cache miss.
D. Connection Lifecycle Protection
To prevent network sockets from hanging open on failed runs:

All command execution and parsing occur within a strict connection context.
A robust try...finally block guarantees that conn.disconnect() is called on all code paths (even in the event of an unexpected script crash or TextFSM failure) before committing changes to NetBox.
3. How to Execute and Deploy
Configuration Variables
At the top of netbox_custom_importer.py, you will find the configuration block:

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
Execution Environment Setup
1. Install Required Python Packages
Install the required packages in your Python virtual environment:

pip install pynetbox netmiko requests urllib3
2. Ensure TextFSM Templates are Accessible
Netmiko relies on Google's textfsm library and the community-supported ntc-templates to parse raw terminal text into structured Python dictionaries.

Option A: Automated packaging In most modern environments, the ntc-templates package can be installed directly via pip:
pip install ntc-templates
Option B: Manual Environment Variable If you are running in an environment without internet access or with manual templates, clone the NTC Templates Repository locally and point your terminal to it via an environment variable:
On Windows (PowerShell):
$env:NET_TEXTFSM="C:\path\to\cloned\ntc-templates\ntc-templates\templates"
On Linux / macOS:
export NET_TEXTFSM="/path/to/cloned/ntc-templates/ntc-templates/templates"
Step-by-Step Running Guide
Step 1: Run a Safe Dry-Run Check
It is highly recommended to run a dry-run sync first. This lets you audit all changes the script plans to execute.

On Windows (PowerShell):
$env:DRY_RUN="true"
python netbox_custom_importer.py
On Linux / macOS:
DRY_RUN="true" python netbox_custom_importer.py
The console will securely prompt you for your NetBox Token, SSH Username, and SSH Password.

Step 2: Review CLI Audit Output
Analyze the logs and the final printed summary table. Ensure the parsed ports and serial numbers match your physical topology expectations.

Step 3: Run the Live Production Sync
Once you are satisfied with the dry-run results, remove the environment variable (or set it to false) to execute the live write operations back to NetBox:

On Windows (PowerShell):
$env:DRY_RUN="false"
python netbox_custom_importer.py
On Linux / macOS:
DRY_RUN="false" python netbox_custom_importer.py
4. Prerequisites & Environment Adjustments
For the script to execute cleanly and map structures correctly, the following network and application prerequisites must be configured.

A. NetBox Prerequisites & Assignments
1. Normalized Platform Slugs
The script dynamically determines which Netmiko SSH driver to load (e.g., cisco_ios vs cisco_nxos) and which OS collector pattern to execute based on the Platform Slug assigned to the device in NetBox. Ensure that your NetBox Platforms have slugs matching the following criteria:

For IOS / IOS-XE Switches: The Platform slug must contain either ios or iosxe (e.g., cisco-ios, cisco-ios-xe, ios-xe).
For NX-OS Switches: The Platform slug must contain nxos (e.g., cisco-nx-os, nxos, nexus-nx-os).
[!IMPORTANT] If a device's platform slug is empty or does not match these patterns, the script will gracefully skip the device and report it as "Skipped" in the final execution summary table.

2. Active Status & Primary IP Address
To protect production equipment, the script filters device queries:

Only devices with their status set to Active in NetBox are queried.
Every target device must have a Primary IPv4 Address configured in NetBox. The script uses this primary IP as the destination host for the SSH session.
3. Pre-defined Subnets (IPAM)
To ensure the subnet mask inference engine works properly, define your network subnets (e.g. point-to-points, SVI subnets, management ranges) in NetBox under IPAM > Prefixes.

If a prefix is configured (e.g., 10.150.12.0/24), and the script discovers SVI interface Vlan12 configured with IP 10.150.12.11 without a subnet mask, it will automatically query NetBox, find that the IP falls inside the /24 prefix, and assign it in NetBox as 10.150.12.11/24 (rather than defaulting to /32).
B. Execution Environment Adjustments
1. Adjusting Target NetBox Location (Remote vs. Local)
If your NetBox instance is not running locally on http://127.0.0.1:8001, edit the NETBOX_URL configuration line at the top of the script:

NETBOX_URL = "https://netbox.yourdomain.com"
Or, if it runs on a custom port:

NETBOX_URL = "http://10.200.10.45:8080"
2. Handling Custom/Private SSL Certificates
If you are running NetBox over HTTPS with a private/self-signed enterprise certificate, the python script will reject connections by default to prevent SSL validation failures.

To tell requests to trust your private PKI, set the NETBOX_VERIFY_SSL environment variable to true and ensure your operating system trusts the CA, or manually adjust the code verification path.
Alternatively, to run without validation checks in non-production sandboxes:
On Windows (PowerShell):
$env:NETBOX_VERIFY_SSL="false"
On Linux / macOS:
export NETBOX_VERIFY_SSL="false"
(This disables warnings and bypasses strict SSL validation securely).
3. Adjusting SSH Timeout Limits
In high-latency enterprise WAN environments, switches can take longer to establish SSH handshakes or complete intensive TextFSM parses. If you experience unexpected SSH connection timeouts, adjust these values at the top of the script:

SSH_TIMEOUT = 60       # Increase handshake timeout to 60 seconds
SSH_READ_TIMEOUT = 60  # Increase command output read timeout to 60 seconds
