# ios-nxos_netbox_importer
Netbox population tool for Cisco IOS, IOS-XE, and NX-OS devices

# Cisco-to-NetBox Custom Switch Importer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![NetBox Compatibility](https://img.shields.io/badge/NetBox-3.0%2B-green.svg)](https://netbox.dev/)
[![Library](https://img.shields.io/badge/library-netmiko-orange.svg)](https://github.com/ktbyers/netmiko)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance, fail-safe, and multi-threaded Python synchronization pipeline that automatically discovers active Cisco IOS/IOS-XE and NX-OS switches from NetBox, queries live hardware telemetry over SSH, and reconciles serial numbers, interfaces, MTUs, descriptions, port speeds, and IP addresses back into your NetBox source-of-truth.

---

## 📖 Table of Contents
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Prerequisites](#-prerequisites)
  - [NetBox Configuration](#1-netbox-configuration)
  - [Python Environment](#2-python-environment)
  - [TextFSM Parse Engine](#3-textfsm-parse-engine)
- [Installation & Quick Start](#-installation--quick-start)
- [Configuration Reference](#-configuration-reference)
- [Fail-Safe & High-Performance Design](#-fail-safe--high-performance-design)
- [License](#-license)

---

## 🚀 Features

* **Multi-Threaded Concurrency:** Leverages parallel worker threads to process large-scale network topologies in seconds.
* **Auto-Discovery:** Queries NetBox dynamically to retrieve only the devices flagged as "Active" with valid IPs and target operating systems.
* **Hardware Serial Reconciler:** Extracts chassis/motherboard serial numbers directly from live hardware inventories (`show inventory` / `show version`) and populates missing or mismatched fields in NetBox.
* **Smart Interface Provisioning:** Automatically provisions missing physical interfaces, Loopbacks, SVIs, and Link Aggregation Groups (LAGs / Port-Channels).
* **Speed & Parameter Tuning:** Translates live interface operational metrics (MTU, administrative state, descriptions, speed) and updates existing interfaces. It automatically handles Nexus 9000 generic naming (e.g., `Ethernet1/1`) by dynamically synchronizing operational speeds (10G, 25G, 40G, 100G) with NetBox.
* **Dynamic IP Address Assignment:** Discovers configured IP addresses on routed interfaces and SVIs, validating format integrity before creating and assigning them in NetBox IPAM.
* **Dry-Run Auditing:** Fail-safe dry-run execution checks planned database changes without writing modifications to your production NetBox database.

---

## 🛠️ How It Works

The synchronization pipeline executes through the following structural workflow:

```text
  +------------------+          +--------------------+          +----------------+          +----------------------+
  |   NetBox API     |          |  Main Orchestrator |          | Switch (SSH)   |          | Thread-Local Client  |
  +------------------+          +--------------------+          +----------------+          +----------------------+
           |                              |                             |                               |
    Query active devices                  |                             |                               |
           |----------------------------->|                             |                               |
           |<-----------------------------|                             |                               |
           |                        (Device list)                       |                               |
           |                              |                             |                               |
           |                    1. Defensive TACACS Check               |                               |
           |                       (Single-Device Sync)                 |                               |
           |                              |---------------------------->|                               |
           |                              |<----------------------------|                               |
           |                              |      (Validation OK)        |                               |
           |                              |                             |                               |
           |                    2. Thread Pool Spawning                 |                               |
           |                              |                             |                               |
           |                              |============================\|                               |
           |                              |  Parallel Thread Workers    |                               |
           |                              |============================/|                               |
           |                              |              |              |                               |
           |                              |              | 3. SSH Connect & Fetch                       |
           |                              |              |-------------------->|                        |
           |                              |              |<--------------------|                        |
           |                              |              | (Show output + timeouts)                     |
           |                              |              |              |                               |
           |                              |              | 4. Disconnect SSH                            |
           |                              |              |-------------------->|                        |
           |                              |              |              |                               |
           |                              |              | 5. Isolated NetBox Syncer                    |
           |                              |              |--------------------------------------------->|
           |                              |              |                                              |
           |                              |              |  - Lookup Parent Subnets (Inferred prefix)   |
           |                              |              |  - Sync interfaces (Speed, MTU, status)      |
           |                              |              |  - Set management/port IPs                   |
           |                              |              |                                              |
           |                              |              |<---------------------------------------------|
           |                              |              |             (Sync Success)                   |
           |                              |<-------------|                                              |
           |                              | (Return status)                                             |
           |                              |                             |                               |
           |                     6. Print Summary Table                 |                               |
           |                        (ASCII Report)                      |                               |
           |                              |                             |                               |
```

---

## 📋 Prerequisites

Before running the import engine, ensure your NetBox instance and local environments meet the following criteria:

### 1. NetBox Configuration

* **Active Devices:** Only devices with the status set to **Active** are selected for synchronization.
* **Primary IP Configuration:** Each target device must have a **Primary IPv4 Address** configured in NetBox. This IP is used as the SSH destination host.
* **Normalized Platform Slugs:** The script dynamically loads SSH drivers and parsing profiles based on device platform slugs. Ensure your NetBox platform slugs match the following:
  * **Cisco IOS / IOS-XE:** Slug must contain `ios` or `iosxe` (e.g., `cisco-ios-xe`, `iosxe`).
  * **Cisco NX-OS:** Slug must contain `nxos` (e.g., `cisco-nxos`, `nxos`).
* **Subnet Prefixes (IPAM):** Define your network subnets under **IPAM > Prefixes**. The script queries these prefixes to automatically infer correct subnet masks for discovered interface IPs instead of defaulting them to `/32`.

### 2. Python Environment

Ensure Python 3.8+ is installed, then install dependencies:
```bash
pip install pynetbox netmiko requests urllib3
```

### 3. TextFSM Parse Engine

Netmiko uses Google's TextFSM and NTC Templates to convert raw switch command outputs into structured data.
* **Option A (Recommended):** Install `ntc-templates` via pip:
  ```bash
  pip install ntc-templates
  ```
* **Option B (Manual Environment Variable):** Clone the [NTC Templates GitHub Repository](https://github.com/networktocode/ntc-templates) locally and point to it using the `NET_TEXTFSM` environment variable before running the script:
  * **Windows (PowerShell):**
    ```powershell
    $env:NET_TEXTFSM="C:\path\to\ntc-templates\ntc-templates\templates"
    ```
  * **Linux / macOS:**
    ```bash
    export NET_TEXTFSM="/path/to/ntc-templates/ntc-templates/templates"
    ```

---

## 📦 Installation & Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/netbox-switch-importer.git
cd netbox-switch-importer
```

### 2. Run in Dry-Run Mode (Audit planned changes)
Always perform a dry-run check before executing database writes on production inventories:

* **Windows (PowerShell):**
  ```powershell
  $env:DRY_RUN="true"
  python netbox_custom_importer.py
  ```
* **Linux / macOS:**
  ```bash
  DRY_RUN="true" python netbox_custom_importer.py
  ```

### 3. Run in Live Sync Mode (Commit changes)
* **Windows (PowerShell):**
  ```powershell
  $env:DRY_RUN="false"
  python netbox_custom_importer.py
  ```
* **Linux / macOS:**
  ```bash
  DRY_RUN="false" python netbox_custom_importer.py
  ```

---

## ⚙️ Configuration Reference

Adjust parameters at the top of the `netbox_custom_importer.py` script as needed:

| Parameter | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `NETBOX_URL` | String | `http://127.0.0.1:8001` | The base URL of your target NetBox instance. |
| `MAX_WORKERS` | Integer | Calculated | The maximum concurrent thread pool size (tuned up to 15 concurrent threads). |
| `SSH_TIMEOUT` | Integer | `30` | Sockets handshake timeout limit in seconds. |
| `SSH_READ_TIMEOUT` | Integer | `30` | Max duration in seconds to wait for command outputs to return. |
| `SSH_RETRIES` | Integer | `3` | Connection attempt limits before flagging a switch as failed. |
| `VERIFY_SSL` | Boolean | Sourced from `NETBOX_VERIFY_SSL` | Bypasses SSL certificate warnings when using private CA certificates. |
| `EXCLUDED_PLATFORMS` | List | `["aci", "apic"]` | Normalized platform slugs to skip. |

---

## 🛡️ Fail-Safe & High-Performance Design

* **Zero TACACS Lockout Risk:** Before launching background worker threads, the script connects synchronously to a single device. If an authentication failure is encountered, the script aborts immediately, preventing multi-threaded lockout cascades.
* **Isolated Thread Sessions:** Rather than utilizing a shared global API instance, each thread worker instantiates an isolated `pynetbox.api` instance with adjusted, isolated connection pool adapters. This completely eliminates HTTP socket exhaustion.
* **Subnet Inference Cache:** Workers maintain a local memory cache of retrieved subnets, avoiding sequential NetBox API parent prefix lookups and significantly reducing execution times.
* **Strict Type-Guards:** Checks the output type of TextFSM parsing models, gracefully skipping misaligned community templates without raising unhandled Python exceptions.
* **Connection Lifecycle Protection:** Ensures all switch SSH connections are closed gracefully under all return conditions (using robust `try...finally` nesting).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
