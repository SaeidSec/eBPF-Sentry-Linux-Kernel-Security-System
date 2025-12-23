<div align="center">
 
![Linux](https://img.shields.io/badge/Linux-5.4%2B-yellow?style=for-the-badge&logo=linux)
![eBPF](https://img.shields.io/badge/eBPF-powered-brightgreen?style=for-the-badge&logo=ebpf)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

<br/>

**eBPF-Sentry**  
**Advanced Linux Kernel Security & Active Defense**

[Quick Start](#quick-start) • 
[Configuration](#configuration) • 
[Report Bug](#)
<br/>
</div>

---

### Overview

**eBPF-Sentry** is a next-generation security tool that leverages **eBPF (Extended Berkeley Packet Filter)** to monitor Linux kernel events in real-time with negligible overhead. Unlike traditional IDS/IPS that rely on user-space hooking (which can be bypassed), eBPF-Sentry attaches directly to kernel tracepoints and kprobes.

### Key Features

-   **Kernel-Level Visibility**: Monitors `execve`, `connect`, `open`, and `openat` syscalls directly from the kernel.
-   **Process Whitelisting**: Trusted processes (e.g., `curl`, `python3`) can be whitelisted to reduce noise.
-   **Active Defense (IPS)**: Optional mode to automatically terminate processes triggering HIGH severity rules.
-   **Stateful Detection**: Detects complex attack chains (e.g., "Sensitive file access followed by outbound connection").
-   **Hot-Reload**: Rules and whitelist configurations are reloaded instantly without restarting the agent.

---

### Project Structure

```text
├── src/
│   ├── sentry_core.py       # Main controller
│   ├── log_shipper.py       # Utility to upload logs
│   └── bpf/
│       └── sentry_probe.c   # eBPF Kernel Probe
├── config/
│   ├── security_rules.yaml  # Detection rules
│   └── whitelist.yaml       # Trusted process names
├── ids_alerts.json          # JSON formatted security alerts
└── ips_actions.log          # Record of blocked/killed processes
```
---

### Standard Installation

**1. Install Prerequisites**
```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev python3-pip \
    linux-headers-$(uname -r) \
    bpfcc-tools libbpfcc-dev
```

**2. Install Python Dependencies**
```bash
pip3 install bcc pyyaml watchdog requests ipaddress
```

### Quick Start

1.  **Clone the repository**
    ```bash
    git clone https://github.com/YourUsername/eBPF-Sentry.git
    cd eBPF-Sentry
    ```

2.  **Run Sentry (Requires Root)**
    ```bash
    sudo python3 src/sentry_core.py
    ```

    You will see the interactive menu:
    ```text
    ==========================================
         eBPF-Sentry | Linux Kernel Security
    ==========================================
    1. Monitor Mode (IDS)
    2. Active Defense Mode (IDS + IPS)
    3. Exit
    ```

---

### Configuration

#### Detection Rules (`config/security_rules.yaml`)
Define what behaviors to flag. Supports Regex matching on filenames, process names, and IPs.

```yaml
- name: "Sensitive File Access"
  description: "Access to /etc/shadow detected"
  severity: "high"
  event: "open"
  match:
    filename_regex: "^/etc/shadow$"
```

#### Whitelist (`config/whitelist.yaml`)
Define processes that should typically be ignored to reduce log volume.

```yaml
processes:
  - "curl"
  - "apt-get"
```

---

### License

Unlicensed / Private Class Project.

### Author
- **SaeidSec** (AbuSaeid) - [mdsaeid598@gmail.com](mailto:mdsaeid598@gmail.com)


---
---
