# Ubuntu Server & Splunk Installation

## Overview
Deployed Ubuntu Server 24.04.5 LTS as a dedicated virtual machine within the Proxmox homelab environment, serving dual purpose as both the Splunk SIEM host and the target machine for attack simulations. Splunk Enterprise 10.2.2 was installed and configured as the primary Security Information and Event Management platform, forming the detection and investigation backbone of the homelab SOC environment.

---

## VM Configuration

| Component | Details |
|---|---|
| VM ID | 101 |
| Hostname | splunk-server |
| Operating System | Ubuntu Server 24.04.5 LTS |
| CPU | 2 Cores |
| RAM | 8192 MB (8GB) |
| Storage | 60GB VirtIO Disk |
| Network | VirtIO Network Adapter |
| IP Address | 192.168.1.220 |
| Hypervisor | Proxmox VE 8.x |

<img width="1508" height="825" alt="Screenshot 2026-04-12 at 4 38 46 PM" src="https://github.com/user-attachments/assets/511494be-fdc4-4f3b-b190-c3826d54696d" />

---

## Why Ubuntu Server?

Ubuntu Server 24.04.5 LTS was selected as the Splunk host for several reasons directly relevant to building a professional SOC environment:

- **Industry standard platform** — Ubuntu Server is one of the most widely deployed Linux distributions in enterprise environments, making familiarity with it directly transferable to real SOC work
- **Headless operation** — runs without a graphical desktop, maximizing available resources for Splunk's indexing and search operations
- **Remote management via SSH** — managed entirely through SSH from the MacBook terminal, mirroring how real server infrastructure is administered in enterprise environments
- **Dual purpose design** — simultaneously hosts Splunk and acts as the SSH brute force target, generating authentic attack logs that flow directly into the SIEM

---

## Dual Role In The Homelab

Ubuntu Server operates as two things simultaneously:
```
Role 1 — Splunk Host
Ubuntu Server runs Splunk Enterprise
Ingests logs from across the lab environment
Provides detection, alerting, and investigation capability

Role 2 — Attack Target
Exposes SSH service to the lab network
Receives brute force attacks from Kali Linux
Generates authentic authentication failure logs
Those logs flow into Splunk for detection
```

---

## Installation Process

### Step 1 — VM Creation
Created a new VM in Proxmox with the configuration detailed above. Allocated 8GB RAM specifically to accommodate Splunk's memory requirements during active log indexing and search operations.

### Step 2 — OS Installation
Booted from the Ubuntu Server 24.04.5 LTS ISO and completed the installation:
- Selected guided full disk partitioning across the 60GB VirtIO disk
- Configured server hostname as **splunk-server**
- Created dedicated admin account **labadmin**
- Enabled **OpenSSH Server** during installation for immediate remote management capability

### Step 3 — Network Verification
Confirmed network connectivity and noted the DHCP assigned IP address for SSH access and attack targeting.

<img width="1330" height="290" alt="Screenshot 2026-04-12 at 5 01 23 PM" src="https://github.com/user-attachments/assets/c61e655c-0951-45d9-864a-46b8884fb3b1" />

### Step 4 — Remote Management Via SSH
Established SSH connection from MacBook terminal eliminating the need for the Proxmox console going forward. All subsequent configuration performed via SSH, mirroring enterprise Linux server administration practices.
```
ssh labadmin@192.168.1.220
```

### Step 5 — System Updates
Updated all system packages prior to Splunk installation:
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 6 — Splunk Download
Downloaded Splunk Enterprise 10.2.2 directly to the server using wget, retrieving the official .deb installer from Splunk's download servers:

<img width="2511" height="290" alt="Screenshot 2026-04-12 at 5 29 14 PM" src="https://github.com/user-attachments/assets/d7f179bc-6c25-42d2-9eff-9e42da08ff4e" />

### Step 7 — Splunk Installation
Installed Splunk using the Debian package manager:
```bash
sudo dpkg -i splunk-10.2.2-80b90d638de6-linux-amd64.deb
```

Splunk installed to **/opt/splunk** with a dedicated **splunk** service account automatically created during installation.

### Step 8 — Service Account Configuration
Assigned ownership of the Splunk installation to the dedicated splunk service account, following security best practices for running services with least privilege:
```bash
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

### Step 9 — Boot Start and Firewall Configuration
Configured Splunk to start automatically on system boot and opened required firewall ports:
```bash
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
sudo ufw allow 8000/tcp
sudo ufw allow 9997/tcp
```

| Port | Purpose |
|---|---|
| **8000** | Splunk web interface access |
| **9997** | Universal Forwarder log ingestion |

<img width="1493" height="189" alt="Screenshot 2026-04-12 at 5 47 18 PM" src="https://github.com/user-attachments/assets/f27b26af-b502-499a-9fff-a43a5e552fc2" />

---

## Splunk Configuration

| Setting | Value |
|---|---|
| Version | Splunk Enterprise 10.2.2 |
| Admin Username | admin |
| Web Interface | http://192.168.1.220:8000 |
| Indexing Limit | 500MB/day (free tier) |
| Service Account | splunk |
| Boot Start | Enabled |

---

## Challenges and Solutions

### Challenge 1 — Splunk Running As Root Warning
**Issue:** Initial Splunk start command using sudo triggered a deprecation warning — running Splunk Enterprise as root is deprecated in version 10.x and Splunk refused to start.

**Resolution:** Created a dedicated splunk service account, transferred ownership of the installation directory, and started Splunk explicitly as the splunk user..

---

### Challenge 2 — Boot Start Permission Denied
**Issue:** Enabling Splunk boot start as the splunk user returned a permission denied error when attempting to write to **/etc/init.d/splunk** — a system directory requiring root access.

**Resolution:** Ran the boot-start command with full sudo privileges while specifying the splunk user with the **-user splunk** flag, allowing the system-level write operation while maintaining the correct service account configuration.

---

### Challenge 3 — Proxmox Console Clipboard Limitation
**Issue:** Standard copy and paste shortcuts do not function inside the Proxmox VNC console, making it impractical to paste long commands like the Splunk wget download URL.

**Resolution:** Established an SSH connection from the MacBook terminal directly to Ubuntu Server, enabling full clipboard functionality and a significantly more efficient management workflow. SSH is now the primary management interface for all Ubuntu Server administration going forward.

---

## Post-Installation Verification

Confirmed the following after installation:

- Splunk web interface accessible at **http://192.168.1.220:8000** from MacBook browser
- Splunk service running under dedicated **splunk** service account
- Boot start enabled — Splunk survives system reboots automatically
- Firewall ports 8000 and 9997 open and accepting connections
- SSH access confirmed from MacBook terminal

<img width="1493" height="790" alt="Screenshot 2026-04-12 at 5 43 44 PM" src="https://github.com/user-attachments/assets/7a6743d3-8875-4299-b17c-f5a293f0b7cd" />

---

## Result

A fully operational Ubuntu Server VM running Splunk Enterprise 10.2.2, accessible via browser from any device on the local network. This machine now serves as the SIEM backbone of the homelab — ready to ingest logs, build detection rules, and alert on attack activity generated by the Kali Linux VM. The same machine exposes an SSH service that will serve as the brute force target in the first detection project.
