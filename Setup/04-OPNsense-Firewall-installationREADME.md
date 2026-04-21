# OPNsense Firewall Setup

## Overview
OPNsense is an open-source firewall and routing platform based on FreeBSD. 
In this homelab it serves as the network gateway and security boundary between 
the home network and the isolated lab environment, providing network-level 
visibility into all traffic between attack and target VMs.

## Purpose
- Segment the lab network from the home network
- Route and inspect all traffic between Kali and Ubuntu VMs
- Generate firewall logs shipped to Splunk for network visibility
- Provide a realistic enterprise-grade network architecture

## Network Architecture

### Home Network (192.168.1.x)
| Device | IP Address | Role |
|---|---|---|
| Home Router | 192.168.1.1 | Internet gateway |
| Proxmox Host | 192.168.1.50 | Hypervisor |
| OPNsense WAN | 192.168.1.214 | Firewall WAN interface |
| Ubuntu ens19 | 192.168.1.234 | Jump host home interface |
| MacBook | 192.168.1.163 | Management workstation |

### Lab Network (10.10.10.x)
| Device | IP Address | Role |
|---|---|---|
| OPNsense LAN | 10.10.10.1 | Firewall and default gateway |
| Ubuntu ens18 | 10.10.10.198 | Splunk SIEM and jump host |
| Kali Linux | 10.10.10.132 | Attack VM |

### Traffic Flow
All traffic between Kali and Ubuntu passes through OPNsense.
OPNsense inspects, filters, and logs every connection.
Logs ship to Splunk via syslog on UDP port 5514.

```
```

## Environment

| Component | Value |
|---|---|
| OPNsense Version | 26.1.2 |
| VM Host | Proxmox VE 9.1.1 |
| WAN Interface | vtnet0 → vmbr0 (home network) |
| LAN Interface | vtnet1 → vmbr1 (lab network) |
| WAN IP | 192.168.1.214 (DHCP from home router) |
| LAN IP | 10.10.10.1/24 (static) |
| DHCP Pool | 10.10.10.100 - 10.10.10.200 |

---

## VM Configuration

| Setting | Value |
|---|---|
| Memory | 4GB |
| CPU | 1 socket, 1 core |
| BIOS | OVMF (UEFI) |
| Machine | q35 |
| Hard Disk | SATA 20GB |
| Network 1 (net0) | VirtIO → vmbr0 |
| Network 2 (net1) | VirtIO → vmbr1 |
| EFI Disk | local-lvm 4MB |

---

## Installation Process

### ISO Download
Downloaded OPNsense 26.1.2 DVD image (AMD64) from:
https://opnsense.org/download
Extracted the .bz2 file and uploaded ISO to Proxmox local storage.

<img width="1267" height="957" alt="Screenshot 2026-04-15 at 5 45 27 PM" src="https://github.com/user-attachments/assets/7f3cd156-6678-4cc4-8341-08a3601051af" />

### Key Installation Challenges
The installation required several troubleshooting steps worth documenting 
for future reference:

**Challenge 1 — Disk Format:**
UFS installer repeatedly failed with "Partition destroy failed" error 
due to residual partition data on virtual disk. Resolved by:
1. Switching to ZFS installation method
2. Using Proxmox shell to manually wipe disk:
```bash
dd if=/dev/zero of=/dev/pve/vm-102-disk-0 bs=1M count=100
```

**Challenge 2 — Secure Boot:**
OVMF UEFI blocked OPNsense ISO with "Access Denied" error.
Resolved by navigating to EFI Firmware Setup → Device Manager → 
Secure Boot Configuration and disabling Secure Boot.

**Challenge 3 — EFI Disk:**
Pre-enrolled Secure Boot keys caused boot failures.
Resolved by removing EFI disk and recreating without 
pre-enrolled keys.

### Successful Installation
After resolving all challenges OPNsense installed successfully 
using ZFS with Stripe configuration on ada0.

<img width="762" height="483" alt="Screenshot 2026-04-15 at 7 52 00 PM" src="https://github.com/user-attachments/assets/07bc2453-3686-4eda-a559-4c277f0aca65" />

---

## Initial Configuration

### Interface Assignment
After installation logged in via Proxmox console with root credentials 
and assigned interfaces:
WAN → vtnet0 (faces home router 192.168.1.x)
LAN → vtnet1 (faces isolated lab network 10.10.10.x)

### LAN Interface Configuration
Selected option 2 from console menu to set LAN IP:
IPv4 address:    10.10.10.1
Subnet:          /24
Gateway:         none (OPNsense IS the gateway)
IPv6:            disabled
DHCP Server:     enabled
DHCP Range:      10.10.10.100 - 10.10.10.200
HTTPS:           enabled (kept default)

<img width="765" height="482" alt="Screenshot 2026-04-19 at 3 23 49 PM" src="https://github.com/user-attachments/assets/53825c37-780e-44f6-8b72-ac1b07aac91a" />

---

## Web GUI Access

### Challenge — Network Access
MacBook sits on 192.168.1.x network. OPNsense LAN is on 10.10.10.x. 
Direct access to web GUI at 10.10.10.1 not possible from MacBook 
without routing.

### Solution — Ubuntu Jump Host
Configured Ubuntu Server as a dual-homed jump host:
ens18: 10.10.10.198  → lab network (talks to OPNsense)
ens19: 192.168.1.234 → home network (reachable from MacBook)

Ubuntu's /etc/netplan/50-cloud-init.yaml:
```yaml
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: true
    ens19:
      dhcp4: true
```

### Tailscale Installation
Installed Tailscale on Ubuntu and MacBook for permanent 
remote access without SSH tunnel timeouts:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

<img width="1214" height="959" alt="Screenshot 2026-04-19 at 3 30 40 PM" src="https://github.com/user-attachments/assets/fb2c6281-fed3-4f80-b36b-bf940257a546" />


**Access method after Tailscale:**
Splunk:    http://100.98.15.123:8000
SSH:       ssh labadmin@100.98.15.123
OPNsense:  ssh -L 8443:10.10.10.1:443 labadmin@100.98.15.123
→ https://localhost:8443

---

## Firewall Configuration

### WAN Rules
Created a rule to allow MacBook management access to web GUI:

| Field | Value |
|---|---|
| Action | Pass |
| Interface | WAN |
| Protocol | TCP |
| Source | 192.168.1.163 (MacBook only) |
| Destination | WAN address |
| Port | 443 (HTTPS) |
| Logging | Enabled |
| Description | Allow MacBook WebGUI Management Access |

<img width="1214" height="959" alt="Screenshot 2026-04-19 at 3 57 46 PM" src="https://github.com/user-attachments/assets/48227e8a-5a64-448b-8ef5-2ca3373e7bf2" />
<img width="1214" height="959" alt="Screenshot 2026-04-19 at 3 57 31 PM" src="https://github.com/user-attachments/assets/a06e66e1-19e5-4235-b353-c3602837b2f9" />


### LAN Rules
Default allow LAN rules kept — permits all lab VM traffic 
outbound through OPNsense to internet.
Default allow LAN to any → Lab VMs reach internet ✅
NAT translation → 10.10.10.x translated to 192.168.1.214 ✅

### Verification
Confirmed internet connectivity through OPNsense from Ubuntu:
```bash
ping -c 4 google.com
# 4 packets transmitted, 4 received ✅
```

---

## Lab Network Configuration

### Kali Linux
Moved from vmbr0 to vmbr1. Received IP from OPNsense DHCP:
eth0: 10.10.10.132/24

<img width="419" height="333" alt="Screenshot 2026-04-19 at 4 57 38 PM" src="https://github.com/user-attachments/assets/cfc74986-7013-4403-b6df-17d797747f73" />

### Network Segmentation Result
All traffic between Kali and Ubuntu now passes through 
OPNsense firewall — fully logged and inspectable.
Kali (10.10.10.132)
↓ ALL traffic inspected by OPNsense
Ubuntu (10.10.10.198)

---

## OPNsense Dashboard

<img width="1214" height="959" alt="Screenshot 2026-04-19 at 3 30 40 PM" src="https://github.com/user-attachments/assets/93d02206-2db2-4278-a235-76c96e2319eb" />


Key services confirmed running:
- Dnsmasq DNS/DHCP ✅
- Packet Filter ✅  
- Syslog-ng Daemon ✅
- Unbound DNS ✅

---

## Key Concepts Learned

| Concept | Application |
|---|---|
| Network Segmentation | Isolated lab from home network |
| Default Deny | WAN blocks all unless explicitly allowed |
| Implicit Deny | Unmatched traffic dropped automatically |
| NAT | Lab VMs reach internet via OPNsense WAN IP |
| DHCP | OPNsense auto-assigns 10.10.10.x addresses |
| Default Gateway | Lab VMs use 10.10.10.1 as their gateway |
| Bastion Host | Ubuntu jump host bridges home and lab networks |
| SSH Tunneling | Secure access to isolated management interfaces |
| PKI | Self-signed certificate for HTTPS web GUI |
| Secure Boot | UEFI security feature blocking unsigned bootloaders |
| Change Management | Disabling firewall requires documented rollback plan |
| ZTNA | Even internal traffic could be restricted per rule |

---

## Troubleshooting Reference

| Issue | Cause | Resolution |
|---|---|---|
| Partition destroy failed | Residual partition data on disk | dd wipe from Proxmox shell |
| Access Denied on boot | Secure Boot blocking unsigned ISO | Disable in EFI firmware |
| UFS install fails repeatedly | Virtual disk compatibility | Switch to ZFS installer |
| Web GUI unreachable | MacBook on different network | Ubuntu jump host + SSH tunnel |
| SSH tunnel timeouts | Idle connection dropped | Tailscale permanent VPN |
| UDP 514 unavailable | Privileged port requires root | Use port 5514 instead |
| OPNsense sending to wrong port | Typo in remote logging config | tcpdump diagnosis → fix port |
