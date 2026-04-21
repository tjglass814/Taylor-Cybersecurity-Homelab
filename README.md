# Taylor Glass — Cybersecurity Homelab

A hands-on cybersecurity homelab documenting real attack simulations, 
detections, and incident investigations to develop practical SOC analyst skills.
Built on a Dell OptiPlex 7060 Micro running Proxmox VE with an isolated lab 
network managed by OPNsense firewall.

---

## About Me
Cybersecurity professional transitioning from SOC audit to defensive security.
Virginia Tech graduate building practical detection engineering skills
through hands-on attack simulation and SIEM analysis.

**Certifications:**
- CompTIA Security+
- Blue Team Level 1 (BTL1)
- CySA+ (In Progress)

---

## Lab Environment

| Component | Details |
|---|---|
| Hardware | Dell OptiPlex 7060 Micro — i5-8500T, 32GB RAM, 512GB NVMe |
| Hypervisor | Proxmox VE 9.1.1 |
| Firewall | OPNsense 26.1.2 |
| SIEM | Splunk Enterprise 9.x |
| Attack VM | Kali Linux — 10.10.10.132 |
| Target VM | Ubuntu Server 24.04 — 10.10.10.198 |
| Network | Isolated lab network 10.10.10.x behind OPNsense |

---

## Projects

| # | Domain | Project | Status | Tools |
|---|---|---|---|---|
| 01 | Linux & SIEM | SSH Brute Force Detection | ✅ Complete | Splunk, Hydra, Ubuntu |
| 02 | Network Security | OPNsense Network Visibility | ✅ Complete | Splunk, OPNsense, Nmap |

---

## Setup Documentation

| # | Guide | Description |
|---|---|---|
| 01 | Proxmox Installation | Bare metal hypervisor setup on Dell OptiPlex |
| 02 | Kali Linux VM | Attack machine configuration |
| 03 | Ubuntu + Splunk | SIEM deployment and Universal Forwarder setup |
| 04 | OPNsense Firewall | Network segmentation and firewall configuration |

---

## Detection Coverage

| Log Source | Status | Projects Using It |
|---|---|---|
| Linux auth.log | ✅ Active | Project 1 |
| OPNsense Firewall Logs | ✅ Active | Project 2 |

---

## Connect
- LinkedIn: https://www.linkedin.com/in/taylorglass/
- GitHub: https://github.com/tjglass814
