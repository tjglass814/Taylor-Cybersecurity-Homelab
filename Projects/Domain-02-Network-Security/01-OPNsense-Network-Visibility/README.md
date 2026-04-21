# Project 2 — OPNsense Network Visibility

## Overview
This project establishes network-level visibility into the homelab environment 
by configuring OPNsense to forward firewall logs to Splunk via syslog. Combined 
with existing host-level logs from Project 1, this creates a dual-layer detection 
capability that mirrors enterprise SOC environments.

## Objectives
- Configure OPNsense remote syslog forwarding to Splunk
- Establish network-level visibility alongside existing host-level logs
- Detect simulated reconnaissance attack at the network layer
- Demonstrate cross-source correlation between firewall and host logs

## MITRE ATT&CK Mapping
| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Nmap port scan detected at firewall |
| Network Sniffing | T1040 | Traffic visible through OPNsense |

---

## Environment

| Component | Value |
|---|---|
| Firewall | OPNsense 26.1.2 |
| SIEM | Splunk Enterprise 9.x |
| Attack VM | Kali Linux 10.10.10.132 |
| Target VM | Ubuntu Server 10.10.10.198 |
| Syslog Port | UDP 5514 |
| Log Source 1 | linux_secure — host logs |
| Log Source 2 | syslog — OPNsense firewall logs |

---

## Step 1 — Configure Splunk UDP Input

Created a new UDP data input in Splunk to receive syslog from OPNsense.

**Settings → Data Inputs → UDP → New Local UDP Input**

| Field | Value |
|---|---|
| Port | 5514 |
| Source Type | syslog |
| Index | main |
| Restrict to Host | 10.10.10.1 |

> Port 514 was unavailable as it requires root privileges on Linux.
> Port 5514 is used instead — a registered port accessible to Splunk.

Verified Splunk was listening on port 5514:
```bash
sudo ss -ulnp | grep 5514
# Result: 0.0.0.0:5514 splunkd ✅
```

---

## Step 2 — Configure OPNsense Remote Syslog

Configured OPNsense to forward all firewall logs to Splunk.

**System → Settings → Logging → Remote → Add**

| Field | Value |
|---|---|
| Enabled | Yes |
| Transport | UDP(4) |
| Applications | All |
| Levels | All |
| Facilities | All |
| Hostname | 10.10.10.198 |
| Port | 5514 |
| Description | Splunk SIEM |

Clicked Apply and restarted syslog service:
```bash
/usr/local/sbin/configctl syslog restart
```

---

## Step 3 — Verify Log Flow

Used tcpdump on Ubuntu to confirm packets arriving from OPNsense:
```bash
sudo tcpdump -i ens18 udp port 5514
```

**Troubleshooting Note:**
Initial configuration had a typo — port 4514 instead of 5514.
Diagnosed using tcpdump which showed:
OPNsense.internal > splunk-server.4514: UDP
ICMP splunk-server udp port 4514 unreachable
Corrected port number in OPNsense remote logging config and reapplied.

Confirmed correct flow after fix:
OPNsense.internal > splunk-server.5514: UDP ✅

---

## Step 4 — Verify In Splunk

Confirmed OPNsense logs appearing in Splunk:
index=main sourcetype=syslog 

<img width="1277" height="1080" alt="Screenshot 2026-04-20 at 5 11 47 PM" src="https://github.com/user-attachments/assets/13815432-e19a-4cad-a565-81556c9fd33c" />

Confirmed dual log sources operational:
index=main (sourcetype=syslog OR sourcetype=linux_secure)
| stats count by sourcetype host

<img width="1277" height="1080" alt="Screenshot 2026-04-20 at 5 12 12 PM" src="https://github.com/user-attachments/assets/3ee31ab3-f4f1-409c-83f5-e6ea64f9dd97" />


Results:
| sourcetype | host | count |
|---|---|---|
| linux_secure | splunk-server | 4,819 |
| syslog | 10.10.10.1 | 6,893 |

---

## Step 5 — Attack Simulation

Simulated network reconnaissance from Kali against Ubuntu:

```bash
nmap -sS 10.10.10.198
```

Nmap results confirmed open ports on Ubuntu:
PORT     STATE  SERVICE
22/tcp   open   SSH
5432/tcp open   postgresql
8089/tcp open   http-alt

---

## Step 6 — Detection

Searched Splunk for Kali's IP in firewall logs:
index=main sourcetype=syslog earliest=-2m
10.10.10.132

<img width="1247" height="1007" alt="Screenshot 2026-04-20 at 5 17 04 PM" src="https://github.com/user-attachments/assets/29c79394-023d-48f9-9048-7a3e6279d7df" />


**Confirmed Detection:**
filterlog: match, pass, in, vtnet1,
10.10.10.132 → 10.10.10.198

OPNsense caught Kali's reconnaissance at the network layer and 
logged it to Splunk successfully.

---

## Detection Rules

### Rule 1 — Network Reconnaissance Detection
index=main sourcetype=syslog
| rex field=_raw "(?P<src_ip>\d+.\d+.\d+.\d+),10.10.10."
| stats count by src_ip
| where count > 10
| sort -count

### Rule 2 — Cross-Source Correlation
index=main (sourcetype=syslog OR sourcetype=linux_secure)
| stats count by sourcetype host

### Rule 3 — Same Attacker IP In Both Sources
index=main (sourcetype=syslog OR sourcetype=linux_secure)
earliest=-15m
| rex field=_raw "from (?P<src_ip>\d+.\d+.\d+.\d+)"
| stats values(sourcetype) as sources count by src_ip
| where mvcount(sources) > 1

This final query is the foundation of BLIP-AI cross-source 
correlation — finding the same attacker IP appearing in both 
network and host logs simultaneously.

---

## Key Findings

| Finding | Detail |
|---|---|
| Log sources operational | linux_secure + syslog both flowing |
| Total events captured | 11,712 across both sources |
| Nmap scan detected | Kali 10.10.10.132 caught by OPNsense |
| Cross-source visibility | Same attack visible at host AND network layer |
| Detection latency | Under 2 minutes from attack to Splunk |

---

## Key Concepts Learned

| Concept | Application |
|---|---|
| Log Aggregation | Centralizing firewall logs into Splunk SIEM |
| Syslog UDP 5514 | Universal logging protocol for network devices |
| Network Segmentation | Isolated lab forces all traffic through firewall |
| Packet Capture | tcpdump used to diagnose syslog delivery issue |
| Firewall Rule Logging | Must be explicitly enabled per rule in OPNsense |
| Field Extraction | Raw syslog requires rex for IP field extraction |
| Cross-Source Correlation | Same event visible in multiple log sources |
| NAT | Lab VMs reach internet via OPNsense WAN IP |
| Default Deny | WAN blocks all inbound unless explicitly allowed |
| Implicit Deny | Unmatched traffic dropped automatically |

---

## Troubleshooting Reference

| Issue | Cause | Resolution |
|---|---|---|
| UDP 514 unavailable | Privileged port requires root | Use port 5514 |
| No logs in Splunk | Wrong port in OPNsense config | tcpdump diagnosis |
| Typo — port 4514 | Manual entry error | Corrected to 5514 |
| Logs not flowing after save | Apply not clicked | Click Apply in OPNsense |
| src_ip field empty | Syslog needs rex extraction | Use rex in SPL query |

---
