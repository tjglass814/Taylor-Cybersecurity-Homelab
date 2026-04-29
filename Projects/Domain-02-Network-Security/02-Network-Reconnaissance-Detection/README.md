# Project 05 — Network Reconnaissance Detection

## Overview

This project simulates four network reconnaissance techniques using Nmap and builds three behavioral Splunk detection rules using OPNsense firewall logs. Unlike the previous projects thus far which used auditd host-based telemetry, this project shifts to **network-based detection** — catching attackers at the perimeter before they ever reach their target.

Every detection uses behavioral analysis rather than signature matching — identifying reconnaissance patterns based on traffic volume, port targeting intent, and campaign persistence rather than specific tool signatures. An attacker using any scanning tool produces the same behavioral fingerprint.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 10.10.10.132 |
| Target | OPNsense WAN — 192.168.1.214 |
| Firewall | OPNsense 26.1.2 |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | OPNsense filterlog via UDP syslog port 5514 |
| Hypervisor | Proxmox VE on Dell OptiPlex 7060 Micro |
| Network | Isolated lab segment 10.10.10.x behind OPNsense |

---

## Project Metrics

| Metric | Result |
|---|---|
| Scan techniques simulated | 4 |
| Detection rules built | 3 |
| Total syslog events ingested | 827,553 |
| Unique ports detected across all scans | 632 |
| Total scan packets captured | 1,748 |
| Detection coverage rate | 100% |
| MITRE technique | T1046 — Network Service Discovery |

---

## Network Architecture Lesson

An important lesson discovered during this project: **traffic between two hosts on the same network segment does not pass through the firewall rule engine.** Kali (`10.10.10.x`) scanning Ubuntu (`10.10.10.x`) travels at Layer 2 and never reaches OPNsense's firewall rules.

The solution — scan OPNsense's WAN interface (`192.168.1.214`) from Kali. This traffic crosses from the lab segment to the WAN segment, passing through OPNsense and generating filterlog entries. This is actually more realistic — real attackers on a compromised internal machine probe network infrastructure and adjacent segments, not just same-subnet hosts.

---

## Phase 1 — OPNsense Logging Configuration

A firewall rule was added to OPNsense to explicitly log Kali traffic:

**Firewall → Rules → LAN → Add at TOP of list**

| Field | Value |
|---|---|
| Action | Pass |
| Interface | LAN |
| Direction | in |
| Protocol | any |
| Source | 10.10.10.132 |
| Destination | any |
| Log | ✅ Enabled |
| Description | Log Kali to Ubuntu traffic for detection |

> **Important note — rule must sit at the TOP of the LAN rules list.** OPNsense processes rules top-to-bottom on a first-match basis. A logging rule placed below the default allow-all rule never fires because all traffic matches the allow-all first.

### Understanding OPNsense filterlog Format

OPNsense logs every packet as a comma-separated filterlog entry:

```
90,,,eb9cc6f498a2ac99,vtnet1,match,pass,in,4,0x0,,64,16622,0,DF,6,tcp,60,10.10.10.132,192.168.1.214,851,443,0,S,...
```

| Position | Field | Example |
|---|---|---|
| 7 | Action | `pass` or `block` |
| 8 | Direction | `in` or `out` |
| 17 | Protocol | `tcp`, `udp`, `icmp` |
| 19 | Source IP | `10.10.10.132` |
| 20 | Destination IP | `192.168.1.214` |
| 21 | Source Port | `851` |
| 22 | Destination Port | `443` |

---

## Phase 2 — Attack Simulation

Four Nmap scan types were run from Kali targeting OPNsense's WAN interface at `192.168.1.214`:

### Scan 1 — SYN Scan (T1046)

```bash
sudo nmap -sS 192.168.1.214
```

Sends SYN packets to the top 1000 ports without completing the TCP handshake. Fast and relatively stealthy — generates minimal log entries per port but hits hundreds of ports rapidly.

### Scan 2 — Service Version Detection (T1046)

```bash
sudo nmap -sV 192.168.1.214
```

Probes open ports to determine exact software versions running. Specifically fingerprints what services are exposed and their versions — intelligence used to select exploits.

### Scan 3 — OS Detection (T1046)

```bash
sudo nmap -O 192.168.1.214
```

Sends specially crafted packets to identify the target operating system. Generates distinctive traffic patterns including ICMP probes and unusual TCP flag combinations.

### Scan 4 — Aggressive Scan (T1046)

```bash
sudo nmap -A 192.168.1.214
```

Combines SYN scan, service detection, OS detection, and traceroute simultaneously. The loudest scan type — generates the highest volume of unique port hits in the shortest time window.

### Baseline Verification — Confirming Scan Data in Splunk

Before building detections, scan traffic was confirmed in Splunk using this baseline query:

```spl
index=main sourcetype=syslog earliest=-30m
| rex field=_raw "(?P<src_ip>10\.10\.10\.\d+),(?P<dst_ip>[\d.]+),(?P<src_port>\d+),(?P<dst_port>\d+)"
| where src_ip="10.10.10.132"
| stats dc(dst_port) as unique_ports count as total_packets by src_ip dst_ip
| sort -unique_ports
```

---

<img width="1169" height="960" alt="Screenshot 2026-04-28 at 9 22 01 PM" src="https://github.com/user-attachments/assets/0227df26-56ce-4658-aa56-7843a331d7dd" />

> The table should display four columns: `src_ip`, `dst_ip`, `unique_ports`, and `total_packets`.
> The top row should show `10.10.10.132 → 192.168.1.214` with 200+ unique ports confirming scan data landed in Splunk before any detection was built.

---

**Result:** 228 unique ports, 383 packets confirmed — attack data verified in Splunk before building detections.

---

## Phase 3 — Detection Engineering

Three behavioral detection rules were built using OPNsense filterlog data. Each detects a different dimension of reconnaissance behavior — volume, intent, and persistence.

---

### Detection 1 — Port Scan Detection

**What it catches:** Any source IP hitting an unusually high number of unique destination ports within a 5 minute window — the core behavioral signature of port scanning regardless of which tool was used.

**The behavioral difference:**

| Traffic Type | Unique Ports per 5 Minutes |
|---|---|
| Normal web browsing | 2-5 |
| Developer testing | 5-10 |
| Targeted port scan | 20-50 |
| Full port scan | 100-1000+ |

```spl
index=main sourcetype=syslog earliest=-15m
| rex field=_raw "(?P<src_ip>10\.10\.10\.\d+),(?P<dst_ip>[\d.]+),(?P<src_port>\d+),(?P<dst_port>\d+)"
| where isnotnull(src_ip) AND isnotnull(dst_port)
| bin _time span=5m
| stats dc(dst_port) as unique_ports count as total_packets by src_ip dst_ip _time
| where unique_ports >= 10
| eval risk_level=case(
    unique_ports>=100, "CRITICAL — Aggressive full port scan",
    unique_ports>=50,  "HIGH — Port scan detected",
    unique_ports>=20,  "MEDIUM — Possible port scan",
    unique_ports>=10,  "LOW — Suspicious port activity")
| eval scan_type=case(
    unique_ports>=100, "Full scan — Nmap aggressive or similar",
    unique_ports>=50,  "Service scan — Top ports enumerated",
    unique_ports>=20,  "Targeted scan — Specific port range",
    unique_ports>=10,  "Probe — Initial reconnaissance")
| table _time src_ip dst_ip unique_ports total_packets scan_type risk_level
| sort -unique_ports
```

---

<img width="1169" height="960" alt="Screenshot 2026-04-28 at 9 30 39 PM" src="https://github.com/user-attachments/assets/1c616877-5a70-4433-bbd9-e4abda68d5ad" />

> The table should show `10.10.10.132 → 192.168.1.214` with 400+ unique ports, `scan_type` labeled as "Full scan — Nmap aggressive or similar", and `risk_level` showing `CRITICAL — Aggressive full port scan`.

---

### Detection 2 — Sensitive Service Enumeration

**What it catches:** Source IPs probing high-value service ports regardless of total scan volume. A patient attacker checking only SSH, RDP, and SMB hits just 3 ports — evading Detection 1 entirely. Detection 2 catches them by recognizing which specific ports they are interested in.

**Sensitive ports monitored:**

| Port | Service | Why Attackers Target It |
|---|---|---|
| 22 | SSH | Remote command execution |
| 23 | Telnet | Unencrypted remote access |
| 80 / 443 | HTTP / HTTPS | Web application attacks |
| 445 | SMB | Windows lateral movement |
| 3389 | RDP | Remote desktop access |
| 3306 | MySQL | Database credential access |
| 5432 | Postgres | Database credential access |
| 8000 | Splunk Web | Security tool access |

```spl
index=main sourcetype=syslog earliest=-15m
| rex field=_raw "(?P<src_ip>10\.10\.10\.\d+),(?P<dst_ip>[\d.]+),(?P<src_port>\d+),(?P<dst_port>\d+)"
| where isnotnull(src_ip) AND isnotnull(dst_port)
| eval dst_port=tonumber(dst_port)
| eval sensitive_port=case(
    dst_port=22,   "SSH",
    dst_port=23,   "Telnet",
    dst_port=25,   "SMTP",
    dst_port=53,   "DNS",
    dst_port=80,   "HTTP",
    dst_port=443,  "HTTPS",
    dst_port=445,  "SMB",
    dst_port=3389, "RDP",
    dst_port=5432, "Postgres",
    dst_port=8000, "Splunk Web",
    dst_port=9997, "Splunk Forwarder",
    dst_port=3306, "MySQL",
    dst_port=21,   "FTP",
    dst_port=110,  "POP3",
    dst_port=143,  "IMAP",
    dst_port=5900, "VNC")
| where isnotnull(sensitive_port)
| stats count values(sensitive_port) as services_probed dc(sensitive_port) as unique_services by src_ip dst_ip
| where unique_services >= 2
| eval risk_level=case(
    unique_services>=6, "CRITICAL — Broad sensitive service enumeration",
    unique_services>=4, "HIGH — Multiple high-value services probed",
    unique_services>=2, "MEDIUM — Sensitive service reconnaissance")
| table src_ip dst_ip unique_services services_probed count risk_level
| sort -unique_services
```

---

<img width="1169" height="960" alt="Screenshot 2026-04-28 at 9 41 37 PM" src="https://github.com/user-attachments/assets/e233a4c5-8cd6-4741-81db-2ad7a298304f" />

> The table should show `10.10.10.132 → 192.168.1.214` with `services_probed` listing DNS, HTTP, HTTPS and `risk_level` showing `MEDIUM — Sensitive service reconnaissance`.

---

### Detection 3 — Repeated Reconnaissance Campaign

**What it catches:** The same source IP appearing across multiple scan windows over an extended time period. A single port scan could be accidental or a misconfigured tool. The same IP scanning repeatedly over hours is a deliberate reconnaissance campaign.

**Why this is the most intelligence-rich detection:** It does not just say "a scan happened." It says "this specific attacker has been mapping your network persistently." 

```spl
index=main sourcetype=syslog earliest=-4h
| rex field=_raw "(?P<src_ip>10\.10\.10\.\d+),(?P<dst_ip>[\d.]+),(?P<src_port>\d+),(?P<dst_port>\d+)"
| where isnotnull(src_ip) AND isnotnull(dst_port)
| bin _time span=5m
| stats dc(dst_port) as unique_ports by src_ip dst_ip _time
| where unique_ports >= 10
| stats count as scan_windows avg(unique_ports) as avg_ports dc(dst_ip) as targets_scanned by src_ip
| where scan_windows >= 2
| eval risk_level=case(
    scan_windows>=5, "CRITICAL — Sustained reconnaissance campaign",
    scan_windows>=3, "HIGH — Repeated scanning behavior detected",
    scan_windows>=2, "MEDIUM — Multiple scan windows observed")
| eval campaign_summary=src_ip." scanned ".tostring(round(avg_ports,0))." avg ports across ".tostring(scan_windows)." windows targeting ".tostring(targets_scanned)." host(s)"
| table src_ip scan_windows avg_ports targets_scanned campaign_summary risk_level
| sort -scan_windows
```

---

<img width="1169" height="960" alt="Screenshot 2026-04-28 at 9 49 21 PM" src="https://github.com/user-attachments/assets/4b163ede-c21c-495d-a29d-d23dba301483" />

> The table should show `10.10.10.132` with `scan_windows` showing 3+, and the `campaign_summary` field reading something like "10.10.10.132 scanned 228 avg ports across 3 windows targeting 1 host(s)" with `HIGH — Repeated scanning behavior detected` visible.

---

## Phase 4 — Alert Validation

All three alerts confirmed firing simultaneously after a single Nmap aggressive scan. Detection 3 fired on the 4 hour lookback capturing the cumulative scan history from the session. One attack — three independent detection layers firing simultaneously.

---

<img width="1169" height="445" alt="Screenshot 2026-04-28 at 10 03 36 PM" src="https://github.com/user-attachments/assets/0ec4c51f-f0ad-4cb8-bb27-07c5e2b9c172" />

> All three alerts should be visible — `Network Port Scan Detected`, `Sensitive Service Enumeration Detected`, and `Repeated Network Reconnaissance Campaign Detected` — all showing timestamps within the same window.

---

## Detection Coverage

| Detection | Catches | Misses |
|---|---|---|
| Port Scan | High volume scanning | Patient low-volume scans |
| Service Enumeration | Targeted sensitive port probing | Non-sensitive port recon |
| Repeated Campaign | Persistent attacker behavior | First-time scans under threshold |

Together they provide complete reconnaissance lifecycle coverage:

- **Loud aggressive scanner** → Detection 1 catches volume immediately
- **Patient attacker** checking 3 specific ports → Detection 2 catches intent
- **Any attacker who returns** → Detection 3 catches the campaign pattern

---

## MITRE ATT&CK Mapping

| Technique | ID | Scan Type | Detected By |
|---|---|---|---|
| Network Service Discovery | T1046 | SYN scan | Detection 1 |
| Network Service Discovery | T1046 | Service version scan | Detection 1 + 2 |
| Network Service Discovery | T1046 | OS detection scan | Detection 1 |
| Network Service Discovery | T1046 | Aggressive scan | Detection 1 + 2 + 3 |

---

## Known Limitations and Detection Gaps

| Gap | Description | Mitigation Path |
|---|---|---|
| Same-subnet blind spot | Traffic between hosts on same LAN segment bypasses firewall logging | Network TAP or SPAN port for full visibility |
| IPv6 scanning | Current regex targets IPv4 only — IPv6 scans not captured | Add IPv6 pattern matching |
| Slow scans | Under 10 ports per 5 minutes evades Detection 1 | Longer time windows with lower thresholds |
| UDP scanning | UDP scan traffic inconsistent in filterlog | Dedicated UDP logging rules |
| External scans | Internet-sourced scanning not in current detection scope | WAN interface logging rules |
