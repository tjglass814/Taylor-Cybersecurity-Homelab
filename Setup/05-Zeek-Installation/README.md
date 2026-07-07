# Zeek Network Security Monitor — Installation and Configuration

## Overview

Zeek (formerly Bro) is a passive network security monitor that reconstructs network conversations and generates structured logs from live traffic. Unlike signature-based IDS tools, Zeek is event-driven — it understands protocols at the application layer and produces rich structured telemetry that BLIP-AI uses for network-level behavioral detection.

This document covers the installation and configuration of Zeek 8.0.9 on Ubuntu Server 24.04 as part of the BLIP-AI Domain 2 network visibility stack.

## Why Zeek

| Capability | OPNsense Firewall | Zeek |
|---|---|---|
| Pass/block decisions | ✅ | ❌ |
| Connection metadata | ❌ | ✅ |
| DNS query content | ❌ | ✅ |
| TLS certificate details | ❌ | ✅ |
| HTTP request/response | ❌ | ✅ |
| File transfer metadata | ❌ | ✅ |
| Protocol anomalies | ❌ | ✅ |
| Passive device discovery | ❌ | ✅ |

OPNsense sees packets. Zeek sees conversations.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Zeek Version | 8.0.9 LTS |
| Monitored Interface | ens19 (192.168.1.x home network + WAN) |
| Log Format | JSON |
| Log Destination | /opt/zeek/logs/current/ |
| Splunk Integration | Universal Forwarder → index=main |

## Architecture

```
Internet
    ↕
ens19 (192.168.1.x) ← Zeek monitors here in promiscuous mode
    ↕
Ubuntu Server (splunk-server)
    ↕
OPNsense (10.10.10.1)
    ↕
Lab Network (10.10.10.x) ← Kali, attack simulations
```

---

## Phase 1 — Add Zeek Repository

Zeek is not in Ubuntu's default apt repositories. Add the official Zeek repository:

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt-get update
```

---

## Phase 2 — Install Zeek LTS

```bash
sudo apt-get install -y zeek-lts
```

**Note:** During installation a Postfix mail server configuration prompt may appear as a dependency. Select **No configuration** and confirm.

Add Zeek to PATH:

```bash
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
zeek --version
```

<img width="1134" height="77" alt="Screenshot 2026-07-07 at 4 49 56 PM" src="https://github.com/user-attachments/assets/24231ee4-c4dc-491e-a66b-a6889c4d0f00" />


---

## Phase 3 — Configure Interface

```bash
sudo nano /opt/zeek/etc/node.cfg
```

```ini
[zeek]
type=standalone
host=localhost
interface=ens19
```

**Interface selection:** `ens19` carries all internet-bound traffic and receives broadcast/multicast traffic from the home network segment. `ens18` carries only lab-internal traffic between Kali and Ubuntu.

---

## Phase 4 — Enable JSON Logging

```bash
echo '@load policy/tuning/json-logs' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
```

JSON logging is required for clean Splunk field extraction — all Zeek fields parse automatically as structured Splunk fields without any props.conf or transforms.conf configuration.

---

## Phase 5 — Deploy and Start Zeek

```bash
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

---

## Phase 6 — Verify Log Generation

```bash
sudo ls -la /opt/zeek/logs/current/
```

<img width="675" height="287" alt="Screenshot 2026-07-07 at 4 56 57 PM" src="https://github.com/user-attachments/assets/fa779545-e105-4bab-a351-c101a4dc7c20" />

**Key log files:**

| Log File | Contents | Investigative Value |
|---|---|---|
| `conn.log` | Every network connection — src/dst IP, port, protocol, duration, bytes | C2 beaconing, exfiltration volume, connection patterns |
| `dns.log` | Every DNS query and response — query, answer, TTL, response code | DNS tunneling, C2 domain resolution, reconnaissance |
| `ssl.log` | TLS connections — version, cipher, certificate fingerprints | Encrypted C2, self-signed certs, weak ciphers |
| `http.log` | HTTP requests — URI, host, method, user-agent, status code | Web-based C2, malicious downloads |
| `files.log` | Files transferred — MIME type, hashes, size | Malware delivery, exfiltration content |
| `weird.log` | Protocol anomalies Zeek cannot parse | Exploitation attempts, custom tooling |
| `capture_loss.log` | Packet capture gaps | Interface overload, missed traffic |
| `stats.log` | Zeek performance metrics | Baseline traffic volume |

Verify logs are populating:

```bash
sudo tail -3 /opt/zeek/logs/current/conn.log
```

<img width="1315" height="159" alt="Screenshot 2026-07-07 at 4 58 12 PM" src="https://github.com/user-attachments/assets/c46ab004-a41d-4a15-99f6-eaf7547deb36" />

---

## Phase 7 — Splunk Integration

```bash
sudo tee /opt/splunkforwarder/etc/apps/search/local/inputs.conf << 'EOF'
[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///var/log/audit/audit.log]
disabled = false
index = main
sourcetype = linux_audit

[monitor:///opt/zeek/logs/current/conn.log]
disabled = false
index = main
sourcetype = zeek_conn

[monitor:///opt/zeek/logs/current/dns.log]
disabled = false
index = main
sourcetype = zeek_dns

[monitor:///opt/zeek/logs/current/ssl.log]
disabled = false
index = main
sourcetype = zeek_ssl

[monitor:///opt/zeek/logs/current/weird.log]
disabled = false
index = main
sourcetype = zeek_weird
EOF

sudo /opt/splunkforwarder/bin/splunk restart
```

Verify ingestion in Splunk:

```spl
index=main sourcetype=zeek_conn earliest=-5m
| head 5
| table _time id.orig_h id.resp_h id.resp_p proto duration
```

<img width="1260" height="442" alt="Screenshot 2026-07-07 at 5 10 04 PM" src="https://github.com/user-attachments/assets/1315c2f0-3c65-4bce-a415-b370aae553e0" />

**JSON auto-parsing:** Splunk automatically extracts all Zeek JSON fields as searchable Splunk fields. No manual field extraction required. Fields like `id.orig_h`, `id.resp_h`, `proto`, `duration`, `orig_bytes`, and `resp_bytes` are immediately available for SPL queries.

---

## Phase 8 — Persistence

```bash
sudo /opt/zeek/bin/zeekctl cron enable
sudo crontab -l 2>/dev/null | { cat; echo "@reboot /opt/zeek/bin/zeekctl start"; } | sudo crontab -
```

---

## Zeek Log Field Reference

### conn.log — Key Fields

| Field | Description | Detection Use |
|---|---|---|
| `ts` | Connection start timestamp | Timeline correlation |
| `uid` | Unique connection ID | Cross-log correlation |
| `id.orig_h` | Source IP | Origin identification |
| `id.resp_h` | Destination IP | C2 destination |
| `id.resp_p` | Destination port | Service identification |
| `proto` | Protocol (tcp/udp/icmp) | Protocol anomaly |
| `duration` | Connection duration in seconds | Beaconing detection |
| `orig_bytes` | Bytes sent by originator | Exfiltration volume |
| `resp_bytes` | Bytes sent by responder | Download detection |
| `conn_state` | Connection state (SF/S0/REJ/etc) | Scan detection |
| `local_orig` | True if source is local | Internal vs external |
| `local_resp` | True if destination is local | Lateral movement |

### dns.log — Key Fields

| Field | Description | Detection Use |
|---|---|---|
| `query` | DNS query string | Domain reputation |
| `qtype_name` | Query type (A/AAAA/TXT/MX) | DNS tunneling |
| `answers` | DNS response answers | C2 resolution |
| `TTLs` | Time to live values | Fast-flux detection |
| `rcode_name` | Response code (NOERROR/NXDOMAIN) | DGA detection |

### ssl.log — Key Fields

| Field | Description | Detection Use |
|---|---|---|
| `version` | TLS version (TLSv1.2/TLSv1.3) | Weak cipher detection |
| `cipher` | Cipher suite | Encryption quality |
| `server_name` | SNI hostname | C2 domain detection |
| `cert_chain_fps` | Certificate fingerprints | Self-signed cert detection |
| `validation_status` | Certificate validation result | Invalid cert detection |
| `established` | Whether TLS handshake completed | Scan vs connection |

---

## Passive Network Discovery — Security Note

Zeek on `ens19` passively captures mDNS (port 5353) and LLMNR (port 5355) broadcast traffic from all devices on the home network segment. Without any active scanning, Zeek reveals device hostnames, IP addresses, model information, and advertised services from every Apple device, Windows machine, and IoT device broadcasting on `192.168.1.x`.

**Security implication:** An attacker who compromises a server on your network gains this same passive visibility immediately — before running a single nmap scan. This reconnaissance is completely undetectable by endpoint security tools. Proper network segmentation prevents cross-segment passive discovery.

---

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `zeek` command not found | Binary not in PATH | `echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc && source ~/.bashrc` |
| No dns.log or ssl.log | Wrong interface monitored | Change interface in node.cfg to match traffic path |
| Permission denied on logs | Zeek runs as root | Use `sudo` to read log files |
| Zeek stops after reboot | No persistence configured | Add `@reboot` crontab entry |
| No Splunk events | Forwarder not restarted | `sudo /opt/splunkforwarder/bin/splunk restart` |

---

## Verification Checklist

- [ ] `zeek --version` returns 8.0.9
- [ ] `zeekctl status` shows running
- [ ] `conn.log` populating with JSON records
- [ ] `dns.log` populating after traffic generation
- [ ] `ssl.log` populating after HTTPS traffic
- [ ] Splunk showing `sourcetype=zeek_conn` events
- [ ] Splunk showing `sourcetype=zeek_dns` events
- [ ] Zeek starts automatically after reboot

---
