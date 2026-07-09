# Project 03 — Zeek Network Monitoring

## Overview

This project establishes network-level behavioral detection for BLIP-AI using Zeek 8.0.9 as a passive network security monitor. It covers three phases: understanding Zeek's architecture and log structure, building a documented 24-hour network baseline that defines normal behavior in this environment, and detection engineering on Zeek telemetry including BLIP-AI's first cross-domain correlation between network and host signals.

Where Domain 1 told Rocky what ran on the box, Domain 2 tells Rocky what was communicated and where it went. This project is the bridge — combining host-level auditd evidence with network-level Zeek evidence to reconstruct the full picture of an attack.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Zeek Version | 8.0.9 LTS |
| Monitored Interface | ens19 (WAN + home network segment) |
| Log Format | JSON — automatic field extraction in Splunk |
| Splunk Sourcetypes | zeek_conn, zeek_dns, zeek_ssl, zeek_weird |
| Installation Reference | Setup/05-Zeek-Installation/ |

## Project Metrics

| Metric | Value |
|---|---|
| New Splunk Sourcetypes | 4 |
| Baseline Period | 24 hours |
| Detections Built | 4 |
| Detections Fully Operational | 3 |
| Detections Architecturally Validated | 1 (DNS — sensor placement limitation) |
| Cross-Domain Detections | 1 (first in BLIP-AI) |
| MITRE Techniques Covered | 5 |
| Eva Review Cycles | 8 total across all detections |

---

## Phase 1 — Understanding Zeek Telemetry

### Why Zeek Is Different From IDS

Zeek is frequently confused with intrusion detection systems like Snort or Suricata. The distinction is fundamental.

Signature-based IDS matches traffic against known-bad patterns. It answers "does this look like a known attack?" It misses unknown threats, zero-days, and anything an attacker designs to avoid signatures.

Zeek reconstructs network conversations and generates structured telemetry regardless of whether traffic looks malicious. It answers "what happened on the network?" without preconceptions about what bad looks like. This is the same behavioral philosophy that drives all of BLIP-AI's Domain 1 detections — look for anomalies from baseline, not signatures.

Zeek's event-driven architecture understands protocols at the application layer. A TLS connection becomes not just "TCP to port 443" but a record containing TLS version, cipher suite, certificate chain fingerprints, SNI hostname, and whether the handshake completed. That depth enables meaningful behavioral detection on encrypted traffic.

### The Major Log Files

**conn.log — The Foundation**

Every network connection generates a conn.log record. This is the most important log for behavioral detection — it captures conversation metadata regardless of protocol.

| Field | Description | Detection Use |
|---|---|---|
| `uid` | Unique connection identifier | Cross-log correlation |
| `id.orig_h` | Source IP | Origin identification |
| `id.resp_h` | Destination IP | C2 destination |
| `id.resp_p` | Destination port | Service identification |
| `proto` | tcp / udp / icmp | Protocol anomaly |
| `duration` | Connection duration in seconds | Beaconing detection |
| `orig_bytes` | Bytes sent by originator | Exfiltration volume |
| `resp_bytes` | Bytes sent by responder | Download detection |
| `conn_state` | SF / S0 / REJ / RSTO | Scan detection |
| `local_orig` | True if source is local | Internal vs external |
| `local_resp` | True if destination is local | Lateral movement |
| `history` | Packet sequence encoding | Connection behavior |

**dns.log — Name Resolution Visibility**

Every DNS query and response. DNS is uniquely valuable because nearly every network action starts with a name lookup — C2 communication, malware updates, data exfiltration, and reconnaissance all leave DNS traces.

| Field | Description | Detection Use |
|---|---|---|
| `query` | Domain being resolved | Domain reputation |
| `qtype_name` | Query type A/AAAA/TXT/MX/CNAME | DNS tunneling |
| `answers` | DNS response answers | C2 resolution |
| `TTLs` | Time-to-live values | Fast-flux detection |
| `rcode_name` | NOERROR / NXDOMAIN | DGA detection |

**ssl.log — Encrypted Traffic Metadata**

TLS/SSL handshake metadata. Even encrypted content reveals significant information through handshake analysis.

| Field | Description | Detection Use |
|---|---|---|
| `version` | TLS version | Weak cipher detection |
| `cipher` | Cipher suite negotiated | Encryption quality |
| `server_name` | SNI hostname | C2 domain detection |
| `cert_chain_fps` | Certificate fingerprints | Self-signed cert detection |
| `validation_status` | Certificate validation | Invalid cert detection |
| `established` | Whether handshake completed | Scan vs connection |

**weird.log — Protocol Anomalies**

Everything Zeek cannot cleanly parse. In a clean environment weird.log should be quiet. Spikes often precede exploitation attempts or indicate custom tooling.

| Anomaly | Meaning |
|---|---|
| `SYN_seq_jump` | TCP sequence number anomaly |
| `DNS_Conn_count_too_large` | Excessive DNS connections from single source |
| `active_connection_reuse` | HTTP keep-alive reuse (normal) |
| `bad_TCP_checksum` | NIC checksum offloading (normal) |
| `data_before_established` | Data sent before TCP handshake |

**The uid Field — Cross-Log Correlation**

Every Zeek log shares a `uid` field — the unique connection identifier. A single HTTPS download generates records in conn.log, ssl.log, http.log, and files.log — all sharing the same uid. This enables full cross-log correlation: start with a suspicious conn.log entry and pivot to every other log for the complete picture.

**BLIP-AI Field Extraction Note**

Zeek JSON field extraction via Splunk auto-parse is inconsistent in this environment. The `where id.orig_h=` filter fails; `rex field=_raw` extraction is required for reliable IP matching. This is a known Splunk JSON parsing issue and is documented throughout the detection queries.

---

## Phase 2 — Splunk Integration

Four sourcetypes configured in the Universal Forwarder:

```
sourcetype=zeek_conn   → /opt/zeek/logs/current/conn.log
sourcetype=zeek_dns    → /opt/zeek/logs/current/dns.log
sourcetype=zeek_ssl    → /opt/zeek/logs/current/ssl.log
sourcetype=zeek_weird  → /opt/zeek/logs/current/weird.log
```

<img width="1260" height="450" alt="Screenshot 2026-07-08 at 4 58 00 PM" src="https://github.com/user-attachments/assets/baa787d6-80ad-4928-9729-1d510c2fc68c" />


JSON auto-parsing extracts all Zeek fields as searchable Splunk fields without any props.conf or transforms.conf configuration.

---

## Phase 3 — Network Baseline

The baseline was built by querying 24 hours of Zeek telemetry collected passively from the lab and home network segments.

### Traffic Volume

Over 24 hours Zeek observed approximately 22,000 connection events:

| Sourcetype | Events | Notes |
|---|---|---|
| zeek_conn | ~22,051 | Connection metadata |
| zeek_dns | ~26,000 | DNS queries — mostly mDNS from home network |
| zeek_ssl | Small | TLS records |
| zeek_weird | ~29 | Protocol anomalies |

### Traffic Direction

<img width="1260" height="638" alt="Screenshot 2026-07-08 at 5 15 35 PM" src="https://github.com/user-attachments/assets/295f62a4-357f-408b-af38-6dc1c20b6e2c" />


| Direction | Connections | Description |
|---|---|---|
| Local → Local | 16,026 | mDNS, home network device chatter |
| Local → External | 5,522 | Server and home network outbound |
| External → External | 154 | Transit traffic visible on interface |

The dominant pattern is local-to-local multicast — mDNS service discovery, IPv6 neighbor discovery, and home network device announcements. Normal for a home network environment.

### Outbound Connection Baseline

<img width="1260" height="453" alt="Screenshot 2026-07-08 at 5 16 01 PM" src="https://github.com/user-attachments/assets/0bc177c7-6ae9-49a2-a0d1-7d9f962b5160" />


| Protocol | Port | Connections | Avg Duration | Avg Bytes Sent | Avg Bytes Recv |
|---|---|---|---|---|---|
| tcp | 443 | 580 | 2.75s | 2,320 | 2,625 |
| udp | 41641 | 13 | 0.07s | 0 | 32 |

**TCP baseline:** Average 2.75 seconds, maximum 10.30 seconds. HTTPS (port 443) is the only significant external TCP protocol. Any connection lasting longer than 60 seconds or connecting on a non-443 port is anomalous.

**Byte baseline:** Symmetric bytes (2,320 sent vs 2,625 received) indicates normal request/response. Connections where sent bytes significantly exceeds received bytes indicates exfiltration.

### DNS Baseline

<img width="1260" height="790" alt="Screenshot 2026-07-08 at 7 37 17 PM" src="https://github.com/user-attachments/assets/0d779391-2c15-4d0f-8ba8-8a17b8cfbea7" />

The lab server does not appear as a DNS originator in Zeek telemetry. The server uses DNS-over-HTTPS (DoH) or routes DNS through a path not captured on ens19. This is a documented baseline data point — if the server ever appears as a zeek_dns originator it indicates a change in DNS routing that warrants investigation.

DNS traffic visible in zeek_dns originates from home network devices — primarily mDNS service discovery from consumer devices.

### Protocol Anomaly Baseline (weird.log)

All observed weird.log entries have normal explanations in this environment:

| Anomaly | Source | Count | Classification |
|---|---|---|---|
| SYN_seq_jump | Home network device | 369 | Normal — specific device's network stack |
| DNS_Conn_count_too_large | Multiple devices | 52 | Normal — aggressive DNS polling by consumer devices |
| active_connection_reuse | Lab server | 47 | Normal — HTTP keep-alive |
| bad_TCP_checksum | Lab server | 2 | Normal — NIC checksum offloading |
| bad_UDP_checksum | Multiple | 4 | Normal — NIC checksum offloading |

### Passive Device Discovery Finding

Zeek on ens19 passively captures mDNS broadcast traffic from all devices on the home network segment (`192.168.1.x`). Without any active scanning, Zeek reveals device hostnames, model information, IP addresses, and advertised services from every Apple device, Windows machine, and IoT device broadcasting mDNS.

**Security implication:** An attacker who compromises a server on a shared network segment gains immediate passive visibility into all other devices broadcasting on that segment. This reconnaissance is undetectable by endpoint security tools and requires no active scanning. Proper network segmentation — separate VLANs for servers, personal devices, and IoT — is the architectural control that prevents cross-segment passive discovery.

---

## Phase 4 — Detection Engineering

### Detection 1 — Long Duration External Connection

**Description:** Detects TCP connections statistically anomalous in duration using a dynamic threshold of mean plus three standard deviations calculated from the prior 24 hours of actual traffic. Evidence weight scales with how many standard deviations above baseline the connection falls.

**MITRE:** T1071.001 — Application Layer Protocol: Web, T1573 — Encrypted Channel

**Baseline threshold:** Any TCP connection more than 3σ above the mean is anomalous. In this environment with a baseline max of 10.30 seconds, connections lasting hours trigger this detection.

**Key architectural lesson:** Eva flagged that `local_orig="true"` filter was excluding long-duration connections because Zeek doesn't recognize the server's IPv6 addresses as local. Removing the local origin filter and detecting purely on statistical duration anomaly is the correct approach.

**Eva critical fix applied:** Added `baseline_std=if(baseline_std<0.1,0.1,baseline_std)` guard to prevent division by zero or inflated z-scores when traffic is very consistent.

```spl
index=main sourcetype=zeek_conn earliest=-24h
| where proto="tcp"
| where isnotnull(duration)
| eventstats avg(duration) as baseline_avg stdev(duration) as baseline_std
| eval baseline_std=if(baseline_std<0.1,0.1,baseline_std)
| eval threshold=baseline_avg + (3 * baseline_std)
| where duration > threshold
| eval duration_min=round(duration/60,2)
| eval mb_sent=round(orig_bytes/1024/1024,3)
| eval mb_recv=round(resp_bytes/1024/1024,3)
| eval deviations_above=round((duration-baseline_avg)/baseline_std,1)
| eval evidence_weight=case(
    deviations_above > 10, 0.95,
    deviations_above > 6, 0.85,
    deviations_above > 3, 0.75,
    true(), 0.65
)
| eval detection="Long Duration External Connection Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| table detection severity evidence_weight id.orig_h id.resp_h id.resp_p duration_min deviations_above mb_sent mb_recv conn_state baseline_avg baseline_std
| sort -deviations_above
```

<img width="1260" height="453" alt="Screenshot 2026-07-08 at 6 01 18 PM" src="https://github.com/user-attachments/assets/76df5530-b81d-4b45-9932-9924b5c598b9" />


**Result:** HIGH at 0.85. Two Tailscale persistent connections scoring 6.5 and 6.2 standard deviations above baseline — documented known false positive from persistent VPN connections.

**Alert Settings:**
- Title: `Long Duration External Connection Detected`
- Alert type: Scheduled — `*/10 * * * *`
- Time Range: Last 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 2 — DNS Anomaly Detection

**Description:** Detects three independent DNS anomaly signals — high query volume (>100 queries per 5-minute window), high NXDOMAIN ratio (>20% indicating DGA behavior), and high TXT query ratio (>20% indicating DNS tunneling). Each signal scores independently; multiple signals together reach CRITICAL.

**MITRE:** T1071.004 — Application Layer Protocol: DNS, T1048.003 — Exfiltration Over Alternative Protocol

**⚠️ Documented Architectural Limitation**

This detection cannot be exercised in the current lab deployment. Zeek on `ens19` only captures mDNS broadcast traffic (port 5353) — unicast DNS queries from client devices traverse the home router's NAT before reaching the monitored interface and are not visible to Zeek.

In an enterprise deployment Zeek is positioned on a SPAN port, TAP, or network edge where all DNS traffic passes through the monitoring point. In those deployments this detection is fully operational. The detection logic and scoring model are architecturally correct — they require only a different sensor placement to function.

**Detection Status:** Validated in design. Deployment constrained by current sensor placement. Will become operational when Zeek is deployed on OPNsense or a network TAP.

```spl
index=main sourcetype=zeek_dns earliest=-60m
| where id.resp_p!="5353"
| where NOT match(query,"\.local$")
| bin _time span=5m
| eval is_nxdomain=if(rcode_name="NXDOMAIN",1,0)
| eval is_txt=if(qtype_name="TXT",1,0)
| stats
    count as total_queries
    sum(is_nxdomain) as nxdomain_count
    sum(is_txt) as txt_count
    dc(query) as unique_queries
    by id.orig_h _time
| eval nxdomain_ratio=round(nxdomain_count/total_queries*100,1)
| eval txt_ratio=round(txt_count/total_queries*100,1)
| eval high_volume=if(total_queries>100,1,0)
| eval high_nxdomain=if(nxdomain_ratio>20 AND total_queries>10,1,0)
| eval high_txt=if(txt_ratio>20 AND total_queries>10,1,0)
| eval signal_count=high_volume+high_nxdomain+high_txt
| where signal_count >= 1
| eval evidence_weight=case(
    signal_count=3, 0.95,
    signal_count=2, 0.85,
    high_nxdomain=1, 0.80,
    high_txt=1, 0.75,
    high_volume=1, 0.65,
    true(), 0.60
)
| eval detection="DNS Anomaly Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table detection severity evidence_weight id.orig_h window total_queries unique_queries nxdomain_ratio txt_ratio signal_count
| sort -evidence_weight
```

**Alert Settings:**
- Title: `DNS Anomaly Detected`
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 3 — C2 Beacon Pattern

**Description:** Detects regular connection intervals to external destinations using inter-arrival time analysis. Calculates the standard deviation of time gaps between consecutive connections to the same destination host and port. Low jitter indicates automated callbacks rather than human browsing behavior.

**MITRE:** T1071.001, T1573 — Encrypted Channel, T1090 — Proxy

**Key architectural lessons:**

Eva flagged that `stdev(_time)` measures spread of raw timestamps, not consistency of intervals — a perfect 60-second beacon has high timestamp spread but near-zero interval spread. Fixed by using `streamstats window=1 current=false last(epoch) as prev_epoch` to capture the previous event's timestamp, then computing `interval = epoch - prev_epoch`.

Eva also flagged that beacon grouping should include destination port — the same host may have independent connection streams on different ports that should not be mixed.

Zeek JSON field extraction inconsistency required `rex field=_raw` for all IP matching.

```spl
index=main sourcetype=zeek_conn earliest=-6h
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_h\":\"(?P<resp_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_p\":(?P<resp_port>\d+)"
| rex field=_raw "\"orig_bytes\":(?P<orig_bytes_val>\d+)"
| where proto="tcp"
| eval epoch=_time
| sort orig_ip resp_ip resp_port epoch
| streamstats window=1 current=false
    last(epoch) as prev_epoch
    by orig_ip resp_ip resp_port
| eval interval=epoch - prev_epoch
| where isnotnull(interval) AND interval > 0
| stats
    count as conn_count
    avg(interval) as avg_interval
    stdev(interval) as interval_jitter
    avg(orig_bytes_val) as avg_bytes_sent
    by orig_ip resp_ip resp_port
| where conn_count >= 5
| eval interval_jitter=if(isnull(interval_jitter),0,interval_jitter)
| eval beacon_score=case(
    interval_jitter < 5, 1.0,
    interval_jitter < 30, 0.90,
    interval_jitter < 60, 0.80,
    interval_jitter < 120, 0.70,
    true(), 0.0
)
| where beacon_score >= 0.70
| eval avg_interval_min=round(avg_interval/60,2)
| eval interval_jitter=round(interval_jitter,2)
| eval evidence_weight=case(
    beacon_score>=0.90 AND avg_bytes_sent>0, 0.95,
    beacon_score>=0.90, 0.85,
    beacon_score>=0.80, 0.80,
    true(), 0.70
)
| eval detection="C2 Beacon Pattern Detected"
| eval severity=case(
    evidence_weight>=0.90,"CRITICAL",
    evidence_weight>=0.75,"HIGH",
    true(),"MEDIUM"
)
| table detection severity evidence_weight orig_ip resp_ip resp_port beacon_score conn_count avg_interval_min interval_jitter
| sort -beacon_score
```

<img width="1260" height="263" alt="Screenshot 2026-07-08 at 6 35 51 PM" src="https://github.com/user-attachments/assets/7ffccfdb-b111-4f52-9963-3055a57af481" />


**Result:** MEDIUM at 0.70. Real device on home network making ~52-second interval connections to external IP on port 443 with 117 seconds of jitter — likely Microsoft Teams or Outlook heartbeat. Correct classification: low confidence beacon that warrants monitoring but not immediate response.

**Alert Settings:**
- Title: `C2 Beacon Pattern Detected`
- Alert type: Scheduled — `*/30 * * * *`
- Time Range: Last 6 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 1800 seconds
- Severity: High

---

### Detection 4 — Combined Cross-Domain Exfiltration Score

**Description:** BLIP-AI's first cross-domain detection. Correlates Domain 1 auditd network tool execution signals with Domain 2 Zeek external connection records in the same 10-minute window. Both signals required — neither alone triggers the alert. Upload ratio asymmetry and byte volume provide confidence scaling.

**MITRE:** T1041 — Exfiltration Over C2 Channel, T1048 — Exfiltration Over Alternative Protocol, T1071.001

**Why this is the most important detection in Domain 2:**

Domain 1 could only confirm that curl or wget ran on the host. Detection 4 adds the network layer — Rocky can now confirm whether data actually left the network, how much, and characterize the upload pattern. This transforms BLIP-AI from a host-only investigator into a host-plus-network investigator.

**Key architectural lessons from Eva:**

Eva identified three critical issues in sequence. First — the correlation key mismatch: auditd `host` field is `splunk-server` while Zeek `orig_ip` is `192.168.1.234` — they never land in the same stats bucket. Fixed by normalizing both to `splunk-server` via explicit case evaluation. Second — minimum byte threshold required before CRITICAL scoring to prevent small beacon traffic from masquerading as exfiltration (`large_upload=if(orig_bytes_val>10485760,1,0)`). Third — auditd `success` field uses no quotes (`success=yes`) not `success="yes"` — this silently dropped all auditd signal matches and required a debugging session to identify.

```spl
index=main (sourcetype=linux_audit OR sourcetype=zeek_conn)
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"orig_bytes\":(?P<orig_bytes_val>\d+)"
| rex field=_raw "\"resp_bytes\":(?P<resp_bytes_val>\d+)"
| eval endpoint=case(
    sourcetype="linux_audit", "splunk-server",
    sourcetype="zeek_conn" AND match(orig_ip,"^10\.10\.10\."), "splunk-server",
    sourcetype="zeek_conn" AND match(orig_ip,"^192\.168\.1\.234"), "splunk-server",
    true(), null()
)
| eval signal=case(
    sourcetype="linux_audit"
        AND match(_raw,"key=\"proc_exec\"")
        AND match(_raw,"comm=\"curl\"")
        AND match(_raw,"success=yes"),
    "host_network_tool_exec",
    sourcetype="linux_audit"
        AND match(_raw,"key=\"proc_exec\"")
        AND match(_raw,"comm=\"wget\"")
        AND match(_raw,"success=yes"),
    "host_network_tool_exec",
    sourcetype="zeek_conn"
        AND match(orig_ip,"^(10\.10\.10\.|192\.168\.1\.234)")
        AND proto="tcp"
        AND match(_raw,"\"local_resp\":false"),
    "network_external_connection",
    true(), null()
)
| where isnotnull(signal) AND isnotnull(endpoint)
| eval upload_ratio=if(
    signal="network_external_connection"
        AND orig_bytes_val>0
        AND resp_bytes_val>0,
    round(orig_bytes_val/(resp_bytes_val+1)*100,1), null()
)
| eval large_upload=if(orig_bytes_val>10485760,1,0)
| eval exfil_indicator=if(upload_ratio>200 AND large_upload=1,1,0)
| bin _time span=10m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    max(upload_ratio) as max_upload_ratio
    max(exfil_indicator) as exfil_indicator
    max(orig_bytes_val) as max_bytes_sent
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| eval combined_confidence=case(
    exfil_indicator=1, 0.97,
    max_upload_ratio>100 AND max_bytes_sent>1048576, 0.90,
    true(), 0.82
)
| where combined_confidence >= 0.75
| eval detection="Combined Cross-Domain Exfiltration Score"
| eval severity=case(
    combined_confidence>=0.95,"CRITICAL",
    combined_confidence>=0.85,"HIGH",
    true(),"MEDIUM"
)
| eval description="Network tool execution on host AND outbound external connection in same 10-minute window. Upload ratio and byte volume indicate data exfiltration."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence endpoint signal_count signals_detected max_upload_ratio exfil_indicator max_bytes_sent first_seen last_seen description
```

<img width="1260" height="317" alt="Screenshot 2026-07-08 at 7 30 39 PM" src="https://github.com/user-attachments/assets/1cea9098-4dab-470f-ac8b-71f4adda41db" />


**Result:** MEDIUM at 0.82 across 7 time windows — both `host_network_tool_exec` and `network_external_connection` confirmed simultaneously on `splunk-server`.

**Alert Settings:**
- Title: `Combined Cross-Domain Exfiltration Score`
- Alert type: Scheduled — `*/10 * * * *`
- Time Range: Last 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

## Phase 5 — Validation Summary

| Detection | Data Source | Attack Run | Result | Eva Cycles | Status |
|---|---|---|---|---|---|
| 1 — Long Duration | zeek_conn | Organic (Tailscale) | 0.85 HIGH | 2 | ✅ Saved |
| 2 — DNS Anomaly | zeek_dns | N/A — sensor limitation | N/A | 1 | ⚠️ Documented |
| 3 — C2 Beacon | zeek_conn | Beacon simulation | 0.70 MEDIUM | 3 | ✅ Saved |
| 4 — Cross-Domain | linux_audit + zeek_conn | curl/wget to example.com | 0.82 MEDIUM | 4 | ✅ Saved |

---

## Known Limitations

| Limitation | Impact | Resolution Path |
|---|---|---|
| Zeek on ens19 cannot see unicast DNS | Detection 2 not exercisable in lab | Deploy Zeek on OPNsense or network TAP |
| Zeek JSON field auto-parse inconsistent | Must use rex extraction for IP matching | Configure props.conf field transforms |
| local_orig/local_resp don't recognize server IPv6 | Long duration filter required workaround | Add networks to /opt/zeek/etc/networks.cfg |
| download_tool auditd key broken on kernel 6.8.0-124 | Detection 4 uses proc_exec with comm matching | Known kernel bug — proc_exec workaround documented |
| Beacon detection requires 5+ connections | Short-lived sessions not detected | Lower threshold in V2 with additional validation |
| Cross-domain endpoint normalization is hardcoded | splunk-server hostname brittle | V2: use dynamic hostname lookup |

---

## Technical Discoveries

**auditd success field format:** The `success` field in auditd SYSCALL records uses no quotes — `success=yes` not `success="yes"`. SPL match strings must use `match(_raw,"success=yes")` not `match(_raw,"success=\"yes\"")`. This silently dropped all auditd signal matches in Detection 4 until identified through systematic debugging.

**streamstats current=false for interval calculation:** `stdev(_time)` measures spread of raw timestamps, not consistency of inter-arrival intervals. Correct beacon detection requires `streamstats window=1 current=false last(epoch) as prev_epoch` to get the previous event timestamp, then `eval interval=epoch-prev_epoch` to compute true inter-arrival time.

**Zeek local network detection:** Zeek does not automatically recognize IPv6 addresses as local even when they belong to the monitored host. The `local_orig` and `local_resp` fields may be `false` for the server's own IPv6 connections. Explicit IP range matching via `rex` is more reliable than relying on Zeek's local classification.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Application Layer Protocol: Web | T1071.001 | Detection 1, 3, 4 |
| Application Layer Protocol: DNS | T1071.004 | Detection 2 |
| Exfiltration Over C2 Channel | T1041 | Detection 4 |
| Exfiltration Over Alternative Protocol | T1048 | Detection 2, 4 |
| Encrypted Channel | T1573 | Detection 1, 3 |

---
