# Project 13 — Resource and Stability Anomaly Detection

## Overview

This project builds behavioral detections around resource consumption anomalies — the side effects of malicious workloads that persist even when attacker tools are hidden. Where Projects 6 through 12 detected specific tools, files, and syscalls, Project 13 detects behavioral fingerprints: process creation storms, disk write volume spikes, and multi-signal resource consumption patterns that indicate active malicious workloads.

Three detections were built: a process creation storm detector using clone/fork syscall monitoring with 1-minute binning, a disk write storm detector measuring write volume to staging directories, and a combined resource anomaly score correlating five technique categories across Projects 10, 11, and 13.

A key design lesson this project: resource anomaly thresholds must be calibrated conservatively — build systems, package managers, and CI/CD pipelines can legitimately exceed naive thresholds. All detections are labeled as anomaly indicators rather than confirmed malicious activity, following Eva's guidance on defensible SOC language.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 83 total (2 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 2 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 4 |
| Confidence Range | 0.90 – 1.0 |

## Why This Project Matters

Sophisticated attackers hide their tools but cannot hide their resource consumption. A cryptominer running as a trojanized system binary still pegs a CPU core. A password cracker spawning 50 threads still creates 50 processes per minute. A data staging operation writing 10GB to /tmp still generates hundreds of disk write events. Resource anomaly detection is the complement to signature-based detection — it catches what tool-based detections miss.

The combined score in Detection 3 deliberately spans Projects 10, 11, and 13 — when disk write storms and process storms fire alongside archive creation and network transfer tools, the behavioral chain reconstructs a complete attack narrative from resource consumption patterns alone, without relying on any specific tool name or file path.

---

## Phase 1 — Infrastructure

### New auditd Rules

Two rules added — monitoring clone and fork syscalls from interactive sessions:

```bash
sudo auditctl -a always,exit -F arch=b64 -S clone -F auid!=4294967295 -k process_creation
sudo auditctl -a always,exit -F arch=b64 -S fork -F auid!=4294967295 -k process_creation
```

**Why clone and fork:** Every process creation on Linux goes through either `clone` or `fork`. By monitoring these syscalls from non-daemon sessions (auid!=4294967295 in the rule itself) we capture process creation storms from interactive attacker sessions while excluding system-level daemon activity at the kernel level before it even reaches Splunk.

**Rule persistence:**
```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 83
```

---

## Phase 2 — Attack Simulation

Simulates four resource anomaly attack patterns:

```bash
# Attack 1 — CPU exhaustion
dd if=/dev/zero bs=1M count=512 | gzip > /dev/null &
sleep 5
kill %1 2>/dev/null || true

# Attack 2 — Rapid process creation (fork storm)
for i in $(seq 1 50); do sleep 0.1 & done
wait

# Attack 3 — Disk write storm to staging directory
for i in $(seq 1 20); do dd if=/dev/urandom bs=1M count=1 of=/tmp/junk_$i 2>/dev/null; done
rm -f /tmp/junk_*

# Attack 4 — Log flooding via rapid execve calls
for i in $(seq 1 30); do ls /tmp > /dev/null; done
```

<img width="1228" height="829" alt="Screenshot 2026-06-22 at 5 29 12 PM" src="https://github.com/user-attachments/assets/3dbad93c-2167-4eb7-ae94-7462d91718c2" />


**What auditd recorded:**
- `process_creation` — bash cloning 50+ child processes ✅
- `staging_write` — dd writing 20 files to /tmp ✅
- `proc_exec` — gzip, ls, and other tool executions ✅

**Noise identified and filtered:**
- `splunkd` — constant thread creation via clone, filtered by `tty!="(none)"`
- `postgres` (Splunk internal) — writes to /dev/shm, filtered by `comm!="postgres"`

---

## Phase 3 — Detections

### Detection 1 — Process Creation Storm Detected

**Description:** Detects unusually high process creation volume from interactive sessions using clone/fork syscall monitoring. Bins into 1-minute windows and flags sessions exceeding 20 process creations per minute. Severity tied directly to peak_per_minute — 100+ CRITICAL, 50+ HIGH. Parent PID context included for analyst triage.

**MITRE:** T1059 — Command and Scripting Interpreter, T1499 — Endpoint Denial of Service

**Evidence Weight:** 0.90 CRITICAL

**Design notes:**
- `tty!="(none)"` eliminates splunkd thread creation noise entirely
- Severity derived directly from `peak_per_minute` not indirectly from evidence_weight — cleaner analyst review
- Process volume alone is a moderate-confidence signal — correlated with other techniques in Detection 3 for higher confidence
- Parent PID exposed in output to help analysts distinguish build systems from attacker shells

```spl
index=main sourcetype=linux_audit earliest=-60m
"process_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "ppid=(?P<ppid>\d+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| bin _time span=1m
| stats
    count as process_count
    dc(comm) as unique_processes
    values(comm) as process_names
    values(ppid) as parent_pids
    by auid ses host _time
| where process_count >= 20
| eval evidence_weight=case(
    process_count>=100, 0.90,
    process_count>=50, 0.80,
    process_count>=20, 0.70,
    true(), 0.60
)
| stats
    sum(process_count) as total_processes
    max(process_count) as peak_per_minute
    max(unique_processes) as peak_unique_processes
    max(evidence_weight) as evidence_weight
    values(process_names) as process_names
    values(parent_pids) as parent_pids
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Process Creation Storm Detected"
| eval severity=case(
    peak_per_minute>=100, "CRITICAL",
    peak_per_minute>=50, "HIGH",
    true(), "MEDIUM"
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host total_processes peak_per_minute peak_unique_processes process_names parent_pids first_seen last_seen
```

<img width="1257" height="306" alt="Screenshot 2026-06-22 at 5 39 58 PM" src="https://github.com/user-attachments/assets/a4a1d676-bbe9-47ce-80ca-eda08d7e5d7a" />


**Alert Settings:**
- Title: `Process Creation Storm Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Disk Write Storm to Staging Directory

**Description:** Detects anomalous write volume to world-writable staging directories from interactive sessions. Bins into 1-minute windows and flags sessions with 5 or more write events per minute. Severity tied directly to peak_per_minute. PATH records confirm staging directory destinations. Splunk's internal postgres filtered to eliminate constant /dev/shm noise.

**MITRE:** T1074.001 — Data Staged: Local Data Staging, T1485 — Data Destruction

**Evidence Weight:** 0.90 CRITICAL

**Design notes:**
- Severity derived from `peak_per_minute` directly — more transparent than routing through evidence_weight
- `comm!="postgres"` removes Splunk's internal PostgreSQL writes to /dev/shm
- PATH join confirms actual staging directory destinations — not just that the watch rule fired
- Write volume is a moderate-confidence signal on its own — combined with process storm and archive activity in Detection 3 for higher confidence

```spl
index=main sourcetype=linux_audit earliest=-60m
"staging_write" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="postgres"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| bin _time span=1m
| stats
    count as write_count
    dc(filepath) as unique_files
    values(comm) as tools_used
    values(filepath) as files_written
    by auid ses host _time
| where write_count >= 5
| eval evidence_weight=case(
    write_count>=20, 0.90,
    write_count>=10, 0.80,
    write_count>=5, 0.70,
    true(), 0.60
)
| stats
    sum(write_count) as total_writes
    max(write_count) as peak_per_minute
    max(unique_files) as peak_unique_files
    max(evidence_weight) as evidence_weight
    values(tools_used) as tools_used
    values(files_written) as files_written
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Disk Write Storm to Staging Directory"
| eval severity=case(
    peak_per_minute>=20, "CRITICAL",
    peak_per_minute>=10, "HIGH",
    true(), "MEDIUM"
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host total_writes peak_per_minute peak_unique_files tools_used files_written first_seen last_seen
```

<img width="1257" height="609" alt="Screenshot 2026-06-22 at 5 50 49 PM" src="https://github.com/user-attachments/assets/29d2a27a-c3aa-4f3a-95f8-84608a6dfbc3" />


**Alert Settings:**
- Title: `Disk Write Storm to Staging Directory`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Resource and Stability Anomaly Score

**Description:** Correlates five resource and behavioral signals in the same session — process creation storms, disk write storms, archive tool activity, network transfer tools, and encoding tools. Individual signals can be legitimate. Multiple signals together in the same session indicate active malicious workload. Normalized weighted scoring with 0.75 minimum confidence gate. Cross-project behavioral chain spanning Projects 10, 11, and 13.

**MITRE:** T1059, T1074.001, T1560.001, T1041, T1027

**Confidence:** 1.0 CRITICAL

```spl
index=main sourcetype=linux_audit earliest=-60m
("process_creation" OR "staging_write" OR "proc_exec" OR "download_tool" OR "encoding_tool") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="postgres"
| eval technique=case(
    key="process_creation" AND match(comm,"^(bash|sh|python|perl|php|nc)$"), "process_storm",
    key="staging_write" AND match(comm,"^(dd|cp|mv|tee|rsync)$"), "disk_storm",
    key="proc_exec" AND match(comm,"^(tar|gzip|zip)$"), "archive_activity",
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    key="encoding_tool" AND comm="base64", "encoding",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="process_storm", 0.75,
    technique="disk_storm", 0.80,
    technique="archive_activity", 0.75,
    technique="network_transfer", 0.80,
    technique="encoding", 0.70,
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
| eval detection="Combined Resource and Stability Anomaly Score"
| eval description="Multiple resource anomaly signals detected in same session. Process storms, disk write storms, and exfiltration-phase tools firing together indicate active malicious workload."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen description
```


<img width="1257" height="424" alt="Screenshot 2026-06-22 at 5 51 22 PM" src="https://github.com/user-attachments/assets/3b8d6436-65e1-4ad0-81da-3238fc7dd366" />

**Alert Settings:**
- Title: `Combined Resource and Stability Anomaly Score`
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
| 1 — Process Creation Storm | ✅ | ✅ process_creation bash 114 events | ✅ 1 row, 0.90 CRITICAL | ✅ (2 review cycles) |
| 2 — Disk Write Storm | ✅ | ✅ staging_write dd 20 events | ✅ 1 row, 0.90 CRITICAL | ✅ (2 review cycles) |
| 3 — Combined Resource Anomaly | ✅ | ✅ 3 technique categories | ✅ 1 row, 1.0 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| Process storm threshold may catch build systems | make -j16, npm install can exceed 20 processes/minute | Tune threshold per environment baseline |
| Disk write storm threshold may catch package extraction | apt, pip, npm write heavily to /tmp | Add comm exclusion list after baseline tuning |
| No CPU utilization metric | auditd doesn't expose CPU usage — storm is inferred from process count | Integrate /proc polling or eBPF CPU monitoring in V2 |
| Log flooding not explicitly detected | Rapid execve volume not separately alerted | Add event rate anomaly detection in V2 |
| process_creation fires on splunkd heavily | Filtered by tty!="(none)" — adequate for homelab | Accept as architectural constraint |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Detection 1, 3 |
| Data Staged: Local Data Staging | T1074.001 | Detection 2, 3 |
| Archive Collected Data | T1560.001 | Detection 3 |
| Exfiltration Over C2 Channel | T1041 | Detection 3 |
| Obfuscated Files or Information | T1027 | Detection 3 |

---
