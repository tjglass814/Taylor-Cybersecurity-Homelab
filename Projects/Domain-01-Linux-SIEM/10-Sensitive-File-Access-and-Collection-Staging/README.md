# Project 10 — Sensitive File Access and Collection Staging

## Overview

This project builds behavioral detections around the collection phase of an attack — the period between an attacker establishing access and actually exfiltrating data. Before data leaves an environment it must be collected: sensitive files accessed, staged in writable directories, and often compressed into archives. Project 10 detects all three behaviors.

Three detections were built: an archive creation detector that validates staging directory destinations via PROCTITLE decode, a sensitive file staging detector using PATH record joins to confirm destinations, and a combined behavioral score that enforces evidence-validated qualifying conditions from both detections before correlating.

A key architectural lesson this project: mixing PROCTITLE and PATH evidence into a single enrichment field creates ambiguous classifications. Both evidence sources must be kept separate through the join and classified independently. The combined score took three Eva review cycles to get right — each iteration identified a subtle way the correlation could produce false confidence.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic (upgraded this project) |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 72 total (3 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 3 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | Pending developer license |
| MITRE Techniques Covered | 3 |
| Confidence Range | 0.85 – 1.0 |

## Why This Project Matters

The collection phase is often the last opportunity to detect an attacker before data leaves the environment. Network-based exfiltration detection is hard — HTTPS traffic to cloud storage looks like normal web browsing. But the collection behavior that precedes exfiltration is highly detectable at the host level: `tar czf /tmp/loot.tar.gz /etc/passwd /etc/shadow` is unambiguous. A system administrator has no legitimate reason to compress credential files into /tmp.

The detection challenge is precision. `/tmp` gets thousands of writes per hour from legitimate processes. `tar` runs constantly in package management and backup jobs. The signal is the combination — archive tools targeting staging directories, combined with sensitive file copying in the same session.

---

## Phase 1 — Infrastructure

### New auditd Rules

Three rules added — staging directory write monitoring:

```bash
# Watch for file writes to world-writable staging directories
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F dir=/tmp -F perm=w -k staging_write
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F dir=/dev/shm -F perm=w -k staging_write
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F dir=/var/tmp -F perm=w -k staging_write
```

**Why open/openat and not execve:** The `-F exe=` filter on execve rules remains broken on kernel 6.8.0-124 (confirmed via test). The open/openat syscall filter works correctly — validated by writing a test file to /tmp and confirming `staging_write` fired. Archive tool detection (tar, gzip) uses the existing `proc_exec` key with SPL-level comm filtering.

**Existing keys leveraged:**
- `proc_exec` — catches tar, gzip, zip execution
- `shadow_access` — /etc/shadow reads
- `homedir_read` — /home directory access

**Rule persistence:**
```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 72
```

---

## Phase 2 — Attack Simulation

Simulates the complete collection staging sequence an attacker executes before exfiltration:

```bash
# Access sensitive credential files
sudo cat /etc/shadow
find / -name "*.pem" 2>/dev/null | head -5

# Create archive of sensitive files in staging directory
sudo tar czf /tmp/loot.tar.gz /etc/passwd /etc/shadow 2>/dev/null

# Stage individual sensitive files
cp /etc/passwd /tmp/passwd_copy
echo "192.168.1.100 db-server" > /tmp/network_map.txt

# Archive home directory to memory-only staging
sudo tar czf /dev/shm/backup.tar.gz /home/labadmin/ 2>/dev/null

# Cleanup
sudo rm -f /tmp/loot.tar.gz /tmp/passwd_copy /tmp/network_map.txt
sudo rm -f /dev/shm/backup.tar.gz
```

<img width="1297" height="865" alt="Screenshot 2026-06-15 at 5 07 15 PM" src="https://github.com/user-attachments/assets/5197922c-f0d3-41bd-b792-a7f7149a89ea" />


**What auditd recorded:**
- `proc_exec` — tar and gzip executions
- `staging_write` — bash writing to /tmp, cp copying to /tmp
- `shadow_access` — /etc/shadow read

---

## Phase 3 — Detections

### Detection 1 — Archive Creation in Staging Directory

**Description:** Detects archive tool execution (tar, zip, gzip, 7z, bzip2) from interactive sessions where PROCTITLE confirms the destination is a world-writable staging directory. Requires PROCTITLE evidence — if PROCTITLE is unavailable the event is excluded rather than silently scoring at lower confidence.

**MITRE:** T1074.001 — Data Staged: Local Data Staging

**Evidence Weight:** 0.90 CRITICAL

**Key design decision — PROCTITLE required:** The detection explicitly filters `| where has_proctitle=1`. Without this, missing PROCTITLE records would cause the detection to silently degrade into a generic "archive tool executed" rule with no staging directory validation. Eva flagged this as a critical fix — silent degradation is worse than no detection because it creates false confidence.

```spl
index=main sourcetype=linux_audit earliest=-60m
"proc_exec" "type=SYSCALL"
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
| where match(comm,"^(tar|zip|gzip|7z|bzip2)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PROCTITLE"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
    | table event_id decoded
]
| eval has_proctitle=if(isnotnull(decoded),1,0)
| where has_proctitle=1
| eval staging_target=if(
    match(decoded,"(/tmp/|/dev/shm/|/var/tmp/)"),
    1, 0
)
| eval evidence_weight=case(
    staging_target=1 AND match(comm,"^(tar|zip)$"), 0.90,
    staging_target=1, 0.80,
    match(comm,"^(tar|zip)$"), 0.65,
    true(), 0.55
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    max(staging_target) as staging_target
    max(has_proctitle) as has_proctitle
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Archive Creation in Staging Directory"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used staging_target has_proctitle commands_run first_seen last_seen
```

<img width="1255" height="371" alt="Screenshot 2026-06-15 at 5 24 27 PM" src="https://github.com/user-attachments/assets/ce84c360-4a8b-45e9-9674-a64cf2782914" />


**Alert Settings:**
- Title: `Archive Creation in Staging Directory`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Sensitive File Staging Detected

**Description:** Detects file copy and move operations writing to world-writable staging directories using the `staging_write` auditd key. Joins PATH records via event_id to extract and validate the actual destination filepath. Scores higher for credential and key file patterns in the destination filename.

**MITRE:** T1074.001 — Data Staged: Local Data Staging, T1005 — Data from Local System

**Evidence Weight:** 0.85 CRITICAL

**Why PATH records over PROCTITLE:** For file operation syscalls, the destination path is more reliably captured in PATH records than PROCTITLE. PATH records contain the actual filesystem paths being operated on — nametype=CREATE or NORMAL confirms a file was written to the staging directory.

```spl
index=main sourcetype=linux_audit earliest=-60m
"staging_write" "type=SYSCALL"
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
| where match(comm,"^(cp|mv|tee|dd|install|rsync)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
    | where nametype="CREATE" OR nametype="NORMAL"
    | table event_id filepath nametype
]
| where isnotnull(filepath)
| eval sensitive_file=if(
    match(filepath,"(?i)(passwd|shadow|key|pem|pfx|env|config|cred|secret|token|db|sql|backup|dump)"),
    1, 0
)
| eval evidence_weight=case(
    sensitive_file=1 AND match(filepath,"^/dev/shm/"), 0.90,
    sensitive_file=1, 0.85,
    match(filepath,"^/dev/shm/"), 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_staged
    max(sensitive_file) as sensitive_file
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Sensitive File Staging Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used sensitive_file files_staged first_seen last_seen
```

<img width="1255" height="371" alt="Screenshot 2026-06-15 at 5 27 57 PM" src="https://github.com/user-attachments/assets/3accd0d0-18fe-4f8d-a6a7-f3d2fe049f32" />

**Alert Settings:**
- Title: `Sensitive File Staging Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Collection and Staging Behavioral Score

**Description:** Correlates confirmed archive creation targeting staging directories and confirmed sensitive file staging in the same session. Both signals require full evidence validation — PROCTITLE for archive destination, PATH records for staging filepath. Evidence sources are kept separate through the join to prevent cross-contamination. Deduplication via `stats by event_id` prevents duplicate row inflation.

**MITRE:** T1074.001, T1005, T1560.001 — Archive Collected Data: Archive via Utility

**Confidence:** 1.0 CRITICAL

**Architectural notes from Eva review:**
1. The combined score must re-implement qualifying conditions from individual detections — not just check tool execution
2. PROCTITLE and PATH evidence must remain separate fields — coalescing into one field creates ambiguous classification
3. Subsearch must deduplicate by event_id to prevent row inflation from multiple matching records

```spl
index=main sourcetype=linux_audit earliest=-60m
("proc_exec" OR "staging_write") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where (key="proc_exec" AND match(comm,"^(tar|zip|gzip|7z|bzip2)$"))
    OR (key="staging_write" AND match(comm,"^(cp|mv|tee|dd|install|rsync)$"))
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now
    ("type=PROCTITLE" OR "type=PATH")
    | rex field=_raw "type=(?P<record_type>\w+)"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
    | eval staging_path=if(
        record_type="PATH"
            AND match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
            AND (nametype="CREATE" OR nametype="NORMAL"),
        filepath, null()
    )
    | eval staging_cmd=if(
        record_type="PROCTITLE"
            AND match(decoded,"(/tmp/|/dev/shm/|/var/tmp/)"),
        decoded, null()
    )
    | where isnotnull(staging_path) OR isnotnull(staging_cmd)
    | stats
        values(staging_path) as staging_path
        values(staging_cmd) as staging_cmd
        by event_id
    | table event_id staging_path staging_cmd
]
| eval technique=case(
    key="proc_exec"
        AND match(comm,"^(tar|zip|gzip|7z|bzip2)$")
        AND isnotnull(staging_cmd),
        "confirmed_archive_staging",
    key="staging_write"
        AND match(comm,"^(cp|mv|tee|dd|install|rsync)$")
        AND isnotnull(staging_path),
        "confirmed_file_staging",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(staging_cmd) as archive_commands
    values(staging_path) as staged_files
    sum(eval(case(
        technique="confirmed_archive_staging", 0.90,
        technique="confirmed_file_staging", 0.85,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval detection="Combined Collection and Staging Behavioral Score"
| eval description="Archive creation targeting staging directory AND sensitive file staging both confirmed in same session. High-confidence pre-exfiltration collection operation."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected archive_commands staged_files first_seen last_seen description
```

<img width="1255" height="452" alt="Screenshot 2026-06-15 at 5 31 29 PM" src="https://github.com/user-attachments/assets/d8230128-da48-41fe-a14f-8585a0c54b8f" />


**Alert Settings:**
- Title: `Combined Collection and Staging Behavioral Score`
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
| 1 — Archive Creation in Staging Directory | ✅ | ✅ proc_exec tar + gzip | ✅ 1 row, 0.90 CRITICAL | ✅ (2 review cycles) |
| 2 — Sensitive File Staging | ✅ | ✅ staging_write cp + bash | ✅ 1 row, 0.85 CRITICAL | ✅ |
| 3 — Combined Collection and Staging Score | ✅ | ✅ both techniques confirmed | ✅ 1 row, 1.0 CRITICAL | ✅ (3 review cycles) |

**Note:** Alerts pending save — Splunk developer license requested during this project. Alerts will be saved upon license receipt.

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| `-F exe=` broken on kernel 6.8.0-124 | Cannot use dedicated archive tool auditd keys | Monitor kernel updates for fix |
| staging_write fires on cron writes to /tmp | Noise from system processes — filtered via auid!=4294967295 | Already mitigated |
| PROCTITLE not always present | Detection 1 excludes events without PROCTITLE rather than degrading silently | Accept as architectural constraint — document gap |
| join 50k row limit | May miss events on high-volume systems | Replace with transaction event_id in V2 |
| No content inspection | Cannot see what files are inside archives | FIM + archive content inspection in V2 |
| /tmp cleanup before detection | Fast attacker cleanup may happen before 5-minute cron fires | Reduce cron to */1 for high-value environments |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Data Staged: Local Data Staging | T1074.001 | Detection 1, 2, 3 |
| Data from Local System | T1005 | Detection 2, 3 |
| Archive Collected Data: Archive via Utility | T1560.001 | Detection 1, 3 |

---
