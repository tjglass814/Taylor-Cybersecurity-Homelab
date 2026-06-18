# Project 12 — Service and Binary Modification

## Overview

This project builds behavioral detections around system integrity attacks — the phase where an attacker moves from using the system to becoming part of it. Where previous projects detected active attacker behavior during sessions, Project 12 detects permanent modifications to system binaries, shared libraries, and environment configuration that persist across reboots and survive partial remediation.

Three detections were built: a system binary modification detector using PATH record joins to confirm affected files, a shared library and environment hijacking detector with PROCTITLE-validated LD_PRELOAD classification, and a combined behavioral score correlating all four system integrity attack techniques in the same session.

Key architectural lessons this project: multivalue field handling requires `mvjoin()` rather than `mvfind()` for reliable pattern matching in Splunk, and `nametype!="PARENT"` is more comprehensive than `nametype="CREATE" OR nametype="NORMAL"` for catching the full range of file modification events.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 81 total (9 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 9 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 4 |
| Confidence Range | 0.90 – 1.0 |

## Why This Project Matters

Most attack detection focuses on behavior during an active session. System binary and library modification is different — the attacker is no longer just visiting the system, they are modifying it permanently. A trojanized `/usr/bin/ps` that hides attacker processes defeats every process-based detection. A malicious shared library loaded via `LD_PRELOAD` runs inside every subsequent process on the system. These modifications are designed to survive incident response.

The detection challenge is that system binary directories are also written to constantly by legitimate package management. The key differentiator is interactive session context — `apt` and `dpkg` run as root with `auid=4294967295` which is filtered out. An attacker writing to `/usr/bin` from an interactive SSH session with `auid=1000` is the signal.

---

## Phase 1 — Infrastructure

### New auditd Rules

Nine rules added — watching critical binary directories, library paths, and environment files:

```bash
# System binary directories
sudo auditctl -w /usr/bin -p wa -k binary_modification
sudo auditctl -w /usr/sbin -p wa -k binary_modification
sudo auditctl -w /bin -p wa -k binary_modification
sudo auditctl -w /sbin -p wa -k binary_modification

# Shared library directories and config
sudo auditctl -w /usr/lib -p wa -k library_modification
sudo auditctl -w /usr/lib64 -p wa -k library_modification
sudo auditctl -w /etc/ld.so.conf -p wa -k library_modification
sudo auditctl -w /etc/ld.so.conf.d -p wa -k library_modification

# Environment file
sudo auditctl -w /etc/environment -p wa -k env_modification
```

**Why watch rules over execve rules:** `-F exe=` execve filter remains broken on kernel 6.8.0-124. Watch rules using `-w` and `-p wa` fire on any write or attribute change to the watched path regardless of which binary performs the operation — no exe filter needed. This is actually more comprehensive since any tool (cp, tee, dd, install) that writes to these paths will fire the rule.

**Rule persistence:**
```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 81
```

---

## Phase 2 — Attack Simulation

Simulates coordinated system integrity attacks across all three modification categories:

```bash
# Attack 1 — System binary replacement
sudo cp /usr/bin/ls /usr/bin/ls.bak
sudo cp /usr/bin/ls /usr/bin/ls
sudo rm /usr/bin/ls.bak

# Attack 2 — Shared library planting
sudo cp /usr/lib/x86_64-linux-gnu/libz.so.1 /usr/lib/x86_64-linux-gnu/libevil.so
sudo rm /usr/lib/x86_64-linux-gnu/libevil.so

# Attack 3 — Library path manipulation
echo "/tmp/evil" | sudo tee -a /etc/ld.so.conf.d/evil.conf
sudo rm /etc/ld.so.conf.d/evil.conf

# Attack 4 — LD_PRELOAD environment injection
echo "LD_PRELOAD=/tmp/evil.so" | sudo tee -a /etc/environment
sudo sed -i '/LD_PRELOAD/d' /etc/environment

# Attack 5 — Fake binary creation
sudo touch /usr/bin/fake_binary
sudo rm /usr/bin/fake_binary
```

<img width="1294" height="831" alt="Screenshot 2026-06-18 at 5 28 01 PM" src="https://github.com/user-attachments/assets/26e50d4c-3314-4877-a0db-698c1323301b" />


**What auditd recorded:**
- `binary_modification` — cp, rm, touch writing to /usr/bin ✅
- `library_modification` — cp, rm, tee writing to /usr/lib and /etc/ld.so.conf.d ✅
- `env_modification` — tee and sed modifying /etc/environment ✅

---

## Phase 3 — Detections

### Detection 1 — System Binary Modification Detected

**Description:** Detects writes, replacements, renames, and deletions of files in critical system binary directories from interactive sessions. Requires PATH record evidence confirming the affected file is in a binary directory. Uses comm-based action classification — portable across kernel versions and architectures.

**MITRE:** T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking, T1543 — Create or Modify System Process

**Evidence Weight:** 0.90 CRITICAL

**Why comm-based not syscall-based:** Earlier version used hardcoded syscall numbers (263=unlinkat, 82=rename). Eva flagged this as architecture-dependent. Replaced with comm-based classification — `rm` = deleted, `mv` = renamed, `cp`/`install` = replaced. Works correctly on any Linux architecture.

```spl
index=main sourcetype=linux_audit earliest=-60m
"binary_modification" "type=SYSCALL"
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
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^(/usr/bin/|/usr/sbin/|/bin/|/sbin/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval action_type=case(
    match(comm,"^(cp|install)$"), "binary_replaced",
    match(comm,"^(mv)$"), "binary_renamed",
    match(comm,"^(rm)$"), "binary_deleted",
    match(comm,"^(dd|tee)$"), "binary_written",
    match(comm,"^(touch)$"), "binary_touched",
    true(), "binary_modified"
)
| eval evidence_weight=case(
    match(comm,"^(cp|mv|install)$"), 0.90,
    match(comm,"^(dd|tee)$"), 0.85,
    match(comm,"^(rm)$"), 0.75,
    match(comm,"^(touch)$"), 0.65,
    true(), 0.70
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as binaries_affected
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="System Binary Modification Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used actions binaries_affected first_seen last_seen
```

<img width="1253" height="271" alt="Screenshot 2026-06-18 at 5 31 46 PM" src="https://github.com/user-attachments/assets/66b5885a-47b0-4ed2-9b3d-3a04c42f68bb" />


**Alert Settings:**
- Title: `System Binary Modification Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Shared Library and Environment Hijacking Detected

**Description:** Detects modifications to shared library directories, library configuration files, and /etc/environment from interactive sessions. PROCTITLE validates LD_PRELOAD= string presence before classifying as injection — prevents false classification of legitimate environment edits. PATH records confirm affected files.

**MITRE:** T1574.006 — Dynamic Linker Hijacking, T1574.007 — Path Interception by PATH Environment Variable

**Evidence Weight:** 0.90 CRITICAL

**Key design decisions:**
- LD_PRELOAD classification requires PROCTITLE confirmation of `ld_preload=` string — not just any env file write
- `.so` matching anchored to `\.so(\.[0-9]+)*$` — catches libssl.so, libssl.so.3, libcrypto.so.3
- PATH filter uses explicit branches: `/etc/ld.so.conf$` and `/etc/ld.so.conf.d/` — avoids regex ambiguity
- Coverage expanded to `/lib/` and `/lib64/` — common library locations missed by usr-only paths

```spl
index=main sourcetype=linux_audit earliest=-60m
("library_modification" OR "env_modification") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now
    ("type=PATH" OR "type=PROCTITLE")
    | rex field=_raw "type=(?P<record_type>\w+)"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
    | eval path_match=if(
        record_type="PATH"
            AND match(filepath,"^(/lib/|/lib64/|/usr/lib/|/usr/lib64/|/etc/ld\.so\.conf$|/etc/ld\.so\.conf\.d/|/etc/environment$)")
            AND nametype!="PARENT",
        filepath, null()
    )
    | eval preload_confirmed=if(
        record_type="PROCTITLE"
            AND match(decoded,"(?i)(ld_preload=|ld_library_path=)"),
        1, 0
    )
    | where isnotnull(path_match) OR preload_confirmed=1
    | stats
        values(path_match) as filepath
        max(preload_confirmed) as preload_confirmed
        by event_id
    | table event_id filepath preload_confirmed
]
| where isnotnull(filepath)
| eval hijack_type=case(
    key="env_modification" AND preload_confirmed=1, "ld_preload_env_injection",
    key="env_modification", "environment_modification",
    key="library_modification" AND match(filepath,"\.so(\.[0-9]+)*$"), "shared_library_planted",
    key="library_modification" AND match(filepath,"ld\.so\.conf(\.d/.*)?$"), "library_path_manipulation",
    true(), "library_modification"
)
| eval evidence_weight=case(
    hijack_type="ld_preload_env_injection", 0.95,
    hijack_type="shared_library_planted", 0.90,
    hijack_type="library_path_manipulation", 0.85,
    hijack_type="environment_modification", 0.80,
    true(), 0.70
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(hijack_type) as hijack_types
    max(preload_confirmed) as preload_confirmed
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Shared Library and Environment Hijacking Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used hijack_types preload_confirmed files_affected first_seen last_seen
```

<img width="1253" height="271" alt="Screenshot 2026-06-18 at 5 41 45 PM" src="https://github.com/user-attachments/assets/db87233c-7e07-4fe8-996d-9a15aac394f4" />


**Alert Settings:**
- Title: `Shared Library and Environment Hijacking Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Service and Binary Modification Score

**Description:** Correlates binary modification, shared library planting, library path manipulation, and environment modification signals in the same session. PATH evidence required for all techniques. Uses `mvjoin()` for safe multivalue filepath pattern matching. High-confidence indicator of coordinated persistence or system tampering activity.

**MITRE:** T1574.006, T1574.007, T1543, T1601 — Modify System Image

**Confidence:** 1.0 CRITICAL

**Architectural notes from Eva review:**
1. `mvfind()` returns index 0 for first match — `isnotnull(0)` works but behavior is inconsistent. Replaced with `mvjoin(filepath," ")` to collapse multivalue to string before pattern matching
2. `nametype!="PARENT"` catches CREATE, NORMAL, DELETE, RENAME — more comprehensive than explicit CREATE/NORMAL list
3. Description softened from "confirmed rootkit" to "high-confidence indicator" — more defensible during SOC tuning reviews

```spl
index=main sourcetype=linux_audit earliest=-60m
("binary_modification" OR "library_modification" OR "env_modification") "type=SYSCALL"
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
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^(/usr/bin/|/usr/sbin/|/bin/|/sbin/|/lib/|/lib64/|/usr/lib/|/usr/lib64/|/etc/ld\.so\.conf$|/etc/ld\.so\.conf\.d/|/etc/environment$)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval technique=case(
    key="binary_modification",
        "binary_modification",
    key="library_modification"
        AND match(mvjoin(filepath," "),"\.so(\.[0-9]+)*$"),
        "library_planted",
    key="library_modification"
        AND match(mvjoin(filepath," "),"ld\.so\.conf(\.d/.*)?$"),
        "library_path_manipulation",
    key="env_modification"
        AND match(mvjoin(filepath," "),"^/etc/environment$"),
        "environment_modification",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="binary_modification", 0.90,
    technique="library_planted", 0.90,
    technique="library_path_manipulation", 0.85,
    technique="environment_modification", 0.80,
    true(), 0.60
)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(comm) as tools_used
    values(filepath) as files_affected
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
| eval detection="Combined Service and Binary Modification Score"
| eval description="System binary modification and library or environment hijacking detected in same session. High-confidence indicator of coordinated persistence or system tampering activity."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used files_affected first_seen last_seen description
```

<img width="1253" height="271" alt="Screenshot 2026-06-18 at 5 48 15 PM" src="https://github.com/user-attachments/assets/14a0780b-ef73-4457-8bf2-bf38bc65e3b3" />


**Alert Settings:**
- Title: `Combined Service and Binary Modification Score`
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
| 1 — System Binary Modification | ✅ | ✅ binary_modification key | ✅ 1 row, 0.90 CRITICAL | ✅ (2 review cycles) |
| 2 — Shared Library and Environment Hijacking | ✅ | ✅ library_modification + env_modification | ✅ 1 row, 0.90 CRITICAL | ✅ (3 review cycles) |
| 3 — Combined Service and Binary Modification | ✅ | ✅ all 4 technique categories | ✅ 1 row, 1.0 CRITICAL | ✅ (4 review cycles) |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| `-F exe=` broken on kernel 6.8.0-124 | Cannot use dedicated binary tool auditd keys | Monitor kernel updates |
| Package manager writes filtered by auid | apt/dpkg run as auid=4294967295 — correctly excluded | Intended behavior |
| No binary content inspection | Cannot verify binary was actually replaced vs just touched | FIM with hash verification in V2 |
| /usr/local/bin not covered | Some environments install tools here | Add watch rule in V2 |
| join 50k row limit | May miss events on high-volume systems | Replace with transaction in V2 |
| LD_PRELOAD via direct process not covered | Attacker setting LD_PRELOAD in shell without writing to /etc/environment | proc_exec PROCTITLE monitoring for env= in V2 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Hijack Execution Flow: Dynamic Linker Hijacking | T1574.006 | Detection 1, 2, 3 |
| Path Interception by PATH Environment Variable | T1574.007 | Detection 2, 3 |
| Create or Modify System Process | T1543 | Detection 1, 3 |
| Modify System Image | T1601 | Detection 3 |
