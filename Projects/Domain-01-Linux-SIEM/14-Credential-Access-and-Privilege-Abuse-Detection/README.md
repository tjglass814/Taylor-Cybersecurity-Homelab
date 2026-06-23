# Project 14 — Credential Access and Privilege Abuse Detection

## Overview

This project builds behavioral detections around credential access and privilege abuse — the phase where an attacker moves from having a foothold to owning the system and potentially every system it can reach. Stolen credentials are uniquely dangerous because they are portable, survive remediation, and appear legitimate to every system they are used against.

Three detections were built: a credential file and auth log harvesting detector, a privileged execution detector catching non-root users gaining root effective UID, and a combined behavioral score correlating both signals in the same session.

A key architectural lesson this project: `euid=0 AND uid!=0` does not reliably identify sudo abuse because sudo often sets both uid and euid to 0 in child processes. The correct filter is `euid=0 AND auid!=0 AND auid!=4294967295` — using the audit login UID which persists from the original login session regardless of privilege escalation.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 88 total (5 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 5 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 5 |
| Confidence Range | 0.95 – 1.0 |

## Why This Project Matters

Credential access is the force multiplier of every attack. An attacker who owns one server but has stolen credentials from `/etc/shadow` can crack those hashes offline and potentially authenticate to every other system in the environment. SSH private keys are even more valuable — they work immediately with no cracking required.

The privilege abuse detection is equally important. `sudo bash` is one command that transforms a limited user account into an unrestricted root shell — bypassing any per-command sudo restrictions the administrator configured. Detecting this transition at the kernel level, using the audit login UID that persists through privilege escalation, is the reliable way to catch it.

---

## Phase 1 — Infrastructure

### New auditd Rules

Five rules added:

```bash
# Auth log access monitoring
sudo auditctl -w /var/log/auth.log -p r -k auth_log_read
sudo auditctl -w /var/log/secure -p r -k auth_log_read

# SSH key access monitoring
sudo auditctl -w /root/.ssh -p r -k ssh_key_access
sudo auditctl -w /home/labadmin/.ssh -p r -k ssh_key_access

# SUID/privileged execution monitoring
sudo auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=4294967295 -k suid_exec
```

**Key discovery — auth_log_read noise:**
The Splunk forwarder (`comm="tailreader0"`) tails `/var/log/auth.log` continuously — generating constant `auth_log_read` events with `tty=(none)`. The `tty!="(none)"` interactive session filter handles this completely. Discovered during ausearch verification before building detections.

**Key discovery — auid vs uid for sudo detection:**
Initial attempt used `euid=0 AND uid!=0` to identify non-root users gaining root. Eva flagged this as incorrect — sudo child processes often run with both `uid=0` and `euid=0`. The correct approach uses `auid` (audit login UID) which is set at login and never changes regardless of privilege escalation. `auid!=0 AND auid!=4294967295` reliably identifies non-root interactive users who gained root effective UID.

**Rule persistence:**
```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 88
```

---

## Phase 2 — Attack Simulation

Simulates credential access and privilege abuse across all four attack categories:

```bash
# Attack 1 — Credential file access
sudo cat /etc/shadow
cat /etc/passwd
cat /home/labadmin/.ssh/id_rsa 2>/dev/null || echo "no key"

# Attack 2 — Auth log harvesting
sudo cat /var/log/auth.log | tail -50
grep "Failed password" /var/log/auth.log | tail -10

# Attack 3 — Sudo abuse
sudo bash -c "whoami"
sudo find /etc -name "shadow" 2>/dev/null
sudo python3 -c "import os; os.system('whoami')"

# Attack 4 — SUID/editor shell escape
find / -perm -4000 -type f 2>/dev/null | head -10
sudo vim -c ':!whoami' -c ':q!' /dev/null 2>/dev/null || true
```

<img width="1308" height="873" alt="Screenshot 2026-06-23 at 5 03 27 PM" src="https://github.com/user-attachments/assets/f4061604-042f-4dc6-a1b7-e53d190e171f" />


**What auditd recorded:**
- `shadow_access` — sudo reading /etc/shadow ✅
- `auth_log_read` — cat and grep reading /var/log/auth.log ✅
- `proc_exec` — vim, whoami, python3, bash running as euid=0 ✅

**Noise identified and filtered:**
- `shadow_access`: `comm="sudo"` fires on every sudo invocation (PAM auth), `cron` fires periodically — both filtered by comm exclusion list
- `auth_log_read`: `comm="tailreader0"` (Splunk forwarder) fires constantly — filtered by `tty!="(none)"`

---

## Phase 3 — Detections

### Detection 1 — Credential File and Auth Log Harvesting Detected

**Description:** Detects interactive reads of `/etc/shadow`, SSH keys, and auth logs. Explicitly excludes sudo, sshd, cron, journalctl, and Splunk forwarder noise. PATH records confirm specific files accessed. Shadow file access scores 0.95 CRITICAL — no legitimate reason for an interactive user session to read `/etc/shadow` directly.

**MITRE:** T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow, T1552.004 — Unsecured Credentials: Private Keys

**Evidence Weight:** 0.95 CRITICAL

**Design decisions:**
- `/etc/passwd` explicitly excluded — readable by all users, referenced constantly by legitimate tools, generates excessive false positives
- Auth log score lowered to 0.70 — many admins legitimately grep auth logs; score is defensible but not CRITICAL alone
- PATH regex anchored with `^` and `$` to prevent substring matches

```spl
index=main sourcetype=linux_audit earliest=-60m
("shadow_access" OR "auth_log_read") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "euid=(?P<euid>\d+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where NOT match(comm,"^(sudo|cron|tailreader|splunkd|sshd|journalctl|logrotate|rsyslogd)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"(^/etc/shadow$|^/var/log/auth\.log$|^/var/log/secure$|/\.ssh/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval target_type=case(
    match(mvjoin(filepath," "),"^/etc/shadow"), "shadow_file",
    match(mvjoin(filepath," "),"/\.ssh/"), "ssh_keys",
    match(mvjoin(filepath," "),"auth\.log|/var/log/secure"), "auth_log",
    true(), "credential_file"
)
| eval evidence_weight=case(
    target_type="shadow_file", 0.95,
    target_type="ssh_keys", 0.90,
    target_type="auth_log", 0.70,
    true(), 0.65
)
| stats
    count as access_count
    values(comm) as tools_used
    values(filepath) as files_accessed
    values(target_type) as target_types
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Credential File and Auth Log Harvesting Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host access_count tools_used target_types files_accessed first_seen last_seen
```

<img width="1250" height="289" alt="Screenshot 2026-06-23 at 5 09 41 PM" src="https://github.com/user-attachments/assets/4518e8bd-5fb2-4506-82fb-21802f302b19" />


**Alert Settings:**
- Title: `Credential File and Auth Log Harvesting Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Privileged Execution by Non-Root User Detected

**Description:** Detects processes running with euid=0 (root effective UID) where the original login user (auid) was non-root. Classifies abuse type by comm — editor shell escapes score 0.95, interpreter execution 0.90, root shell spawning 0.85, LOLBin execution and privilege verification 0.75. PROCTITLE decode provides full command visibility.

**MITRE:** T1548.003 — Abuse Elevation Control Mechanism: Sudo, T1059 — Command and Scripting Interpreter

**Evidence Weight:** 0.95 CRITICAL

**Key architectural fix — auid over uid:**
First version used `uid!=0` to identify non-root users. Eva flagged this as incorrect — sudo child processes set both uid and euid to 0. Corrected to `auid!=0` — the audit login UID persists from the original login session through any privilege escalation, making it the reliable identifier of the originating non-root user.

```spl
index=main sourcetype=linux_audit earliest=-60m
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "euid=(?P<euid>\d+)"
| rex field=_raw "uid=(?P<uid>\d+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where auid!=0
| where tty!="(none)"
| where euid=0
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
| eval abuse_type=case(
    match(comm,"^(bash|sh|dash|zsh|fish|su)$"), "shell_spawned_as_root",
    match(comm,"^(vim|vi|nano|less|more)$") AND has_proctitle=1
        AND match(mvjoin(decoded," "),"(^!|:!|os\.system|exec\()"), "editor_shell_escape",
    match(comm,"^(python3?|perl|ruby|lua|php)$"), "interpreter_exec_as_root",
    match(comm,"^(find|awk|sed|nmap|curl|wget)$"), "lolbin_exec_as_root",
    match(comm,"^(whoami|id|hostname)$"), "privilege_verification",
    true(), "privileged_exec"
)
| eval evidence_weight=case(
    abuse_type="editor_shell_escape", 0.95,
    abuse_type="interpreter_exec_as_root", 0.90,
    abuse_type="shell_spawned_as_root", 0.85,
    abuse_type="lolbin_exec_as_root", 0.75,
    abuse_type="privilege_verification", 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(abuse_type) as abuse_types
    values(decoded) as commands_run
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Privileged Execution by Non-Root User Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used abuse_types commands_run first_seen last_seen
```

<img width="1250" height="653" alt="Screenshot 2026-06-23 at 5 12 42 PM" src="https://github.com/user-attachments/assets/f83b54e8-e6e3-46a1-a407-086a74a49808" />


**Alert Settings:**
- Title: `Privileged Execution by Non-Root User Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Credential Access and Privilege Abuse Score

**Description:** Correlates credential file harvesting, auth log harvesting, and privileged execution in the same session. Credential harvesting alone is suspicious. Privileged execution alone may be legitimate admin work. Both in the same session confirms active credential theft combined with privilege abuse. Normalized weighted scoring with 0.75 minimum confidence gate.

**MITRE:** T1003.008, T1552.004, T1548.003, T1059, T1078 — Valid Accounts

**Confidence:** 1.0 CRITICAL

```spl
index=main sourcetype=linux_audit earliest=-60m
("shadow_access" OR "auth_log_read" OR "proc_exec") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "euid=(?P<euid>\d+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where auid!=0
| where tty!="(none)"
| where NOT match(comm,"^(sudo|cron|tailreader|splunkd|sshd|journalctl|logrotate)$")
| eval technique=case(
    key="shadow_access" AND match(comm,"^(cat|grep|python3?|perl|less|more|head|tail)$"),
        "credential_harvesting",
    key="auth_log_read" AND match(comm,"^(cat|grep|less|more|head|tail|awk)$"),
        "auth_log_harvesting",
    key="proc_exec" AND euid=0
        AND match(comm,"^(bash|sh|dash|zsh|fish|su|python3?|perl|vim|vi|whoami|id)$"),
        "privileged_execution",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="credential_harvesting", 0.90,
    technique="auth_log_harvesting", 0.70,
    technique="privileged_execution", 0.85,
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
| eval detection="Combined Credential Access and Privilege Abuse Score"
| eval description="Credential harvesting and privileged execution detected in same session. Reading credential stores combined with root-level execution confirms active credential theft and privilege abuse."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen description
```

<img width="1250" height="466" alt="Screenshot 2026-06-23 at 5 16 05 PM" src="https://github.com/user-attachments/assets/fc35206b-85dd-45aa-b1b6-cfdca334789a" />


**Alert Settings:**
- Title: `Combined Credential Access and Privilege Abuse Score`
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
| 1 — Credential File and Auth Log Harvesting | ✅ | ✅ shadow_access + auth_log_read | ✅ 1 row, 0.95 CRITICAL | ✅ (3 review cycles) |
| 2 — Privileged Execution by Non-Root User | ✅ | ✅ proc_exec euid=0 auid=1000 | ✅ 1 row, 0.95 CRITICAL | ✅ (3 review cycles) |
| 3 — Combined Credential Access and Privilege Abuse | ✅ | ✅ all 3 technique categories | ✅ 1 row, 1.0 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| /etc/passwd excluded entirely | Misses passwd-based enumeration | Add back at very low weight (0.40) with comm exclusion list |
| Auth log score conservative at 0.70 | May miss dedicated auth log harvesting sessions | Raise to 0.80 when correlated with shadow_access |
| No offline hash cracking detection | Attacker takes hashes offline — undetectable on this host | Network-based detection in Domain 2 |
| SSH key detection requires key to exist | No .ssh directory on this host | Confirmed gap — add test key for future validation |
| suid_exec rule generates mostly noise | euid=0 rule fires on all privileged executions including legitimate | Refine with specific binary exclusion list in V2 |
| Editor shell escape PROCTITLE dependent | If PROCTITLE missing, editor escape downgrades to privileged_exec | Accept as architectural constraint |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| OS Credential Dumping: /etc/shadow | T1003.008 | Detection 1, 3 |
| Unsecured Credentials: Private Keys | T1552.004 | Detection 1, 3 |
| Abuse Elevation Control: Sudo | T1548.003 | Detection 2, 3 |
| Command and Scripting Interpreter | T1059 | Detection 2, 3 |
| Valid Accounts | T1078 | Detection 3 |

---
