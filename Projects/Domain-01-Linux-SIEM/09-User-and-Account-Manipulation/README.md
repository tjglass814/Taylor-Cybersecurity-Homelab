# Project 09 — User and Account Manipulation

## Overview

This project builds behavioral detections around post-compromise account manipulation — the phase where an attacker with root access creates backdoor accounts, modifies existing accounts, and grants themselves permanent sudo privileges. Where Project 3 (Persistence) detected mechanisms like cron jobs and systemd services, Project 9 detects the human account layer: new users, password changes, group membership manipulation, and direct sudoers modification.

Three detections were built: a backdoor user account detector using PROCTITLE decode to classify account operations, a sudoers privilege escalation detector that separates write signals from sudo's constant read noise, and a session-scoped combined behavioral score correlating both signals.

A key discovery this project: the existing `sudo_changes` watch rule only covered `/etc/sudoers` — not `/etc/sudoers.d/`. Attackers frequently use the drop-in directory to avoid touching the main sudoers file. One new watch rule was added to close that gap.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 69 total (1 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 1 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 4 |
| Confidence Range | 0.90 – 1.0 |

## Why This Project Matters

Account manipulation is the most durable form of persistence. A cron job can be deleted. A systemd service can be disabled. But a backdoor user account with NOPASSWD sudo access survives nearly every incident response action short of a full reimaging. An attacker who creates `backdoor ALL=(ALL) NOPASSWD:ALL` in `/etc/sudoers.d/` has root access that survives password resets, process kills, and service restarts.

The detection challenge is noise. `sudo` reads `/etc/sudoers` on every single invocation — a busy system generates hundreds of `sudo_changes` events per hour from completely legitimate activity. This project demonstrates how to separate the write signal (attacker granting privileges) from the read noise (sudo checking permissions) using syscall analysis and binary classification.

---

## Phase 1 — Infrastructure

### New auditd Rule

One rule added — closing the `/etc/sudoers.d/` gap:

```bash
sudo auditctl -w /etc/sudoers.d -p wa -k sudoers_change
```

**Why this was missing:** The existing `sudo_changes` watch from Project 3 only covered `/etc/sudoers`. Attackers frequently write to `/etc/sudoers.d/` drop-in files instead — a separate directory that allows adding sudo rules without touching the main file. Without this rule, `echo "backdoor ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/backdoor` was completely invisible to auditd.

**Existing rules leveraged (no changes needed):**
- `user_creation` — watches `useradd`, `adduser`, `usermod` binaries
- `sudo_changes` — watches `/etc/sudoers` reads and writes
- `passwd_changes` — watches `/etc/passwd` modifications
- `proc_exec` — broad execve monitor catches `passwd`, `chpasswd` and other account tools

**Rule persistence:**
```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 69
```

---

## Phase 2 — Attack Simulation

Simulates the complete backdoor account creation sequence an attacker with root access would execute:

```bash
# Create backdoor user account
sudo useradd -m -s /bin/bash backdoor

# Add to sudo group via usermod
sudo usermod -aG sudo backdoor

# Grant passwordless root via sudoers drop-in file
echo "backdoor ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/backdoor

# Cleanup
sudo userdel -r backdoor 2>/dev/null
sudo rm -f /etc/sudoers.d/backdoor
```
<img width="1270" height="259" alt="Screenshot 2026-06-09 at 5 11 49 PM" src="https://github.com/user-attachments/assets/1602edab-2590-4bf9-8f0a-ed36d08bc126" />

**What auditd recorded:**
- `user_creation` key — `useradd` and `usermod` executions
- `sudoers_change` key — `tee` writing to `/etc/sudoers.d/backdoor` and `rm` deleting it
- `passwd_changes` key — `/etc/passwd` modifications from useradd/userdel

**Key lesson — `/etc/sudoers.d/` gap:** The initial attack confirmed that without the new `sudoers_change` watch on the drop-in directory, the `tee` write was completely invisible. auditd only caught the sudo read noise. One rule addition closed a complete blind spot.

---

## Phase 3 — Detections

### Detection 1 — Backdoor User Account Activity Detected

**Description:** Detects interactive user account creation and modification using the `user_creation` auditd key. Decodes PROCTITLE hex to extract full command arguments and classifies the action type. Scores highest when a user is added to the sudo or wheel group — immediate root-level access granted in a single command.

**MITRE:** T1136.001 — Create Account: Local Account, T1098 — Account Manipulation

**Evidence Weight:** 0.90 CRITICAL

**Why 0.90:** Adding a user directly to the sudo or wheel group (`usermod -aG sudo backdoor`) grants root-equivalent access immediately. There's no legitimate reason for this operation to occur outside of planned admin work — and planned admin work should be scheduled and documented, not appearing as an ad-hoc interactive session event.

```spl
index=main sourcetype=linux_audit earliest=-60m
"user_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(useradd|adduser|usermod)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PROCTITLE"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
    | table event_id decoded
]
| eval action_type=case(
    match(decoded,"(?i)(sudo|wheel)") AND comm="usermod", "user_added_to_privileged_group",
    comm="useradd" OR comm="adduser", "new_user_created",
    comm="usermod", "user_modified",
    true(), "account_change"
)
| eval evidence_weight=case(
    match(decoded,"(?i)(sudo|wheel)") AND comm="usermod", 0.90,
    comm="useradd" OR comm="adduser", 0.80,
    comm="usermod", 0.70,
    true(), 0.60
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Backdoor User Account Activity Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used actions commands_run first_seen last_seen
```

<img width="1257" height="372" alt="Screenshot 2026-06-09 at 5 25 02 PM" src="https://github.com/user-attachments/assets/09719096-1f2a-44e6-a796-57f737699031" />


**Alert Settings:**
- Title: `Backdoor User Account Activity Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Sudoers Privilege Escalation Detected

**Description:** Detects writes, renames, and deletions of sudoers files. Explicitly excludes `comm="sudo"` which reads sudoers on every invocation and would otherwise generate constant false positives. Joins PATH records via event_id to identify the specific file modified. Shell-based writes score CRITICAL — legitimate sudoers changes use `visudo`, not `tee` or shell redirection.

**MITRE:** T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

**Evidence Weight:** 0.90 CRITICAL

**Syscall validation:** On Ubuntu 24.04 x86_64, `syscall=263` = unlinkat (file deletion) and `syscall=257` = openat (file open/write). These values were validated directly from real attack telemetry — not assumed from documentation.

```spl
index=main sourcetype=linux_audit earliest=-60m
"sudoers_change" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "syscall=(?P<syscall>\d+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="sudo"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"sudoers")
    | where nametype="NORMAL" OR nametype="CREATE"
    | table event_id filepath nametype
]
| eval action_type=case(
    syscall=263, "sudoers_file_deleted",
    syscall=82, "sudoers_file_renamed",
    match(comm,"^(tee|echo|bash|sh|dash|nano|vim|vi|cp|mv)$"), "sudoers_file_written",
    true(), "sudoers_modified"
)
| eval evidence_weight=case(
    match(comm,"^(tee|echo|bash|sh|dash)$"), 0.90,
    match(comm,"^(nano|vim|vi)$"), 0.80,
    match(comm,"^(cp|mv)$"), 0.75,
    syscall=263, 0.70,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Sudoers Privilege Escalation Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used files_affected actions first_seen last_seen
```

<img width="1257" height="372" alt="Screenshot 2026-06-09 at 5 33 29 PM" src="https://github.com/user-attachments/assets/dca057da-5d8f-4f63-b5d6-042701f73ccf" />


**Alert Settings:**
- Title: `Sudoers Privilege Escalation Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Account Manipulation Behavioral Score

**Description:** Correlates user account creation/modification and sudoers file modification within the same session. Creating a backdoor account AND granting it root access in the same session is a complete privilege escalation sequence. Either signal alone is suspicious — both together in the same session is confirmed attacker behavior.

**MITRE:** T1136.001, T1098, T1548.003, T1078 — Valid Accounts

**Confidence:** 1.0 CRITICAL

**Why session-scoped matters here:** A system administrator who adds a user on Monday and modifies sudoers on Friday is doing two separate legitimate admin tasks. An attacker who creates `backdoor` and immediately grants it `NOPASSWD:ALL` in the same SSH session is executing a complete privilege escalation chain. The `ses` field separates these cases — same session correlation eliminates the false positive.

```spl
index=main sourcetype=linux_audit earliest=-60m
("user_creation" OR "sudoers_change") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "syscall=(?P<syscall>\d+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key="user_creation" AND match(comm,"^(useradd|adduser|usermod)$"), "account_manipulation",
    key="sudoers_change" AND comm!="sudo", "sudoers_modification",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(
        technique="account_manipulation", 0.80,
        technique="sudoers_modification", 0.90,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval detection="Combined Account Manipulation Behavioral Score"
| eval description="User account creation/modification AND sudoers modification detected in same session. Creating a backdoor account and immediately granting it root access is a confirmed privilege escalation pattern."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected first_seen last_seen description
```
<img width="1257" height="372" alt="Screenshot 2026-06-09 at 5 35 21 PM" src="https://github.com/user-attachments/assets/35b670b3-f967-449c-8142-18f09ede6fd0" />

**Alert Settings:**
- Title: `Combined Account Manipulation Behavioral Score`
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
| 1 — Backdoor User Account Activity | ✅ | ✅ user_creation key firing | ✅ 1 row, 0.90 CRITICAL | ✅ |
| 2 — Sudoers Privilege Escalation | ✅ | ✅ sudoers_change tee + rm | ✅ 1 row, 0.90 CRITICAL | ✅ |
| 3 — Combined Account Manipulation | ✅ | ✅ both techniques same session | ✅ 1 row, 1.0 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| sudo_changes noisy | sudo reads sudoers on every invocation — hundreds of events per hour | Already mitigated via comm!="sudo" filter |
| PROCTITLE join scalability | join has 50k row limit | Replace with transaction event_id in V2 |
| Syscall numbers hardcoded | 263/257 validated on x86_64 Ubuntu 24.04 only | Use comm-based classification as primary signal |
| passwd binary not covered | `passwd username` execution not in user_creation key | Add passwd key watch or filter proc_exec |
| visudo not detected | visudo is the legitimate sudoers editor — modifications via visudo would fire this alert | Tune with known-good baseline or visudo exclusion |
| No content inspection | auditd captures WHO modified sudoers not WHAT was written | FIM integration in V2 for content analysis |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Create Account: Local Account | T1136.001 | Detection 1, 3 |
| Account Manipulation | T1098 | Detection 1, 3 |
| Abuse Elevation Control: Sudo | T1548.003 | Detection 2, 3 |
| Valid Accounts | T1078 | Detection 3 |
