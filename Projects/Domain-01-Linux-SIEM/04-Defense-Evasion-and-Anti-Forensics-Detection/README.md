# Project 04 — Defense Evasion and Anti-Forensics Detection

## Overview

This project simulates a full attacker anti-forensics lifecycle against a monitored Linux SIEM server and builds an eight-layer behavioral detection framework in Splunk using auditd kernel telemetry. Every technique simulated represents genuine attacker behavior documented in MITRE ATT&CK, and every detection uses behavioral scoring, session-scoped correlation, and temporal sequence analysis rather than simple signature matching.

The project follows the complete defensive cycle: attack simulation, kernel-level telemetry collection, detection engineering, alert validation, and architectural limitation documentation. It culminates in the most powerful detection in the entire platform — the Escalation-to-Evasion Temporal Correlation, which proves attacker sequence not just co-occurrence.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 10.10.10.132 |
| Target | Ubuntu Server — splunk-server (10.10.10.198) |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Sources | /var/log/audit/audit.log (auditd) |
| Kernel Monitor | auditd with 45 custom rules (15 new this project) |
| Hypervisor | Proxmox VE on Dell OptiPlex 7060 Micro |
| Network | Isolated lab segment 10.10.10.x behind OPNsense |

---

## Project Metrics

| Metric | Result |
|---|---|
| New auditd rules added | 15 |
| Total auditd rules | 45 |
| Splunk detections built | 8 |
| Attack simulations run | 9 |
| Attacks successfully detected | 8 |
| Detection rate | 89% |
| Architectural limitations documented | 4 |
| Known detection gaps | 3 |
| Highest confidence detection | 1.0 — Escalation-to-Evasion Correlation |
| MITRE techniques covered | T1070.001, T1070.002, T1070.003, T1070.006, T1485, T1562.001 |

---

## Why This Project Is Different

Every previous project in this domain detected attackers *doing* things — scanning, escalating, persisting. This project detects attackers *hiding* things.

The moment an attacker achieves root on a monitored system their first priority is often to stop the recording. An attacker who stops auditd, clears auth.log, and wipes bash history is telling you everything about their sophistication level and intent.

**The critical architectural insight:** Anti-forensics has a race condition. auditd logs its own death before it shuts down. The kernel generates one final record — a SERVICE_STOP entry — before the daemon goes dark. If the Splunk forwarder ships it in time, you catch the attacker stopping your detection system in the act.

**The confidence chain this project completes:**

```
Privilege Escalation CONFIRMED (Project 03)
        +
Anti-Forensics DETECTED in same session (Project 06)
        =
Confidence 0.95+ — BLIP-AI Autonomous Response Threshold Reached
```

---

## Phase 1 — New auditd Rules

16 new rules added bringing the total from 30 to 46.

```bash
# Audit system tampering
sudo auditctl -w /usr/sbin/auditctl -p x -k audit_tampering
sudo auditctl -w /etc/audit/audit.rules -p wa -k audit_rules_modified
sudo auditctl -w /etc/audit/rules.d -p wa -k audit_rules_modified

# Syslog and journal tampering
sudo auditctl -w /var/log/journal -p wa -k journald_tamper
sudo auditctl -w /usr/bin/journalctl -p x -k journald_exec
sudo auditctl -w /usr/sbin/rsyslog -p x -k syslog_tamper

# Targeted log file monitoring — NOT global /var/log
sudo auditctl -w /var/log/auth.log -p wa -k auth_log_tamper
sudo auditctl -w /var/log/syslog -p wa -k syslog_tamper
sudo auditctl -w /var/log/kern.log -p wa -k log_tamper

# Shell history tampering — all shells
sudo auditctl -w /home/labadmin/.bash_history -p wa -k history_tamper
sudo auditctl -w /home/labadmin/.zsh_history -p wa -k history_tamper
sudo auditctl -w /root/.bash_history -p wa -k history_tamper
sudo auditctl -w /root/.zsh_history -p wa -k history_tamper

# Secure deletion tools
sudo auditctl -w /usr/bin/shred -p x -k secure_delete
sudo auditctl -w /usr/bin/wipe -p x -k secure_delete

# Timestamp manipulation
sudo auditctl -w /usr/bin/touch -p x -k timestamp_tamper

# Splunk forwarder tampering
sudo auditctl -w /opt/splunkforwarder/bin/splunk -p x -k forwarder_tamper
```

Rules made permanent:

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Result: 46
```

**Key design decision — targeted vs broad watching:** The original broad `-w /var/log -p wxa -k log_tampering` rule was removed in favor of targeted file watches. Package managers, logrotate, and system services write to `/var/log` constantly — a broad watch generates thousands of false positives daily. Targeted rules watching specific high-value log files produce clean, actionable signal. This is alert tuning applied at the kernel level before data reaches the SIEM.

<img width="664" height="399" alt="Screenshot 2026-05-03 at 5 07 24 PM" src="https://github.com/user-attachments/assets/fc1000ac-981f-4791-95ab-6c521d1fef80" />

---

## Phase 2 — Attack Simulations

All attacks executed from a root shell on the Ubuntu server simulating post-exploitation attacker behavior. The attack sequence mirrors real attacker priority order: blind the detector first, then destroy evidence.

### Attack 1 — Blind the Detector

```bash
sudo systemctl stop auditd
sudo journalctl -u auditd | tail -10
sudo systemctl start auditd
sudo auditctl -l | wc -l
```

**Result:** auditd logged its own death. The kernel generated a final `SERVICE_STOP` record before shutdown — captured by journald and forwarded to Splunk before visibility was lost. This is the race condition: the attacker stops the recording and the recording catches it happening. Rules survived the restart at 45.

<img width="813" height="451" alt="Screenshot 2026-05-03 at 5 32 26 PM" src="https://github.com/user-attachments/assets/608382a2-7425-427d-ac47-292d6ed199a3" />

---

### Attack 2 — Erase Command Trail

```bash
history -c
history -w
unset HISTFILE
export HISTSIZE=0
rm ~/.bash_history
ln -sf /dev/null ~/.bash_history
cat ~/.bash_history
```

**Result:** 4 of 7 commands caught. `history -w`, `rm`, and `ln` captured by `history_tamper` rule. Bash built-ins (`history -c`, `unset HISTFILE`, `export HISTSIZE=0`) are invisible to auditd — they generate no syscalls and touch no files. Documented as known architectural gap.

---

### Attack 3 — Destroy Log Evidence

```bash
sudo rm /var/log/auth.log
sudo truncate -s 0 /var/log/kern.log
sudo shred /var/log/syslog
```

**Result:** auth.log deletion captured by `auth_log_tamper` rule. kern.log truncation captured by `log_tamper` rule. rsyslog automatically recreated auth.log within 30 minutes — Splunk had already ingested everything before deletion. Real-time log forwarding defeated the attack.

**Key discovery — inode watching:** When auth.log was deleted the auditd watch died with it because auditd watches inodes not paths. Restarting auditd re-establishes the watch against the new inode. This is why enterprise FIM tools like Wazuh explicitly handle inode recycling.

---

### Attack 4 — Manipulate Timestamps

```bash
echo "malicious_script" > /tmp/payload.sh
chmod +x /tmp/payload.sh
stat /tmp/payload.sh
sudo touch -t 202001010101 /tmp/payload.sh
stat /tmp/payload.sh
```

**Result:** touch execution captured by `timestamp_tamper` rule. stat output confirmed Modify time faked to January 2020 while Birth time preserved at 2026 — birth time (crtime) cannot be modified with touch and serves as the forensic anchor that survives all timestomping attempts.

<img width="1251" height="315" alt="Screenshot 2026-05-04 at 5 27 43 PM" src="https://github.com/user-attachments/assets/03d89299-68cf-4a5a-8916-e159313941ce" />

---

### Attack 5 — Secure File Deletion

```bash
echo "evidence" > /tmp/sensitive_data.txt
sudo shred -u /tmp/sensitive_data.txt
```

**Result:** shred execution captured by `secure_delete` rule. PROCTITLE hex record decoded to reveal full command including target file. Data overwritten multiple times — forensic recovery significantly impaired.

---

### Attack 6 — Full Cleanup Sequence After Escalation

```bash
# Step 1 — Escalate
sudo vim -c ':!/bin/bash'
whoami

# Step 2 — Immediate cleanup
history -c
history -w
rm ~/.bash_history
sudo touch -t 202001010101 /tmp/payload.sh
sudo shred -u /tmp/payload.sh 2>/dev/null

# Step 3 — Exit
exit
```

**Result:** Escalation at 21:19:02 → Anti-forensics at 21:19:13. 12 seconds between getting root and beginning cleanup. Detection 7 caught this as CRITICAL with 1.0 confidence — the attack narrative generated automatically.

---

### Attack 7 — Cut the SIEM Pipeline

```bash
sudo /opt/splunkforwarder/bin/splunk stop
sleep 20
sudo /opt/splunkforwarder/bin/splunk start
```

**Result:** 44 second dark window — auditd continued writing to disk but Splunk received nothing during the gap. Both stop and start captured by `forwarder_tamper` rule. Gap calculated from SYSCALL timestamps as 44 seconds at 0.85 confidence HIGH.

---

## Phase 3 — Detection Engineering

Eight behavioral detection rules built in Splunk using auditd kernel telemetry. All detections use session-scoped correlation via the `ses` field — ensuring techniques are tied to specific SSH sessions not just user accounts, dramatically reducing false positives from separate legitimate admin sessions.

---

### Detection 1 — Audit System Tampered

**What it catches:** Interactive and non-interactive modification or disabling of the auditd kernel monitoring system. Uses TTY context scoring not hard filtering — both surface at different confidence levels. Captures `auditctl -e 0` via argument analysis. Sets `telemetry_integrity=DEGRADED` platform-wide.

**Key design decision:** Hard `tty!=(none)` filtering would miss reverse shells and non-interactive attacks. The `interaction_type` scoring field replaced the filter — interactive tampering scores 0.95 CRITICAL, non-interactive scores 0.60 MEDIUM, both appear in results.

```spl
index=main sourcetype=linux_audit earliest=-15m
(key="audit_tampering" OR key="audit_rules_modified")
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
| rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval args=coalesce(a0,"")." ".coalesce(a1,"")
| eval dangerous_args=if(
    match(args,"-e 0|-e0|-D|-d"),
    "YES — Audit rules disabled or deleted",
    "NO — Standard audit operation")
| eval technique=case(
    binary="auditctl" AND dangerous_args="YES — Audit rules disabled or deleted",
        "Audit rules explicitly disabled — T1562.001",
    binary="auditctl", "Audit configuration modified",
    binary="systemctl" AND match(args,"stop|disable|mask"),
        "Audit service stopped via systemctl — T1562.001",
    true(), "Unknown audit system tampering")
| eval telemetry_integrity=if(
    match(technique,"disabled|stopped"),
    "DEGRADED — Kernel telemetry at risk",
    "MONITOR — Audit configuration changed")
| eval base_score=case(
    interaction_type="interactive"
        AND dangerous_args="YES — Audit rules disabled or deleted", 0.95,
    interaction_type="interactive", 0.80,
    interaction_type="non_interactive"
        AND dangerous_args="YES — Audit rules disabled or deleted", 0.85,
    interaction_type="non_interactive", 0.60,
    true(), 0.50)
| stats count values(exe) as tools values(technique) as techniques
    values(interaction_type) as session_type
    values(dangerous_args) as argument_analysis
    values(telemetry_integrity) as telemetry_status
    max(base_score) as confidence_score by auid host
| eval risk_level=case(
    confidence_score>=0.90, "CRITICAL — Audit system disabled by interactive user",
    confidence_score>=0.80, "HIGH — Interactive audit tampering detected",
    confidence_score>=0.60, "MEDIUM — Non-interactive audit modification",
    true(), "LOW — Audit system activity")
| table auid host count tools techniques session_type
    argument_analysis telemetry_status confidence_score risk_level
| sort -confidence_score
```

<img width="1238" height="868" alt="Screenshot 2026-05-03 at 5 50 13 PM" src="https://github.com/user-attachments/assets/f4bad581-d3ed-4e90-bde8-b815f29fe74b" />
<img width="1238" height="577" alt="Screenshot 2026-05-03 at 5 50 28 PM" src="https://github.com/user-attachments/assets/14f9dc1d-eb4b-40d4-a414-2cca575819f7" />


**Alert:** `Audit System Tampering Detected` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.80 HIGH
**MITRE:** T1562.001

---

### Detection 2 — Log File Deletion or Destruction

**What it catches:** Deletion, truncation, or secure wiping of critical log files. PATH record join on event_id identifies the specific file targeted. File criticality scoring distinguishes auth.log deletion (0.90) from application log deletion. Deletion method scoring: shred=0.98, rm=0.85, truncate=0.85.

```spl
index=main sourcetype=linux_audit earliest=-15m
(key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper")
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join event_id [
    search index=main sourcetype=linux_audit type=PATH
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"/var/log")
    | table event_id filepath nametype
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval file_criticality=case(
    match(filepath,"auth\.log|secure|audit\.log"),
        "CRITICAL FILE — Authentication or audit evidence",
    match(filepath,"syslog|messages|kern\.log"),
        "HIGH FILE — System operational evidence",
    true(), "MODERATE FILE — General log evidence")
| eval deletion_method=case(
    binary="shred", "Secure overwrite — forensic recovery prevented",
    binary="rm", "Standard deletion — forensic recovery possible",
    binary="truncate", "File zeroed — content destroyed",
    true(), "Unknown modification method")
| eval base_score=case(
    binary="shred" AND match(filepath,"auth\.log|secure|audit\.log"), 0.98,
    binary="shred", 0.95,
    binary="rm" AND match(filepath,"auth\.log|secure|audit\.log")
        AND interaction_type="interactive", 0.90,
    binary="rm" AND interaction_type="interactive", 0.85,
    binary="truncate" AND interaction_type="interactive", 0.85,
    true(), 0.50)
| stats count values(exe) as tools values(deletion_method) as methods
    values(filepath) as files_targeted values(file_criticality) as criticality
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host
| eval risk_level=case(
    confidence_score>=0.95, "CRITICAL — Forensic-grade destruction of critical log evidence",
    confidence_score>=0.85, "HIGH — Critical log file deleted by interactive user",
    true(), "MEDIUM — Log file activity")
| eval telemetry_impact="WARNING — Log evidence may be partially or fully destroyed"
| table auid host count tools methods files_targeted criticality
    session_type confidence_score telemetry_impact risk_level
| sort -confidence_score
```

<img width="1251" height="959" alt="Screenshot 2026-05-04 at 5 23 34 PM" src="https://github.com/user-attachments/assets/476ab82d-31af-4e33-a968-732be4011af4" />
<img width="1251" height="902" alt="Screenshot 2026-05-04 at 5 23 54 PM" src="https://github.com/user-attachments/assets/50e04b26-3c73-4ce0-92cd-626be8339184" />


**Alert:** `Log File Deletion or Destruction Detected` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.85 HIGH
**MITRE:** T1070.002

---

### Detection 3 — Shell History Evasion

**What it catches:** Deletion, symlinking, or modification of shell history files across bash, zsh, and python. PATH record join identifies the specific history file targeted. Symlink to /dev/null scores highest at 0.90. V2 will add escalation temporal correlation.

```spl
index=main sourcetype=linux_audit earliest=-15m
key="history_tamper"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join event_id [
    search index=main sourcetype=linux_audit type=PATH
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"bash_history|zsh_history|python_history|sh_history")
    | table event_id filepath nametype
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval evasion_technique=case(
    binary="ln",
        "History symlinked to /dev/null — future commands hidden",
    binary="rm" AND nametype="DELETE",
        "History file deleted — command trail destroyed",
    binary="truncate",
        "History file zeroed — content destroyed",
    binary="bash" OR binary="sh",
        "Shell writing to history file — possible overwrite",
    true(), "Unknown history modification")
| eval shell_type=case(
    match(filepath,"bash_history"), "Bash shell history",
    match(filepath,"zsh_history"), "Zsh shell history",
    match(filepath,"python_history"), "Python interpreter history",
    true(), "Unknown shell history")
| eval base_score=case(
    binary="ln" AND interaction_type="interactive", 0.90,
    binary="rm" AND interaction_type="interactive", 0.85,
    binary="truncate" AND interaction_type="interactive", 0.80,
    binary="bash" OR binary="sh", 0.70,
    interaction_type="non_interactive", 0.50,
    true(), 0.40)
| stats count values(exe) as tools
    values(evasion_technique) as techniques
    values(filepath) as history_files
    values(shell_type) as shells_affected
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host
| eval risk_level=case(
    confidence_score>=0.88, "CRITICAL — Multiple history evasion techniques combined",
    confidence_score>=0.80, "HIGH — Shell history destroyed by interactive user",
    confidence_score>=0.70, "HIGH — History evasion technique detected",
    true(), "MEDIUM — Shell history activity")
| eval v2_note="Escalation correlation pending — V2 raises severity when same session shows prior euid=0"
| table auid host count tools techniques history_files
    shells_affected session_type confidence_score risk_level v2_note
| sort -confidence_score
```

<img width="1265" height="654" alt="Screenshot 2026-05-04 at 5 19 53 PM" src="https://github.com/user-attachments/assets/25cb660a-c0b7-4fe3-960f-77d9710f2863" />

**Alert:** `Shell History Evasion Detected` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.90 CRITICAL
**MITRE:** T1070.003
**Known gaps:** `history -c`, `unset HISTFILE`, `export HISTSIZE=0` — bash built-ins, no syscall generated, invisible to auditd

---

### Detection 4 — Timestamp Manipulation

**What it catches:** Explicit timestamp modification via `-t` or `-d` flags using PROCTITLE hex decoding. Detects timestomping behavior not binary name — a renamed touch binary still passes `-t` and still fires. Birth time (crtime) preserved as forensic anchor.

```spl
index=main sourcetype=linux_audit earliest=-15m
type=PROCTITLE
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1"))
| where match(decoded,"(^|\s)(-t|-d|--date)(\s|$)")
| join event_id [
    search index=main sourcetype=linux_audit type=SYSCALL
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
    | rex field=_raw "ses=(?P<ses>\d+)"
    | rex field=_raw "tty=(?P<tty>\S+)"
    | rex field=_raw "success=(?P<success>\w+)"
    | where auid!="unset" AND auid!="4294967295"
    | where success="yes" OR success="1"
    | table event_id auid ses tty success
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval execution_tool=mvindex(split(trim(decoded)," "),0)
| eval filepath=mvindex(split(trim(decoded)," "),-1)
| eval tool_sophistication=case(
    match(execution_tool,"debugfs|perl|python|ruby"),
        "HIGH — Advanced timestomping tool detected",
    match(execution_tool,"touch|sudo"),
        "MEDIUM — Standard timestomping tool",
    true(), "LOW — Unknown tool")
| eval base_score=case(
    match(filepath,"/tmp/|/dev/shm/")
        AND interaction_type="interactive", 0.85,
    match(filepath,"\.sh$|\.py$|\.pl$|\.elf$|\.bin$"), 0.85,
    interaction_type="interactive", 0.75,
    true(), 0.60)
| stats count values(decoded) as full_command
    values(execution_tool) as tools_used
    values(tool_sophistication) as tool_assessment
    values(filepath) as files_targeted
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host
| eval risk_level=case(
    confidence_score>=0.85, "HIGH — Script or suspicious path timestomping",
    confidence_score>=0.75, "HIGH — Explicit timestamp manipulation by interactive user",
    true(), "MEDIUM — Timestamp manipulation detected")
| eval forensic_note="Birth time (crtime) cannot be modified with touch — preserved as forensic anchor"
| eval known_gaps="debugfs and binary renaming bypass this detection — documented limitation"
| table auid host count full_command tools_used tool_assessment
    files_targeted session_type confidence_score risk_level forensic_note known_gaps
| sort -confidence_score
```

<img width="1251" height="944" alt="Screenshot 2026-05-04 at 5 54 26 PM" src="https://github.com/user-attachments/assets/1bfab938-da78-40f2-bb13-872bb3cd08e7" />
<img width="1251" height="720" alt="Screenshot 2026-05-04 at 5 54 35 PM" src="https://github.com/user-attachments/assets/a1a1f5bd-62a8-45b5-a3ad-ed41d1dd9fee" />


**Alert:** `Timestamp Manipulation Detected` — Scheduled `*/5 * * * *`, Medium severity
**Confidence:** 0.85 HIGH
**MITRE:** T1070.006

---

### Detection 5 — Secure Deletion Tools Executed

**What it catches:** Forensic-grade secure deletion tools — shred, wipe, srm — using PROCTITLE hex decoding. Shred against /var/log scores 0.98. Recovery status: data overwritten multiple times — forensic recovery significantly impaired.

```spl
index=main sourcetype=linux_audit earliest=-15m
type=PROCTITLE
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1"))
| where match(decoded,"(^|\s)(shred|wipe|srm)(\s|$)")
| join event_id [
    search index=main sourcetype=linux_audit type=SYSCALL
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
    | rex field=_raw "ses=(?P<ses>\d+)"
    | rex field=_raw "tty=(?P<tty>\S+)"
    | rex field=_raw "success=(?P<success>\w+)"
    | where auid!="unset" AND auid!="4294967295"
    | where success="yes" OR success="1"
    | table event_id auid ses tty success
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval execution_tool=mvindex(split(trim(decoded)," "),0)
| eval filepath=mvindex(split(trim(decoded)," "),-1)
| eval tool_severity=case(
    match(execution_tool,"shred"),
        "CRITICAL — Multi-pass overwrite — forensic recovery prevented",
    match(execution_tool,"wipe"),
        "CRITICAL — Secure wipe — forensic recovery prevented",
    match(execution_tool,"srm"),
        "CRITICAL — Secure remove — forensic recovery prevented",
    true(), "HIGH — Secure deletion behavior detected")
| eval base_score=case(
    match(execution_tool,"shred|wipe|srm")
        AND match(filepath,"/var/log/")
        AND interaction_type="interactive", 0.98,
    match(execution_tool,"shred|wipe|srm")
        AND interaction_type="interactive", 0.92,
    match(execution_tool,"shred|wipe|srm"), 0.80,
    true(), 0.65)
| stats count values(decoded) as full_command
    values(execution_tool) as tools_used
    values(tool_severity) as severity_assessment
    values(filepath) as files_targeted
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host
| eval risk_level=case(
    confidence_score>=0.95, "CRITICAL — Forensic evidence permanently destroyed",
    confidence_score>=0.85, "CRITICAL — Secure deletion by interactive user",
    true(), "HIGH — Secure deletion tool detected")
| eval recovery_status="SEVERE — Data overwritten multiple times — forensic recovery significantly impaired"
| table auid host count full_command tools_used severity_assessment
    files_targeted session_type confidence_score risk_level recovery_status
| sort -confidence_score
```

<img width="1251" height="949" alt="Screenshot 2026-05-04 at 6 03 46 PM" src="https://github.com/user-attachments/assets/dc936aef-8d3a-4966-8241-e1cf61b7fcc2" />
<img width="1251" height="779" alt="Screenshot 2026-05-04 at 6 03 58 PM" src="https://github.com/user-attachments/assets/7f532b30-3dba-468f-bb39-ec3c2139bbf1" />


**Alert:** `Secure Deletion Tool Executed` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.92 CRITICAL
**MITRE:** T1485

---

### Detection 6 — Combined Anti-Forensics Behavioral Score

**What it catches:** Multiple evasion techniques from the same session within one hour. Session-scoped via `ses` field prevents false correlation across separate admin sessions. Two techniques = HIGH. Three or more = CRITICAL. Telemetry integrity flag surfaces when auditd was interrupted.

**Key design decision:** `by auid host ses` not `by auid host` — same user doing one technique in three separate SSH sessions is noise. Three techniques in one session is signal. Eva's feedback: session attribution is the difference between a noisy detection and a high-confidence one.

```spl
index=main sourcetype=linux_audit earliest=-1h
(key="audit_tampering" OR key="audit_rules_modified"
OR key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper"
OR key="history_tamper" OR key="timestamp_tamper" OR key="secure_delete"
OR key="journald_tamper")
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval technique=case(
    key="audit_tampering" OR key="audit_rules_modified", "Audit System Tampered",
    key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper", "Log File Destroyed",
    key="history_tamper", "Shell History Erased",
    key="timestamp_tamper", "Timestamps Manipulated",
    key="secure_delete", "Secure Deletion Tool Used",
    key="journald_tamper", "Journal Tampered",
    true(), "Unknown Evasion")
| eval technique_weight=case(
    key="audit_tampering" OR key="audit_rules_modified", 0.35,
    key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper", 0.25,
    key="history_tamper", 0.20,
    key="secure_delete", 0.25,
    key="timestamp_tamper", 0.15,
    key="journald_tamper", 0.20,
    true(), 0.10)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(technique_weight) as raw_score
    values(interaction_type) as session_types
    min(_time) as first_seen
    max(_time) as last_seen
    by auid host ses
| eval evasion_duration_minutes=round((last_seen - first_seen)/60, 1)
| eval combined_score=min(round(raw_score, 2), 1.0)
| eval interactive_bonus=if(mvfind(session_types,"interactive")>=0, 0.10, 0.0)
| eval final_confidence=min(combined_score + interactive_bonus, 1.0)
| where technique_count >= 2
| eval risk_level=case(
    technique_count>=4, "CRITICAL — Systematic anti-forensics campaign",
    technique_count>=3, "CRITICAL — Multiple evasion techniques in same session",
    technique_count>=2, "HIGH — Combined evasion behavior detected",
    true(), "MEDIUM — Evasion activity")
| eval attack_phase="POST-EXPLOITATION CLEANUP — Attacker actively destroying evidence"
| eval telemetry_integrity=case(
    mvfind(techniques_detected,"Audit System Tampered")>=0,
        "DEGRADED — Kernel telemetry was interrupted during attack window",
    true(), "INTACT — Full telemetry coverage maintained")
| table auid host ses technique_count techniques_detected
    final_confidence risk_level evasion_duration_minutes
    attack_phase telemetry_integrity
| sort -final_confidence
```

<img width="1251" height="953" alt="Screenshot 2026-05-04 at 6 07 38 PM" src="https://github.com/user-attachments/assets/0c5c0383-bbeb-4ebc-b232-6bc99802e8f4" />
<img width="1251" height="701" alt="Screenshot 2026-05-04 at 6 07 47 PM" src="https://github.com/user-attachments/assets/f6853ae5-7811-467a-8786-474c308e66e4" />

**Alert:** `Combined Anti-Forensics Behavioral Score` — Scheduled `*/5 * * * *`, Critical severity
**Confidence:** 1.0 CRITICAL
**MITRE:** T1070, T1562

---

### Detection 7 — Escalation-to-Evasion Temporal Correlation

**What it catches:** Anti-forensics occurring within 60 minutes of confirmed privilege escalation in the same session. This is the crown jewel detection. Confidence decays with time — under 5 minutes scores 0.95 CRITICAL. `evasion_time > escalation_time` is the sequence enforcement line that transforms co-occurrence into causation evidence.

**Why this is the most important detection:** Every other detection asks "did this bad thing happen?" This detection asks "did this bad thing happen BECAUSE of that bad thing that happened earlier?" That is the difference between detecting events and detecting intent.

```spl
index=main sourcetype=linux_audit earliest=-2h
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "(?i)euid[=:\"](?P<euid>\d+)"
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| eval event_category=case(
    match(key,"audit_tampering|audit_rules_modified"), "anti_forensics",
    match(key,"auth_log_tamper|syslog_tamper|log_tamper"), "anti_forensics",
    match(key,"history_tamper"), "anti_forensics",
    match(key,"timestamp_tamper"), "anti_forensics",
    match(key,"secure_delete"), "anti_forensics",
    euid="0" AND auid!="0" AND isnotnull(euid), "escalation",
    true(), null())
| where isnotnull(event_category)
| stats
    min(eval(if(event_category="escalation",_time,null()))) as escalation_time
    min(eval(if(event_category="anti_forensics",_time,null()))) as evasion_time
    values(eval(if(event_category="anti_forensics",key,null()))) as evasion_keys
    dc(eval(if(event_category="anti_forensics",key,null()))) as evasion_technique_count
    by auid ses host
| where isnotnull(escalation_time) AND isnotnull(evasion_time)
| where evasion_time > escalation_time
| eval minutes_between=round((evasion_time - escalation_time)/60, 1)
| where minutes_between <= 60
| eval sequence_confidence=case(
    minutes_between <= 5,  0.95,
    minutes_between <= 15, 0.90,
    minutes_between <= 30, 0.85,
    minutes_between <= 60, 0.75,
    true(), 0.60)
| eval evasion_bonus=case(
    evasion_technique_count >= 3, 0.10,
    evasion_technique_count >= 2, 0.05,
    true(), 0.0)
| eval final_confidence=min(sequence_confidence + evasion_bonus, 1.0)
| eval risk_level=case(
    final_confidence >= 0.95, "CRITICAL — Immediate cleanup after escalation",
    final_confidence >= 0.85, "CRITICAL — Anti-forensics followed escalation",
    final_confidence >= 0.75, "HIGH — Probable attacker cleanup sequence",
    true(), "MEDIUM — Suspicious escalation-evasion proximity")
| eval attack_narrative=
    "Privilege escalation at ".strftime(escalation_time,"%H:%M:%S").
    " → Anti-forensics at ".strftime(evasion_time,"%H:%M:%S").
    " (".tostring(minutes_between)." minutes later)"
| eval techniques_used=mvjoin(evasion_keys," | ")
| table auid host ses attack_narrative techniques_used
    evasion_technique_count minutes_between
    final_confidence risk_level
| sort -final_confidence
```

<img width="1251" height="949" alt="Screenshot 2026-05-04 at 6 54 11 PM" src="https://github.com/user-attachments/assets/590f0734-4642-4ffb-a19e-746465c89c13" />
<img width="1251" height="518" alt="Screenshot 2026-05-04 at 6 54 21 PM" src="https://github.com/user-attachments/assets/5e36ca04-0610-4caf-899b-1d7d5a2a455a" />


**Alert:** `Escalation-to-Evasion Temporal Correlation` — Scheduled `*/5 * * * *`, Critical severity
**Confidence:** 1.0 CRITICAL
**MITRE:** T1562, T1070, T1548
**Result:** Escalation at 21:19:02 → Anti-forensics at 21:19:13 — 12 seconds between getting root and cleanup

---

### Detection 8 — Splunk Forwarder Stopped

**What it catches:** Stop and start cycle of the Splunk Universal Forwarder binary. The gap between invocations represents a SIEM blind window. auditd continues writing to disk during the gap but Splunk receives nothing — the SOC is blind while logs accumulate locally.

**Key architectural distinction:** Stopping the forwarder is different from stopping auditd. auditd tampering blinds kernel collection. Forwarder tampering blinds the SIEM pipeline while leaving collection intact. A sophisticated attacker does the forwarder because auditd continues producing evidence they cannot suppress — they just stop it from reaching analysts.

```spl
index=main sourcetype=linux_audit earliest=-15m
key="forwarder_tamper"
type=SYSCALL
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295"
| where success="yes" OR success="1"
| where comm="splunk"
| sort _time
| streamstats count as n first(_time) as t1 last(_time) as t2 by auid ses
| where n>=2
| eval gap=round(t2-t1,0)
| eval score=if(gap>120,0.90,if(gap>30,0.85,0.75))
| dedup auid ses
| table auid ses gap score
```
<img width="1251" height="947" alt="Screenshot 2026-05-04 at 7 28 53 PM" src="https://github.com/user-attachments/assets/3baa6d60-a525-4fef-b989-53c882706f53" />

**Alert:** `Splunk Forwarder Stopped — SIEM Pipeline Severed` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.85 HIGH
**MITRE:** T1562
**Result:** 44 second dark window — gap calculated from SYSCALL timestamps

---

## Alert Validation Summary

All eight alerts confirmed firing against real attack data:

| Alert | Severity | Confidence | Triggered By |
|---|---|---|---|
| Audit System Tampering Detected | High | 0.80 | auditctl execution by interactive user |
| Log File Deletion or Destruction Detected | High | 0.85 | rm and truncate against /var/log files |
| Shell History Evasion Detected | High | 0.90 | rm, ln, and bash write to .bash_history |
| Timestamp Manipulation Detected | Medium | 0.85 | touch -t 202001010101 /tmp/payload.sh |
| Secure Deletion Tool Executed | High | 0.92 | shred -u /tmp/sensitive_data.txt |
| Combined Anti-Forensics Behavioral Score | Critical | 1.0 | 3 techniques in same session |
| Escalation-to-Evasion Temporal Correlation | Critical | 1.0 | 12 second gap between root and cleanup |
| Splunk Forwarder Stopped | High | 0.85 | 44 second forwarder stop/start cycle |

---

## Architectural Limitations and Known Gaps

| Gap | Description | Detection Impact | Mitigation Path |
|---|---|---|---|
| Bash built-ins invisible | `history -c`, `unset HISTFILE`, `export HISTSIZE=0` generate no syscalls | 3 of 9 attacks undetected | eBPF-based monitoring, shell session auditing |
| auditd race condition | Stop event may not reach Splunk before daemon shuts down | SERVICE_STOP unreliable in Splunk | journald captures independently |
| Inode-based watching | Deleting a watched file destroys the watch — new inode loses the rule | Brief gap after deletion | auditd restart re-establishes watches |
| Shell redirect truncation | `> /var/log/auth.log` uses shell built-in — no binary executed | Redirect truncation partially invisible | Filesystem PATH records catch the write syscall |
| PROCTITLE fragility | Hex decoding breaks with special characters | Detections 4 and 5 may miss edge cases | EXECVE records as fallback |

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Detected |
|---|---|---|---|
| Disable or Modify Tools | T1562.001 | Defense Evasion | ✅ Detection 1 |
| Clear Linux System Logs | T1070.002 | Defense Evasion | ✅ Detection 2 |
| Clear Command History | T1070.003 | Defense Evasion | ✅ Detection 3 |
| Timestomp | T1070.006 | Defense Evasion | ✅ Detection 4 |
| Data Destruction | T1485 | Impact | ✅ Detection 5 |
| Multi-technique behavioral correlation | T1070, T1562 | Defense Evasion | ✅ Detection 6 |
| Escalation-to-evasion sequence | T1562, T1070, T1548 | Combined | ✅ Detection 7 |
| Impair logging pipeline | T1562 | Defense Evasion | ✅ Detection 8 |

---
