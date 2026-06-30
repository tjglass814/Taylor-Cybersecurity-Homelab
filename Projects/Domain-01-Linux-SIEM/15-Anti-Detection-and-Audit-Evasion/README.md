# Project 15 — Anti-Detection and Audit Evasion Detection

## Overview

This is the capstone project of Domain 1. Every previous project assumed auditd was faithfully recording attacker activity. Project 15 detects attackers who know that assumption and attack the detection infrastructure itself — disabling audit rules, tampering with configuration files, and coordinating multi-technique evasion campaigns against the entire BLIP-AI detection stack.

Three detections were built: an audit configuration tampering detector watching for interactive writes to `/etc/audit/`, an audit rule deletion and evasion detector classifying specific auditctl evasion techniques via PROCTITLE decode, and a combined anti-detection score correlating multiple evasion technique categories in the same session.

This project also served as the Domain 1 infrastructure finalization — adding four additional auditd rule categories recommended by Eva (setuid/setgid syscalls, ptrace injection, kernel module loading, capabilities manipulation) plus tightly scoped /proc sensitive reads, bringing the final Domain 1 rule count to 83.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| SIEM | Splunk Enterprise 10.2.2 |
| Kernel | 6.8.0-124-generic |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 83 total — Domain 1 final count |

## Domain 1 Final Rule Count: 83

| Rule Category | Key | Count |
|---|---|---|
| SSH key modification | ssh_key_modification | 2 |
| Cron modification | cron_modification | 3 |
| Systemd modification | systemd_modification | 1 |
| Startup file modification | startup_modification | 4 |
| Cron execution | cron_exec | 1 |
| Systemd execution | systemd_exec | 1 |
| SSHD execution | sshd_exec | 1 |
| Process execution (broad) | proc_exec | 1 |
| Suspicious execution | suspicious_exec | 3 |
| Reverse shell tools | reverse_shell_tool | 2 |
| Interpreter execution | interpreter_exec | 2 |
| Download tools | download_tool | 2 |
| Encoding tools | encoding_tool | 1 |
| Log tampering | log_tamper | 1 |
| Audit tampering | audit_tampering | 1 |
| History tampering | history_tamper | 2 |
| Secure delete | secure_delete | 2 |
| Forwarder tampering | forwarder_tamper | 2 |
| Timestamp tampering | timestamp_tamper | 1 |
| Shadow access | shadow_access | 1 |
| Passwd read | passwd_read | 1 |
| Group read | group_read | 1 |
| Network config read | network_config_read | 2 |
| Home directory read | homedir_read | 1 |
| User creation | user_creation | 3 |
| Passwd changes | passwd_changes | 1 |
| Sudo changes | sudo_changes | 1 |
| Sudoers change | sudoers_change | 1 |
| Staging write | staging_write | 3 |
| Binary modification | binary_modification | 4 |
| Library modification | library_modification | 4 |
| Environment modification | env_modification | 1 |
| Process creation | process_creation | 2 |
| Auth log read | auth_log_read | 2 |
| SSH key access | ssh_key_access | 2 |
| SUID execution | suid_exec | 1 |
| Auditd binary exec | auditd_binary_exec | 1 |
| Auditd config tamper | auditd_config_tamper | 1 |
| Auditd rules tamper | auditd_rules_tamper | 1 |
| Systemctl execution | systemctl_exec | 1 |
| Sudo execution | sudo_exec | 1 |
| SUID find | suid_find | 1 |
| Shadow changes | shadow_changes | 1 |
| Exfil tool | exfil_tool | 2 |
| Setuid call | setuid_call | 1 |
| Ptrace call | ptrace_call | 1 |
| Module load | module_load | 4 |
| Capability set | capability_set | 2 |
| Proc sensitive read | proc_sensitive_read | 2 |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 15 (4 Project 15 + 5 Project 2 gaps + 6 Eva recommendations) |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 4 |
| Confidence Range | 0.75 – 1.0 |

## Why This Project Matters

Anti-detection is the final phase of a sophisticated attack. An attacker who disables auditd before exfiltrating data, deletes rules before escalating privileges, or floods the audit buffer during lateral movement has specifically identified and neutralized BLIP-AI's detection capability. This isn't opportunistic — it's deliberate counter-security operations.

The meta-detection insight: if an attacker is tampering with auditd, it means every other alert in BLIP-AI may have been suppressed. Detection 3's combined score firing means the attacker has likely already completed other attack phases without generating alerts. The anti-detection detection is therefore both a final defense and a retrospective indicator that earlier activity may have gone undetected.

---

## Phase 1 — Infrastructure

### New auditd Rules — Project 15

```bash
sudo auditctl -w /sbin/auditd -p x -k auditd_binary_exec
sudo auditctl -w /etc/audit/auditd.conf -p wa -k auditd_config_tamper
sudo auditctl -w /etc/audit/rules.d -p wa -k auditd_rules_tamper
sudo auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/systemctl -k systemctl_exec
```

### Additional Rules — Eva Recommendations

```bash
# setuid/setgid syscall monitoring
sudo auditctl -a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -F auid!=4294967295 -k setuid_call

# ptrace process injection
sudo auditctl -a always,exit -F arch=b64 -S ptrace -F auid!=4294967295 -k ptrace_call

# kernel module loading
sudo auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
sudo auditctl -w /sbin/insmod -p x -k module_load
sudo auditctl -w /sbin/modprobe -p x -k module_load
sudo auditctl -w /sbin/rmmod -p x -k module_load

# capabilities manipulation
sudo auditctl -a always,exit -F arch=b64 -S capset -F auid!=4294967295 -k capability_set
sudo auditctl -w /usr/sbin/setcap -p x -k capability_set

# /proc sensitive reads — tightly scoped
sudo auditctl -w /proc/kcore -p r -k proc_sensitive_read
sudo auditctl -w /proc/sysrq-trigger -p wa -k proc_sensitive_read
```

### Missing Project 2 Rules Added

```bash
sudo auditctl -w /usr/bin/sudo -p x -k sudo_exec
sudo auditctl -w /usr/bin/find -p x -k suid_find
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -w /usr/bin/nc -p x -k exfil_tool
sudo auditctl -w /usr/bin/scp -p x -k exfil_tool
```

### Rule Persistence

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Final count: 83
```

**Important note — auditctl -D incident:**
During the Project 15 attack simulation, `auditctl -D` deleted all in-memory rules. The subsequent `auditctl -l | tee blip-ai.rules` command overwrote the rules file with "No rules". Recovery required recreating the rules file from scratch using the documented rule set across all 15 projects. This incident directly validated the need for Project 15's detections — and demonstrated exactly how dangerous `auditctl -D` is in practice.

---

## Phase 2 — Attack Simulation

```bash
# Attack 1 — Audit rule deletion
sudo auditctl -D
sleep 1
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd

# Attack 2 — Auditd config tampering
sudo cp /etc/audit/auditd.conf /tmp/auditd.conf.bak
echo "max_log_file = 1" | sudo tee -a /etc/audit/auditd.conf
sudo cp /tmp/auditd.conf.bak /etc/audit/auditd.conf
sudo rm /tmp/auditd.conf.bak

# Attack 3 — systemctl targeting auditd
sudo systemctl stop auditd 2>/dev/null || true
sleep 1
sudo systemctl start auditd

# Attack 4 — Rules file tampering
sudo touch /etc/audit/rules.d/test.rules
sudo rm /etc/audit/rules.d/test.rules
echo "# test" | sudo tee -a /etc/audit/auditd.conf
sudo sed -i '/# test/d' /etc/audit/auditd.conf
```

**What auditd recorded:**
- `audit_tampering` — auditctl, tee, sed, cp, rm, touch, python3 writing to /etc/audit ✅

<img width="1306" height="871" alt="Screenshot 2026-06-30 at 5 06 55 PM" src="https://github.com/user-attachments/assets/d472ee9e-9a47-4276-a116-327e6a0bd1dc" />


---

## Phase 3 — Detections

### Detection 1 — Audit Configuration Tampering Detected

**Description:** Detects interactive writes to `/etc/audit/` excluding auditctl itself. PATH records confirm specific files affected. Rules directory modifications score higher — deleting or replacing rules files directly blinds the detection platform. Scripting languages writing to the rules directory score 0.95 CRITICAL.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Evidence Weight:** 0.95 CRITICAL

```spl
index=main sourcetype=linux_audit earliest=-60m
"audit_tampering" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="auditctl"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=PATH"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^/etc/audit/")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval tamper_type=case(
    match(mvjoin(filepath," "),"auditd\.conf"), "config_file_modified",
    match(mvjoin(filepath," "),"rules\.d/"), "rules_file_modified",
    true(), "audit_dir_modified"
)
| eval evidence_weight=case(
    tamper_type="rules_file_modified" AND match(comm,"^(rm|python3|perl|bash|sh)$"), 0.95,
    tamper_type="rules_file_modified", 0.90,
    tamper_type="config_file_modified", 0.85,
    true(), 0.75
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(tamper_type) as tamper_types
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Audit Configuration Tampering Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count tools_used tamper_types files_affected first_seen last_seen
```

<img width="1250" height="466" alt="Screenshot 2026-06-30 at 5 06 22 PM" src="https://github.com/user-attachments/assets/933f5cdc-49f7-4552-9ad3-f28968b840d4" />


**Alert Settings:**
- Title: `Audit Configuration Tampering Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Audit Rule Deletion and Evasion Detected

**Description:** Detects interactive auditctl executions from any session. PROCTITLE classifies evasion technique — auditd disabled (-e 0) scores 0.98, delete all rules (-D) scores 0.95, delete single rule (-d) scores 0.90, buffer manipulation scores 0.90. Any interactive auditctl invocation scores minimum 0.75 HIGH — legitimate auditctl use is scripted at boot, not interactive.

**MITRE:** T1562.001 — Impair Defenses, T1562.006 — Impair Defenses: Indicator Blocking

**Evidence Weight:** 0.75+ (scales with evasion technique)

```spl
index=main sourcetype=linux_audit earliest=-60m
"audit_tampering" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm="auditctl"
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
| eval action_type=case(
    has_proctitle=1 AND match(mvjoin(decoded," "),"-e\s+0\b"), "auditd_disabled",
    has_proctitle=1 AND match(mvjoin(decoded," ")," -D(\s|$)"), "delete_all_rules",
    has_proctitle=1 AND match(mvjoin(decoded," ")," -d\s"), "delete_single_rule",
    has_proctitle=1 AND match(mvjoin(decoded," "),"--backlog-wait-time 0|rate.limit"), "buffer_manipulation",
    has_proctitle=1, "auditctl_interactive",
    true(), "auditctl_unknown"
)
| eval evidence_weight=case(
    action_type="auditd_disabled", 0.98,
    action_type="delete_all_rules", 0.95,
    action_type="delete_single_rule", 0.90,
    action_type="buffer_manipulation", 0.90,
    action_type="auditctl_interactive", 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(decoded) as commands_run
    values(action_type) as actions
    max(has_proctitle) as has_proctitle
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval detection="Audit Rule Deletion and Evasion Detected"
| eval severity=case(evidence_weight>=0.95,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host event_count actions commands_run first_seen last_seen
```

<img width="1249" height="474" alt="Screenshot 2026-06-30 at 5 09 34 PM" src="https://github.com/user-attachments/assets/a6859bdf-3704-4ea7-8fb7-019bb0759393" />


**Alert Settings:**
- Title: `Audit Rule Deletion and Evasion Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 3 — Combined Anti-Detection and Audit Evasion Score

**Description:** Correlates audit rule manipulation, config file tampering, Splunk forwarder tampering, and log deletion in the same session. Two or more techniques confirms deliberate coordinated attack on the detection infrastructure. Normalized weighted scoring with 0.75 minimum confidence gate.

**MITRE:** T1562.001, T1562.006, T1070 — Indicator Removal, T1485 — Data Destruction

**Confidence:** 1.0 CRITICAL

```spl
index=main sourcetype=linux_audit earliest=-60m
("audit_tampering" OR "forwarder_tamper" OR "log_tamper") "type=SYSCALL"
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
    key="audit_tampering" AND comm="auditctl", "audit_rule_manipulation",
    key="audit_tampering" AND match(comm,"^(tee|sed|cp|rm|touch|python3?|perl|bash|sh)$"), "audit_config_tampering",
    key="forwarder_tamper" AND match(comm,"^(cp|mv|rm|tee|sed|vi|vim|nano)$"), "forwarder_tampering",
    key="log_tamper" AND match(comm,"^(rm|shred|truncate|tee|sed)$"), "log_tampering",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="audit_rule_manipulation", 0.90,
    technique="audit_config_tampering", 0.90,
    technique="forwarder_tampering", 0.85,
    technique="log_tampering", 0.80,
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
| eval detection="Combined Anti-Detection and Audit Evasion Score"
| eval description="Multiple audit system attack techniques detected in same session. Audit rule manipulation combined with config tampering or log deletion confirms deliberate SIEM evasion."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen description
```

<img width="1249" height="474" alt="Screenshot 2026-06-30 at 5 11 15 PM" src="https://github.com/user-attachments/assets/d40313c7-56b1-4f3d-86ab-73e63672ce7f" />


**Alert Settings:**
- Title: `Combined Anti-Detection and Audit Evasion Score`
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
| 1 — Audit Configuration Tampering | ✅ | ✅ audit_tampering tee/sed/cp/rm | ✅ 1 row, 0.95 CRITICAL | ✅ |
| 2 — Audit Rule Deletion and Evasion | ✅ | ✅ audit_tampering auditctl | ✅ 1 row, 0.75 HIGH | ✅ (2 review cycles) |
| 3 — Combined Anti-Detection Score | ✅ | ✅ both technique categories | ✅ 1 row, 1.0 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| systemctl_exec broken on kernel 6.8.0-124 | Cannot detect auditd stop/start via dedicated key | Monitor proc_exec comm=systemctl + PROCTITLE decode |
| auditctl -D wipes all rules before detection fires | The attack succeeds before the detection triggers | Immutable rules mode (-e 2) in production |
| No detection of kernel-level auditd bypass | eBPF-based audit bypass not detectable via auditd | eBPF monitoring in V2 |
| Forwarder tamper detection relies on file watches | Attacker stopping splunkd process not caught | Process monitoring via systemd + proc_exec |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Impair Defenses: Disable or Modify Tools | T1562.001 | Detection 1, 2, 3 |
| Impair Defenses: Indicator Blocking | T1562.006 | Detection 2, 3 |
| Indicator Removal | T1070 | Detection 3 |
| Data Destruction | T1485 | Detection 3 |

---

## Domain 1 Complete — Summary

| Project | Title | Detections | Rules Added |
|---|---|---|---|
| 01 | Linux Privilege Escalation | 3 | 0 |
| 02 | OPNsense Network Visibility | — | 17 |
| 03 | Linux Persistence Detection | 5 | 30 |
| 04 | Web Application Attacks | — | — |
| 05 | Reverse Shell Detection | 6 | 12 |
| 06 | Anti-Forensics Detection | 8 | 9 |
| 07 | Internal Reconnaissance | 4 | 6 |
| 08 | Lateral Movement | 3 | 0 |
| 09 | User and Account Manipulation | 3 | 1 |
| 10 | Sensitive File and Collection Staging | 3 | 3 |
| 11 | Data Exfiltration | 3 | 0 |
| 12 | Service and Binary Modification | 3 | 9 |
| 13 | Resource and Stability Anomaly | 3 | 2 |
| 14 | Credential Access and Privilege Abuse | 3 | 5 |
| 15 | Anti-Detection and Audit Evasion | 3 | 15 |
| **Total** | | **52 detections** | **83 rules** |

---
