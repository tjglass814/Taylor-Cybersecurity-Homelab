# Project 07 — Internal Reconnaissance Detection

## Overview

This project builds behavioral detections around post-exploitation internal reconnaissance — the systematic enumeration an attacker performs immediately after gaining access to a system. Where previous projects detected the initial compromise and execution phases, Project 7 detects what happens next: the attacker mapping their environment before moving laterally.

Four detections were built covering credential file harvesting, network topology discovery, sensitive file hunting, and a multi-signal session correlation engine. The core detection philosophy is categorical intelligence — not just counting commands, but classifying what type of reconnaissance is happening and scoring based on the combination of categories observed in a single session.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| Attacker | Kali Linux (VM 100) — 10.10.10.132 |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 68 total (6 net new this project) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 4 |
| auditd Rules Added | 6 |
| Attack Simulations Run | 1 |
| Splunk Alerts Saved | 4 |
| MITRE Techniques Covered | 6 |
| Confidence Range | 0.75 – 1.0 |

## Why This Project Matters

Internal reconnaissance is the phase most SIEM platforms miss entirely. Brute force, privilege escalation, and reverse shells are noisy and well-understood. An attacker quietly reading `/etc/shadow`, mapping the network with `ip route`, and hunting for SSH keys generates almost no traffic and no authentication events — it's entirely host-based behavioral signal.

The multi-signal correlation in Detection 4 demonstrates a core detection engineering principle: individual signals are informative, correlated signals within the same session are confirmatory. An attacker who touches credential files AND maps the network AND hunts for SSH keys has executed a complete reconnaissance operation. That three-category combination is the high-confidence signal that justifies autonomous investigation.

---

## Phase 1 — Infrastructure

### New auditd Rules

Six rules added across four new keys:

```bash
# Sensitive credential file reads
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F path=/etc/passwd -F perm=r -k passwd_read
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F path=/etc/group -F perm=r -k group_read

# SSH key directory access
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F dir=/root/.ssh -F perm=r -k ssh_key_read
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F dir=/home -F perm=r -k homedir_read

# Network configuration reads
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F path=/etc/hosts -F perm=r -k network_config_read
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F path=/etc/resolv.conf -F perm=r -k network_config_read
```

**Key architectural note:** `/etc/shadow` reads are captured by the existing `shadow_access` key from Project 3 (`-w /etc/shadow -p r`). A new `shadow_read` rule was initially added but caused a conflict — auditd watch rules take priority over `-a always,exit` rules on the same file. The duplicate was removed and `shadow_access` is used directly in SPL.

**Rule persistence:**

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Expected: 68
```

---

## Phase 2 — Attack Simulation

Simulates complete internal reconnaissance — the full sequence an attacker executes after landing on a system to map their environment before moving laterally.

```bash
# Identity and account enumeration
cat /etc/passwd
cat /etc/group
getent passwd
sudo cat /etc/shadow
id
whoami
last
w
who

# System and network discovery
uname -a
hostname
ip route
arp -a
ss -tnp
cat /etc/hosts
cat /etc/resolv.conf

# Sensitive file discovery
ls -la /root/.ssh/ 2>/dev/null
ls -la /home/labadmin/.ssh/
find / -name "*.env" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
```

**Key observation:** `find / -name "id_rsa"` generates thousands of `homedir_read` records as it traverses `/home` — one record per file touched. The attacker command itself is captured in PROCTITLE records tagged with `homedir_read`, not in a dedicated execution key. This required PROCTITLE decode + join approach for Detection 3.

---

## Phase 3 — Detections

### Detection 1 — Credential File Enumeration

**Description:** Detects interactive sessions accessing `/etc/shadow`, `/etc/passwd`, or `/etc/group` using known file inspection tools. Multiple credential files accessed in the same session indicates systematic credential harvesting.

**MITRE:** T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow, T1087.001 — Account Discovery: Local Account

**Evidence Weight:** 0.95 CRITICAL

**Why 0.95:** Accessing all three credential files (`/etc/shadow` + `/etc/passwd` + `/etc/group`) in the same session with inspection tools like `cat` and `getent` is a complete credential enumeration operation. The multi-file bonus pushes the base weight of 0.85 to 0.95. False positive risk is low — legitimate admin work rarely requires reading all three files back-to-back with `cat`.

```spl
index=main sourcetype=linux_audit earliest=-60m
"type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw " uid=(?P<uid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where success="yes" OR success="1"
| where key IN ("shadow_access","passwd_read","group_read")
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(cat|getent|less|more|strings|grep|awk|head|tail)$")
| eval file_accessed=case(
    key="shadow_access", "/etc/shadow",
    key="passwd_read", "/etc/passwd",
    key="group_read", "/etc/group",
    true(), "unknown"
)
| eval technique_weight=case(
    key="shadow_access", 0.85,
    key="passwd_read", 0.70,
    key="group_read", 0.65,
    true(), 0.50
)
| stats
    dc(file_accessed) as files_accessed
    values(file_accessed) as files
    values(comm) as tools_used
    max(technique_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    files_accessed>=3, min(base_weight + 0.10, 1.0),
    files_accessed=2, min(base_weight + 0.05, 1.0),
    true(), base_weight
)
| eval detection="Credential File Enumeration"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host files_accessed files tools_used first_seen last_seen
```

<img width="1270" height="809" alt="Screenshot 2026-06-03 at 5 18 07 PM" src="https://github.com/user-attachments/assets/484f7697-ab36-494d-9469-77b28d02f124" />

<img width="1270" height="258" alt="Screenshot 2026-06-03 at 5 28 26 PM" src="https://github.com/user-attachments/assets/5b2316b5-9c20-4c4c-9880-ee911100c262" />

**Alert Settings:**
- Title: `Credential File Enumeration Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Network Discovery Activity

**Description:** Detects network topology mapping behavior combining network tool execution (`ip`, `ss`, `arp`, `netstat`) and network configuration file reads (`/etc/hosts`, `/etc/resolv.conf`). Both signal types in the same session indicates systematic network discovery.

**MITRE:** T1016 — System Network Configuration Discovery, T1018 — Remote System Discovery

**Evidence Weight:** 0.75 HIGH

**Why 0.75:** Individual network commands are common admin activity. The behavioral signal is the combination — running network tools AND reading network config files in the same session means the attacker is building a complete network picture. Single signal alone stays at 0.60, both signals together bump to 0.75.

```spl
index=main sourcetype=linux_audit earliest=-60m
"type=SYSCALL"
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
| where (
    (key="proc_exec" AND match(comm,"^(ip|arp|ss|netstat|ifconfig|route|ping|traceroute|dig|nslookup|host|nmap)$") AND NOT match(exe,"^/opt/splunk"))
    OR
    (key="network_config_read" AND match(comm,"^(cat|less|more|grep|strings|awk|head|tail)$"))
)
| eval signal_type=case(
    key="proc_exec", "network_tool_execution",
    key="network_config_read", "network_config_read",
    true(), "unknown"
)
| eval signal_weight=case(
    signal_type="network_tool_execution", 0.60,
    signal_type="network_config_read", 0.55,
    true(), 0.40
)
| stats
    dc(signal_type) as signal_count
    values(signal_type) as signals_detected
    values(comm) as commands_run
    max(signal_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    signal_count>=2, min(base_weight + 0.15, 1.0),
    true(), base_weight
)
| eval detection="Network Discovery Activity Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host signal_count signals_detected commands_run first_seen last_seen
```

<img width="1270" height="248" alt="Screenshot 2026-06-03 at 5 30 00 PM" src="https://github.com/user-attachments/assets/b03df958-38ea-4fd9-8dd4-8a58828e1e62" />


**Alert Settings:**
- Title: `Network Discovery Activity Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 3 — Sensitive File Discovery

**Description:** Detects credential hunting behavior by decoding PROCTITLE command arguments to identify searches for SSH keys, certificates, cloud credentials, and password files. Combines PROCTITLE argument inspection with tool-awareness weighting.

**MITRE:** T1552.001 — Unsecured Credentials: Credentials in Files, T1083 — File and Directory Discovery

**Evidence Weight:** 1.0 CRITICAL

**Why this detection uses PROCTITLE join:** The `find / -name id_rsa` command generates thousands of `homedir_read` records — one per file touched during traversal. The command arguments are only visible in the PROCTITLE record tied to the original execution via event_id. A join is required to get session context (auid, ses, tty) from the matching SYSCALL record. Eva flagged this for V2 refactor using `transaction event_id` for scalability.

```spl
index=main sourcetype=linux_audit earliest=-60m
"type=PROCTITLE"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1"))
| eval decoded=lower(decoded)
| where match(decoded,"(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|\.pem|\.pfx|\.p12|\.kdbx|aws|credentials|\.env|secret|token|password|credential|vault|\.ssh)")
| where NOT match(decoded,"auditctl")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=SYSCALL"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "auid=(?P<auid>\d+)"
    | rex field=_raw "ses=(?P<ses>\d+)"
    | rex field=_raw "tty=(?P<tty>\S+)"
    | rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
    | rex field=_raw "success=(?P<success>\w+)"
    | where tty!="(none)"
    | where auid!=4294967295
    | where success="yes" OR success="1"
    | where comm!="auditctl"
    | where match(comm,"^(find|grep|locate|ls|tree|cat|less|more|strings|awk|head|tail)$")
    | table event_id auid ses tty comm success
]
| where isnotnull(auid)
| eval signal_type=case(
    match(decoded,"(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts)"), "ssh_key_hunt",
    match(decoded,"\.ssh"), "ssh_dir_hunt",
    match(decoded,"(\.pem|\.pfx|\.p12|\.kdbx)"), "cert_key_hunt",
    match(decoded,"(aws|credentials)"), "cloud_credential_hunt",
    match(decoded,"(\.env|secret|token|api.key|credential|password|vault)"), "credential_file_hunt",
    true(), "sensitive_file_hunt"
)
| eval tool_weight=case(
    comm="find", 0.15,
    comm="grep", 0.10,
    comm="locate", 0.10,
    comm="ls", 0.05,
    comm="tree", 0.05,
    true(), 0.0
)
| eval signal_weight=case(
    signal_type="ssh_key_hunt", 0.80,
    signal_type="cert_key_hunt", 0.80,
    signal_type="cloud_credential_hunt", 0.80,
    signal_type="ssh_dir_hunt", 0.75,
    signal_type="credential_file_hunt", 0.80,
    true(), 0.60
)
| eval combined_weight=min(signal_weight + tool_weight, 1.0)
| stats
    dc(signal_type) as signal_count
    values(signal_type) as signals_detected
    values(comm) as commands_run
    values(decoded) as search_patterns
    max(combined_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    signal_count>=3, min(base_weight + 0.10, 1.0),
    signal_count=2, min(base_weight + 0.05, 1.0),
    true(), base_weight
)
| eval detection="Sensitive File Discovery Detected"
| eval severity=case(evidence_weight>=0.85,"CRITICAL",evidence_weight>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host signal_count signals_detected commands_run search_patterns first_seen last_seen
```


<img width="1270" height="427" alt="Screenshot 2026-06-03 at 5 37 46 PM" src="https://github.com/user-attachments/assets/f514666d-8214-4dab-be62-3ff0ea710c93" />

**Alert Settings:**
- Title: `Sensitive File Discovery Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 4 — Internal Recon Correlation

**Description:** Correlates three SYSCALL-based signals within the same session: credential file enumeration, network tool execution, and network config reads. Two or more distinct technique categories in the same session indicates a systematic reconnaissance operation. Detection 3 (Sensitive File Discovery) scores fed separately into BLIP-AI session confidence.

**MITRE:** T1003.008, T1087.001, T1016, T1018, T1552.001, T1083

**Confidence:** 1.0 CRITICAL (all three techniques present)

**Why session-scoped:** `by auid ses host` ensures we're correlating within the same login session. An admin who reads `/etc/passwd` on Monday and runs `ip route` on Wednesday is not an attacker. An attacker who does both within the same SSH session is building an operational picture.

```spl
index=main sourcetype=linux_audit earliest=-60m
"type=SYSCALL"
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
    key IN ("shadow_access","passwd_read","group_read") AND match(comm,"^(cat|getent|less|more|strings|grep|awk|head|tail)$"), "credential_enumeration",
    key="proc_exec" AND match(comm,"^(ip|arp|ss|netstat|ifconfig|route|ping|traceroute|dig|nslookup|host|nmap)$") AND NOT match(exe,"^/opt/splunk"), "network_tool_execution",
    key="network_config_read" AND match(comm,"^(cat|less|more|grep|strings|awk|head|tail)$"), "network_config_read",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(
        technique="credential_enumeration", 0.85,
        technique="network_tool_execution", 0.70,
        technique="network_config_read", 0.60,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.05, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval detection="Internal Recon Correlation — Credential and Network Signal Correlation"
| eval description="Credential file enumeration and network discovery techniques detected in same session. SYSCALL-based signals only. Detection 3 (Sensitive File Discovery) scores fed separately into BLIP-AI session confidence."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence auid ses host technique_count techniques_detected first_seen last_seen description
```

<img width="1270" height="427" alt="Screenshot 2026-06-03 at 5 43 02 PM" src="https://github.com/user-attachments/assets/3da97d1f-0054-45ab-abd8-8ee9ecf25e7f" />


**Alert Settings:**
- Title: `Internal Recon Correlation — Credential and Network Signal Correlation`
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
| 1 — Credential File Enumeration | ✅ | ✅ shadow_access + passwd_read + group_read | ✅ 1 row, 0.95 CRITICAL | ✅ |
| 2 — Network Discovery Activity | ✅ | ✅ network_config_read + proc_exec | ✅ 1 row, 0.75 HIGH | ✅ |
| 3 — Sensitive File Discovery | ✅ | ✅ homedir_read PROCTITLE decoded | ✅ 1 row, 1.0 CRITICAL | ✅ |
| 4 — Internal Recon Correlation | ✅ | ✅ all 3 technique categories | ✅ 1 row, 1.0 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| Detection 3 uses join | Expensive at scale, 50k row limit | Replace with `transaction event_id` in V2 |
| homedir_read is broad | Fires on every file find touches in /home | Scope to specific sensitive subdirectories |
| auid=1000 removed but single-user lab | Only one real user in lab — multi-user coverage untested | Test with additional user accounts |
| network_tool_execution limited to known tools | New tools (masscan, zmap) not covered | Add to comm regex as tools are discovered |
| Detection 3 not in combined score | PROCTITLE join can't be embedded in stats correlation | Feed D3 evidence_weight into BLIP-AI session model externally |
| bash built-ins not captured | whoami, id as built-ins may not fire in all shells | Document gap, rely on binary execution |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | Detection 1, 4 |
| Account Discovery: Local Account | T1087.001 | Detection 1, 4 |
| System Network Configuration Discovery | T1016 | Detection 2, 4 |
| Remote System Discovery | T1018 | Detection 2, 4 |
| Unsecured Credentials: Credentials in Files | T1552.001 | Detection 3 |
| File and Directory Discovery | T1083 | Detection 3 |
