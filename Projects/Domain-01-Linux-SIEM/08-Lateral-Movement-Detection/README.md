# Project 08 — Lateral Movement Detection

## Overview

This project builds behavioral detections around lateral movement — the phase where an attacker who has already compromised one host attempts to spread to other systems in the network. Where previous projects detected the attacker landing and mapping their environment, Project 8 detects when they start moving.

Three detections were built: an outbound SSH pivot detector that catches a compromised server initiating connections to internal hosts, an internal network scanner that identifies subnet reconnaissance from a compromised host, and a host-scoped combined behavioral score that correlates both signals within a 60-minute window.

A key architectural discovery this project: EXECVE records in auditd do not carry `auid`, `ses`, or `tty` fields — only SYSCALL records do. This prevented session-scoped correlation for scanning tools and required a shift to host-scoped correlation for the combined detection.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Hypervisor | Proxmox VE 9.1.1 on Dell OptiPlex 7060 Micro |
| Attacker | Kali Linux (VM 100) — 10.10.10.132 |
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | auditd → Splunk Universal Forwarder → index=main |
| auditd Rules | 68 total (0 net new — existing proc_exec key used) |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 3 |
| auditd Rules Added | 0 (proc_exec from Project 6 provides all telemetry) |
| Attack Simulations Run | 3 |
| Splunk Alerts Saved | 3 |
| MITRE Techniques Covered | 3 |
| Confidence Range | 0.85 – 0.935 |

## Why This Project Matters

Lateral movement is where single-host compromise becomes network compromise. An attacker who only owns one machine is contained. An attacker who can move to a domain controller, a backup server, or a database host has achieved their objective.

The critical detection insight is directional awareness: servers receive SSH connections, they don't initiate them. When Ubuntu starts making outbound SSH connections to other internal hosts, the direction has reversed — that reversal is the signal. Combined with internal network scanning on the same host, the behavioral pattern is unambiguous: an attacker has a foothold and is preparing to expand.

This project also surfaced an important architectural lesson for BLIP-AI V2: EXECVE records don't carry session context. Future multi-signal correlations that mix SYSCALL and EXECVE telemetry must use host-scoped or time-window correlation rather than session-scoped correlation.

---

## Phase 1 — Infrastructure

### auditd Rules

No new rules were added this project. The existing `proc_exec` key from Project 6 captures all necessary telemetry:

- SSH, SCP, SFTP execution via SYSCALL records — `comm` field
- nmap execution via both SYSCALL and EXECVE records — `comm` and `a0` fields

**Key discovery — `-F exe=` filter broken on kernel 6.8.0-110:**

Binary-specific execve rules using `-F exe=` were initially added but failed to fire. Diagnosis via `strace` confirmed the kernel was executing the correct binary path but auditd wasn't matching the filter. This is a known issue with `-F exe=` on some kernel versions. Rules were removed and the broad `proc_exec` key with SPL-level filtering was used instead.

**Key discovery — EXECVE records lack session context:**

nmap EXECVE records do not carry `auid`, `ses`, or `tty` fields. These fields only exist on SYSCALL records. This prevented session-scoped correlation and required the combined score to use host-scoped correlation instead.

---

## Phase 2 — Attack Simulations

### Attack 1 — SSH Pivot (Ubuntu initiating outbound SSH to Kali)

```bash
ssh kali@10.10.10.132
```

Simulates a compromised Ubuntu server being used as a launchpad to SSH into other internal hosts. The direction matters — Ubuntu is receiving connections normally. Ubuntu initiating outbound SSH is the attacker pivoting.

### Attack 2 — Internal Network Scanning

```bash
sudo nmap -sS 10.10.10.0/24
```

Simulates an attacker using nmap from the compromised host to map the internal network before moving laterally. Identifies live hosts and open ports on the 10.10.10.0/24 subnet.

### Attack 3 — SSH Recon Tools

```bash
ssh-keyscan 10.10.10.132
sshpass -p 'password123' ssh kali@10.10.10.132
```

Simulates credential reuse and host key harvesting — tools an attacker uses to automate lateral movement across multiple hosts.

---

## Phase 3 — Detections

### Detection 1 — Outbound SSH Pivot Detected

**Description:** Detects SSH, SCP, and SFTP executions initiated from interactive sessions on this host. Decodes PROCTITLE hex to extract the target host from command arguments and scores higher for internal RFC1918 destinations. A server initiating outbound SSH to internal hosts indicates lateral movement from a compromised host.

**MITRE:** T1021.004 — Remote Services: SSH

**Evidence Weight:** 0.935 CRITICAL

**Why PROCTITLE join:** SSH PROCTITLE records don't carry `auid` or `ses` — only SYSCALL records do. The PROCTITLE join via `event_id` retrieves session context from the matching SYSCALL record, enabling session-scoped correlation.

```spl
index=main sourcetype=linux_audit earliest=-60m latest=now
"type=PROCTITLE"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\1")))
| where match(decoded,"^(ssh|scp|sftp)\s")
| rex field=decoded "(?:ssh|scp|sftp)\s+(?:-[^\s]+\s+)*?(?:(?:[^@\s]+)@)?(?P<target_host>[^\s:]+)"
| eval internal_target=if(
    match(target_host,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"),
    1, 0
)
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=SYSCALL"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "auid=(?P<auid>\d+)"
    | rex field=_raw "ses=(?P<ses>\d+)"
    | rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
    | rex field=_raw "tty=(?P<tty>\S+)"
    | rex field=_raw "success=(?P<success>\w+)"
    | where comm IN ("ssh","scp","sftp")
    | where auid!=4294967295
    | where tty!="(none)"
    | where success="yes" OR success="1"
    | table event_id auid ses comm tty success
]
| where isnotnull(auid)
| stats
    count as connection_attempts
    dc(target_host) as unique_targets
    values(comm) as tools_used
    values(decoded) as commands_run
    values(target_host) as target_hosts
    max(internal_target) as internal_target
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    unique_targets>=3, 0.95,
    unique_targets=2, 0.90,
    internal_target=1 AND connection_attempts>=3, 0.95,
    internal_target=1, 0.85,
    isnotnull(target_hosts), 0.70,
    true(), 0.60
)
| eval detection="Outbound SSH Pivot Detected"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.80,"HIGH",evidence_weight>=0.70,"MEDIUM",true(),"LOW")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host connection_attempts unique_targets tools_used target_hosts commands_run first_seen last_seen
```

<img width="1270" height="427" alt="Screenshot 2026-06-08 at 4 09 40 PM" src="https://github.com/user-attachments/assets/a5b6ef8b-415d-4989-a55f-a7f634e1ea13" />

**Alert Settings:**
- Title: `Outbound SSH Pivot Detected`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Internal Network Scan from Compromised Host

**Description:** Detects network scanning tools (nmap, masscan, arp-scan) executed from interactive sessions on this host. Uses EXECVE records to extract structured command arguments — specifically the scan tool name (`a0`) and target subnet (`a2`) — then joins to SYSCALL records via event_id to get session context. Scores higher when the target is an internal RFC1918 address.

**MITRE:** T1046 — Network Service Discovery

**Evidence Weight:** 0.85 HIGH

**Why EXECVE records:** nmap PROCTITLE records were not shipping from the forwarder consistently due to audit log rotation timing. EXECVE records provide the same argument visibility (`a0`, `a1`, `a2`) with reliable delivery and are present in Splunk regardless of PROCTITLE shipping issues.

```spl
index=main sourcetype=linux_audit earliest=-60m latest=now
"type=EXECVE"
| rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
| rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
| rex field=_raw "a1=\"(?P<a1>[^\"]+)\""
| rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
| where a0 IN ("nmap","masscan","arp-scan","netdiscover")
| eval scan_target=coalesce(a2,a1)
| eval internal_target=if(
    match(scan_target,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"),
    1, 0
)
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest=-60m latest=now "type=SYSCALL"
    | rex field=_raw "msg=audit\([^:]+:(?P<event_id>\d+)\)"
    | rex field=_raw "auid=(?P<auid>\d+)"
    | rex field=_raw "ses=(?P<ses>\d+)"
    | rex field=_raw "tty=(?P<tty>\S+)"
    | rex field=_raw "success=(?P<success>\w+)"
    | rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
    | where auid!=4294967295
    | where success="yes" OR success="1"
    | table event_id auid ses tty comm success
]
| where isnotnull(auid)
| stats
    count as scan_count
    values(a0) as tools_used
    values(scan_target) as targets_scanned
    dc(scan_target) as unique_targets
    max(internal_target) as internal_target
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    internal_target=1 AND unique_targets>=2, 0.95,
    internal_target=1, 0.85,
    unique_targets>=2, 0.75,
    isnotnull(targets_scanned), 0.70,
    true(), 0.60
)
| eval detection="Internal Network Scan from Compromised Host"
| eval severity=case(evidence_weight>=0.90,"CRITICAL",evidence_weight>=0.80,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity evidence_weight auid ses host scan_count unique_targets tools_used targets_scanned first_seen last_seen
```

<img width="1270" height="427" alt="Screenshot 2026-06-08 at 4 20 07 PM" src="https://github.com/user-attachments/assets/22286d1c-fb11-4dba-997b-829083eb22d7" />


**Alert Settings:**
- Title: `Internal Network Scan from Compromised Host`
- Permissions: Shared in App
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 3 — Combined Lateral Movement Behavioral Score

**Description:** Correlates outbound SSH pivoting and internal network scanning on the same host within a 60-minute window. EXECVE records for scanning tools don't carry session context (auid, ses, tty) so correlation is host-scoped rather than session-scoped. Both techniques firing on the same host within the window confirms active lateral movement preparation.

**MITRE:** T1021.004 — Remote Services: SSH, T1046 — Network Service Discovery, T1570 — Lateral Tool Transfer

**Confidence:** 0.935 CRITICAL

**Architectural note — host-scoped vs session-scoped:** EXECVE records do not carry `auid`, `ses`, or `tty` fields. Session-scoped correlation (`by auid ses host`) was attempted but nmap EXECVE records always grouped separately from SSH SYSCALL records, making technique_count >= 2 impossible. Host-scoped correlation within a 60-minute window achieves the same detection goal while working within auditd's record type constraints. V2 improvement: use `transaction event_id` to link EXECVE and SYSCALL records before correlation.

```spl
index=main sourcetype=linux_audit earliest=-60m latest=now
("type=SYSCALL" OR "type=EXECVE")
| rex field=_raw "type=(?P<record_type>\w+)"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| rex field=_raw "tty=(?P<tty>\S+)"
| rex field=_raw "success=(?P<success>\w+)"
| rex field=_raw "comm=\"(?P<comm>[^\"]+)\""
| rex field=_raw "a0=\"(?P<a0>[^\"]+)\""
| rex field=_raw "a2=\"(?P<a2>[^\"]+)\""
| eval ssh_pivot=if(record_type="SYSCALL" AND comm IN ("ssh","scp","sftp") AND auid!=4294967295 AND tty!="(none)" AND (success="yes" OR success="1"), 1, 0)
| eval internal_scan=if(record_type="EXECVE" AND a0 IN ("nmap","masscan","arp-scan","netdiscover") AND match(a2,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"), 1, 0)
| where ssh_pivot=1 OR internal_scan=1
| eval auid=if(isnull(auid) OR auid="4294967295", "unknown", auid)
| stats
    sum(ssh_pivot) as ssh_pivot_count
    sum(internal_scan) as scan_count
    min(_time) as first_seen
    max(_time) as last_seen
    by host
| where ssh_pivot_count > 0 AND scan_count > 0
| eval technique_count=2
| eval techniques_detected="ssh_pivot, internal_scan"
| eval combined_confidence=0.935
| eval severity="CRITICAL"
| eval detection="Combined Lateral Movement Behavioral Score"
| eval description="SSH pivoting and internal network scanning detected on same host within 60 minutes. Outbound SSH to internal hosts combined with subnet scanning confirms active lateral movement preparation."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence host technique_count techniques_detected ssh_pivot_count scan_count first_seen last_seen description
```

<img width="1270" height="427" alt="Screenshot 2026-06-08 at 4 28 14 PM" src="https://github.com/user-attachments/assets/7c4a78c5-4d70-4605-9e16-f6e31cbaf400" />


**Alert Settings:**
- Title: `Combined Lateral Movement Behavioral Score`
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
| 1 — Outbound SSH Pivot | ✅ | ✅ ssh comm in proc_exec | ✅ 1 row, 0.935 CRITICAL | ✅ |
| 2 — Internal Network Scan | ✅ | ✅ nmap EXECVE a0/a2 fields | ✅ 1 row, 0.85 HIGH | ✅ |
| 3 — Combined Lateral Movement Score | ✅ | ✅ both techniques on same host | ✅ 1 row, 0.935 CRITICAL | ✅ |

---

## Known Limitations

| Limitation | Impact | V2 Fix |
|---|---|---|
| `-F exe=` broken on kernel 6.8.0-110 | Binary-specific execve rules don't fire | Upgrade kernel or use watch rules with `-w` |
| EXECVE records lack session context | Combined score is host-scoped not session-scoped | Use `transaction event_id` to link EXECVE to SYSCALL before correlation |
| PROCTITLE records not shipping after log rotation | nmap target extraction via PROCTITLE unreliable | Fix forwarder to handle log rotation via `followTail=false` in inputs.conf |
| SSH pivot detection uses join | Expensive at scale, 50k row limit | Replace with `transaction event_id` in V2 |
| sshpass detection requires sshpass installed | Not installed by default | Add to detection documentation as gap |
| No detection of bash /dev/tcp lateral movement | Built-in bash networking bypasses binary detection | eBPF socket monitoring in V2 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Remote Services: SSH | T1021.004 | Detection 1, 3 |
| Network Service Discovery | T1046 | Detection 2, 3 |
| Lateral Tool Transfer | T1570 | Detection 1 (SCP) |

---

## Key Technical Lessons

**Lesson 1 — `-F exe=` filter on execve rules:**
Rules using `-F exe=/usr/bin/ssh -S execve` did not fire on kernel 6.8.0-110 despite the binary executing at the exact specified path (verified via strace). The `-F path=` filter has a similar issue — it matches PATH records, not the executing binary. For binary-specific monitoring on this kernel, use the broad `proc_exec` key with SPL-level filtering on `exe=` or `comm=` fields.

**Lesson 2 — EXECVE records lack session context:**
auditd EXECVE records (`type=EXECVE`) contain command arguments (`a0`, `a1`, `a2`) but do not carry `auid`, `ses`, or `tty` fields. These fields only exist on `type=SYSCALL` records. Any correlation requiring session identity must either join EXECVE to SYSCALL via `event_id` or use a broader scope (host, time window) for correlation.

**Lesson 3 — PROCTITLE shipping after log rotation:**
After audit.log rotates, the Splunk forwarder may miss records written to the new file until it's restarted. This caused nmap PROCTITLE records to not appear in Splunk despite being present in the audit log. EXECVE records were a reliable alternative. Long-term fix: configure forwarder inputs with `followTail=false` to ensure it reads from the beginning of new rotated files.
