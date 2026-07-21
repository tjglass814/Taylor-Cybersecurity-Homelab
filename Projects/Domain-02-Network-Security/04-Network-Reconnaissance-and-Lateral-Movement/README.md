# Project 04 — Network Reconnaissance and Lateral Movement Detection

## Overview

This project builds behavioral detections for the attacker's network footprint after initial access — the reconnaissance, host discovery, and lateral movement phases that follow a successful compromise. Using Zeek conn.log telemetry from both lab network interfaces combined with auditd host telemetry, BLIP-AI gains its first complete kill-chain correlation: detecting the full sequence from network scanning through SSH access to command execution on the target host.

A significant infrastructure advancement was also made in this project: Zeek was upgraded from standalone single-interface monitoring to a cluster configuration monitoring both ens18 (lab network) and ens19 (home network/WAN) simultaneously.

## Environment

| Component | Details |
|---|---|
| Host | Ubuntu Server 24.04 (splunk-server) |
| Attacker | Kali Linux 6.18.12 (10.10.10.132) |
| Target | Ubuntu Server (10.10.10.198) |
| Zeek Version | 8.0.9 LTS — cluster mode |
| Monitored Interfaces | ens18 (lab) + ens19 (home/WAN) |
| Attack Tools | nmap 7.98 |
| Splunk Sourcetypes | zeek_conn, linux_audit |

## Project Metrics

| Metric | Value |
|---|---|
| Detections Built | 4 |
| Attack Simulations Run | 6 |
| Zeek Events Captured | 4,117 scan records + SSH sessions |
| Unique Ports Scanned | 946 |
| Eva Review Cycles | 9 total |
| MITRE Techniques Covered | 4 |
| Cross-Domain Detections | 2 |

---

## Phase 1 — Infrastructure Upgrade: Zeek Cluster Mode

### Why the Upgrade Was Needed

Project 3 ran Zeek on ens19 (home network interface) providing visibility into internet traffic and home network devices. When Kali attacks Ubuntu, traffic travels directly between `10.10.10.132` and `10.10.10.198` on the lab segment — this goes through ens18, not ens19. Initial nmap scans generated 0 Zeek events because the scan traffic never crossed the monitored interface.

### Zeek Cluster Configuration

Upgraded from standalone to cluster mode supporting simultaneous dual-interface monitoring:

```bash
sudo tee /opt/zeek/etc/node.cfg << 'EOF'
[manager]
type=manager
host=localhost

[proxy-1]
type=proxy
host=localhost

[worker-ens18]
type=worker
host=localhost
interface=ens18

[worker-ens19]
type=worker
host=localhost
interface=ens19
EOF

sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

<img width="1278" height="874" alt="Screenshot 2026-07-21 at 5 34 40 PM" src="https://github.com/user-attachments/assets/f46d3736-6134-4c1e-b54c-af87ca4358c8" />

**Cluster architecture:**
- Manager — aggregates logs from all workers into `/opt/zeek/logs/current/`
- Proxy — handles inter-node communication
- Worker-ens18 — captures all lab network traffic (Kali↔Ubuntu)
- Worker-ens19 — captures home network and WAN traffic

**Key discovery — cluster log aggregation lag:** Workers forward events to the manager which writes to log files. There is a 1-2 minute aggregation delay between a connection occurring and the record appearing in `/opt/zeek/logs/current/conn.log`. This is normal cluster behavior and must be accounted for in detection time windows.

**Key discovery — port 9991 conflict:** Initial cluster deploy failed because the previous standalone Zeek instance held port 9991 (Prometheus metrics endpoint). Resolved with `sudo fuser -k 9991/tcp` before redeployment.

<img width="1278" height="426" alt="Screenshot 2026-07-21 at 5 42 20 PM" src="https://github.com/user-attachments/assets/c97d887d-bdbe-4e80-be95-5118c62d56ee" />

---

## Phase 2 — Attack Simulation

### Kali Linux Setup

SSH enabled on Kali via Proxmox console:

```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```

Connectivity verified from Ubuntu:
```bash
ssh kali@10.10.10.132 "uname -a && ip addr show eth0"
```

### nmap Attack Sequence

Four scans executed from Kali targeting the lab network:

```bash
# Attack 1 — SYN scan (stealthy, top 1000 ports)
nmap -sS 10.10.10.198

# Attack 2 — Aggressive scan (service/version/OS detection)
nmap -A 10.10.10.198

# Attack 3 — Host discovery across full subnet
nmap -sn 10.10.10.0/24

# Attack 4 — Targeted sensitive port scan
nmap -p 22,80,443,445,3389,5432,8000,8089 10.10.10.198
```

<img width="1278" height="63" alt="Screenshot 2026-07-21 at 5 51 45 PM" src="https://github.com/user-attachments/assets/275c5c4f-3c83-4ed3-835c-045a6570668f" />


nmap discovered: SSH (22/open), Splunk Web (8000/open), port 514 (closed). OS fingerprinted as Linux. Service version identified as OpenSSH 9.6p1.

### SSH Lateral Movement Attack

```bash
ssh -t kali@10.10.10.132 "ssh labadmin@10.10.10.198 'whoami && id && ls /tmp'"
```

This creates the complete lateral movement chain:
- Zeek sees: TCP connection from 10.10.10.132 to 10.10.10.198:22
- auditd sees: USER_START from sshd with hostname=10.10.10.132
- auditd sees: proc_exec command execution in the new session

### Zeek Capture Verification

```bash
sudo grep "10.10.10.132" /opt/zeek/logs/current/conn.log | wc -l
# Result: 4,117 records
```

![Zeek capturing 4,117 scan records from Kali](screenshots/04-zeek-capture-count.png)

---

## Phase 3 — Splunk Verification

```spl
index=main sourcetype=zeek_conn earliest=-30m
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| where orig_ip="10.10.10.132"
| stats count as connections dc(id.resp_p) as unique_ports values(conn_state) as states by orig_ip
```

<img width="1253" height="506" alt="Screenshot 2026-07-21 at 5 56 17 PM" src="https://github.com/user-attachments/assets/2a616fac-de94-44d7-ae75-45236e1a9fa2" />


**Result:** 2,988 events, 946 unique ports, conn_states: S0, REJ, RSTOS0, SH, OTH — textbook port scan fingerprint.

---

## Phase 4 — Detection Engineering

### Key Technical Discovery — id.resp_p Field Extraction

A critical Zeek/Splunk integration lesson discovered during Detection 3 debugging: the `id.resp_p` field from Zeek JSON auto-parsing is unreliable for filtering in SPL `where` clauses. Using `where id.resp_p="22"` returns 0 results even when port 22 data exists. The fix is explicit rex extraction:

```spl
| rex field=_raw "\"id\.resp_p\":(?P<resp_port>\d+)"
| where resp_port="22"
```

This pattern is applied in all detections that filter on destination port.

---

### Detection 1 — Port Scan Detected

**Description:** Detects scanning behavior from lab network hosts using Zeek conn.log. Groups connections in 1-minute windows and counts unique destination ports per source IP. Evidence weight scales with port count. Also captures S0 and REJ connection state counts — scanners generate overwhelmingly failed connections (99.6% in the nmap test) while legitimate software maintains established sessions.

**Why this differs from Domain 1 nmap detection:** Domain 1 Project 5 caught nmap by watching auditd detect the binary executing on the local host. This detection catches external attackers scanning from the network — no foothold on the target required. Any scanning tool produces the same behavioral fingerprint regardless of whether it's nmap, a custom script, or a commercial scanner.

**MITRE:** T1046 — Network Service Discovery

```spl
index=main sourcetype=zeek_conn earliest=-30m
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_h\":\"(?P<resp_ip>[^\"]+)\""
| where match(orig_ip,"^10\.10\.10\.")
| bin _time span=1m
| stats
    dc(id.resp_p) as unique_ports
    count as total_conns
    sum(eval(if(conn_state="S0",1,0))) as s0_count
    sum(eval(if(conn_state="REJ",1,0))) as rej_count
    by orig_ip _time
| eval failed_ratio=round((s0_count+rej_count)/total_conns*100,1)
| eval evidence_weight=case(
    unique_ports > 500, 0.95,
    unique_ports > 100, 0.90,
    unique_ports > 50,  0.85,
    unique_ports > 20,  0.75,
    true(), 0.65
)
| where unique_ports > 20
| eval detection="Port Scan Detected"
| eval severity=case(
    evidence_weight>=0.90,"CRITICAL",
    evidence_weight>=0.75,"HIGH",
    true(),"MEDIUM"
)
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table detection severity evidence_weight orig_ip window unique_ports total_conns s0_count rej_count failed_ratio
| sort -unique_ports
```

<img width="1253" height="230" alt="Screenshot 2026-07-21 at 6 07 56 PM" src="https://github.com/user-attachments/assets/bd4317e0-4820-440a-acc0-c8832d8bce79" />


**Result:** CRITICAL at 0.95. 945 unique ports, 2,984 connections, 99.6% failure rate.

**Alert Settings:**
- Title: `Port Scan Detected`
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 30 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: Critical

---

### Detection 2 — Internal Host Discovery Detected

**Description:** Detects a single source IP contacting multiple unique internal hosts within a 2-minute window. Explicitly excludes multicast ranges (224.x, 239.x), mDNS port 5353, and ICMPv6 neighbor discovery to avoid home network noise.

**MITRE:** T1018 — Remote System Discovery

**⚠️ Documented Architectural Limitation — ARP Blind Spot**

`nmap -sn` on the local subnet defaults to ARP-based host discovery. ARP operates at Layer 2 and is not recorded in Zeek's conn.log (which only captures Layer 3/4 conversations). Detection 2 cannot detect ARP-based subnet sweeps.

Validated with TCP-based discovery (`nmap -PS22,80,8000 10.10.10.0/24`) which generates TCP SYN probes visible in conn.log. This is the detection's intended use case — TCP/UDP/ICMP host discovery is detectable; ARP-only sweeps are not.

For the portfolio: this is not a detection flaw but an architectural constraint. Enterprise Zeek deployments on SPAN ports or TAPs may see ARP depending on configuration. Understanding the difference between Layer 2 and Layer 3 visibility is a core network detection engineering concept.

```spl
index=main sourcetype=zeek_conn earliest=-30m
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_h\":\"(?P<resp_ip>[^\"]+)\""
| where match(orig_ip,"^10\.10\.10\.")
| where match(resp_ip,"^10\.10\.10\.")
| where NOT match(resp_ip,"^224\.")
| where NOT match(resp_ip,"^239\.")
| where id.resp_p!="5353"
| where proto!="icmp6"
| bin _time span=2m
| stats
    dc(resp_ip) as unique_hosts
    count as total_conns
    dc(id.resp_p) as unique_ports
    values(resp_ip) as hosts_contacted
    by orig_ip _time
| where unique_hosts >= 3
| eval evidence_weight=case(
    unique_hosts > 10, 0.95,
    unique_hosts > 5,  0.85,
    unique_hosts >= 3, 0.75,
    true(), 0.65
)
| eval detection="Internal Host Discovery Detected"
| eval severity=case(
    evidence_weight>=0.90,"CRITICAL",
    evidence_weight>=0.75,"HIGH",
    true(),"MEDIUM"
)
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table detection severity evidence_weight orig_ip window unique_hosts unique_ports total_conns hosts_contacted
| sort -unique_hosts
```

**Alert Settings:**
- Title: `Internal Host Discovery Detected`
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 30 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 3 — SSH Lateral Movement Detected

**Description:** Correlates three independent signals in a 5-minute window — Zeek network-layer view of inbound SSH connection, auditd USER_START record confirming successful PAM authentication from a lab host IP, and auditd proc_exec showing command execution. Audit session ID validates that session creation and command execution belong to the same login session.

**MITRE:** T1021.004 — Remote Services: SSH

**Key architectural lessons:**

**id.resp_p extraction:** `where id.resp_p="22"` fails silently. Must use `rex field=_raw "\"id\.resp_p\":(?P<resp_port>\d+)"` — discovered through systematic debugging when network_ssh_inbound signal returned zero events despite SSH data existing in Splunk.

**Audit session correlation:** Eva identified that grouping by `ses` breaks Zeek correlation (Zeek has no audit ses field). Fix: group by `_time endpoint` but validate audit signals share a session using `dc(audit_session) <= 1`. This ensures `host_ssh_session_created` and `host_command_execution` belong to the same login session while allowing the Zeek signal to correlate by time window only.

**auid generalization:** Changed from `auid="1000"` (hardcoded lab account) to `auid!="0" AND auid!="4294967295"` — detection works for any non-root interactive user.

```spl
index=main (sourcetype=zeek_conn OR sourcetype=linux_audit) earliest=-30m
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_h\":\"(?P<resp_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_p\":(?P<resp_port>\d+)"
| rex field=_raw "addr=(?P<ssh_src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| eval signal=case(
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\.10\.10\.")
        AND resp_ip="10.10.10.198"
        AND resp_port="22"
        AND proto="tcp"
        AND (conn_state="SF" OR conn_state="S1" OR conn_state="OTH"),
    "network_ssh_inbound",
    sourcetype="linux_audit"
        AND match(_raw,"type=USER_START")
        AND match(_raw,"exe=\"/usr/sbin/sshd\"")
        AND match(_raw,"res=success")
        AND match(ssh_src_ip,"^10\.10\.10\."),
    "host_ssh_session_created",
    sourcetype="linux_audit"
        AND match(_raw,"key=\"proc_exec\"")
        AND match(_raw,"success=yes")
        AND auid!="0"
        AND auid!="4294967295",
    "host_command_execution",
    true(), null()
)
| where isnotnull(signal)
| eval audit_session=if(
    signal="host_ssh_session_created"
        OR signal="host_command_execution",
    ses, null()
)
| eval endpoint="splunk-server"
| bin _time span=5m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    dc(audit_session) as audit_session_count
    values(audit_session) as sessions
    values(ssh_src_ip) as source_ips
    values(orig_ip) as network_sources
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| where audit_session_count <= 1
| eval combined_confidence=case(
    signal_count=3, 0.97,
    signal_count=2, 0.85,
    true(), 0.70
)
| where combined_confidence >= 0.75
| eval detection="SSH Lateral Movement Detected"
| eval severity=case(
    combined_confidence>=0.95,"CRITICAL",
    combined_confidence>=0.80,"HIGH",
    true(),"MEDIUM"
)
| eval description="Inbound SSH connection from lab host corroborated by auditd session creation and command execution in same audit session."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence endpoint signal_count signals_detected audit_session_count sessions source_ips first_seen last_seen description
```

<img width="1253" height="507" alt="Screenshot 2026-07-21 at 6 38 51 PM" src="https://github.com/user-attachments/assets/be3c3725-6927-4ca1-9723-479eb4f35bf0" />

**Result:** HIGH at 0.85. network_ssh_inbound and host_command_execution confirmed in same window. Session 3772 validated.

**Alert Settings:**
- Title: `SSH Lateral Movement Detected`
- Alert type: Scheduled — `*/5 * * * *`
- Time Range: Last 30 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 600 seconds
- Severity: High

---

### Detection 4 — Combined Lateral Movement Attack Chain Detected

**Description:** BLIP-AI's first complete kill-chain correlation. Correlates four signals — port scan, SSH inbound connection, SSH session creation, and command execution — from the same attacker IP in a 30-minute window. Requires 3+ distinct signals and audit session validation. Attacker IP grouping ensures all signals are attributed to the same source rather than coincidental activity from different hosts.

**MITRE:** T1046, T1021.004, T1059 — Command and Scripting Interpreter

**Key architectural lessons:**

**Attacker identity attribution:** First version lost attacker identity in the stats aggregation — different IPs could generate different signals and be incorrectly combined into one "attack chain." Fix: `by _time attacker_ip` ensures all signals must come from the same source IP.

**Session validation in combined score:** Same audit session correlation requirement from Detection 3 applied here — `dc(audit_session) <= 1` ensures command execution belongs to the SSH session being tracked.

```spl
index=main (sourcetype=zeek_conn OR sourcetype=linux_audit) earliest=-60m
| rex field=_raw "\"id\.orig_h\":\"(?P<orig_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_h\":\"(?P<resp_ip>[^\"]+)\""
| rex field=_raw "\"id\.resp_p\":(?P<resp_port>\d+)"
| rex field=_raw "addr=(?P<ssh_src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "auid=(?P<auid>\d+)"
| rex field=_raw "ses=(?P<ses>\d+)"
| eval attacker_ip=case(
    sourcetype="zeek_conn", orig_ip,
    sourcetype="linux_audit" AND match(_raw,"type=USER_START"), ssh_src_ip,
    true(), null()
)
| eval signal=case(
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\.10\.10\.")
        AND match(resp_ip,"^10\.10\.10\.")
        AND proto="tcp"
        AND (conn_state="S0" OR conn_state="REJ" OR conn_state="RSTOS0"),
    "network_port_scan",
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\.10\.10\.")
        AND resp_ip="10.10.10.198"
        AND resp_port="22"
        AND proto="tcp"
        AND (conn_state="SF" OR conn_state="S1" OR conn_state="OTH"),
    "network_ssh_inbound",
    sourcetype="linux_audit"
        AND match(_raw,"type=USER_START")
        AND match(_raw,"exe=\"/usr/sbin/sshd\"")
        AND match(_raw,"res=success")
        AND match(ssh_src_ip,"^10\.10\.10\."),
    "host_ssh_session_created",
    sourcetype="linux_audit"
        AND match(_raw,"key=\"proc_exec\"")
        AND match(_raw,"success=yes")
        AND auid!="0"
        AND auid!="4294967295",
    "host_command_execution",
    true(), null()
)
| where isnotnull(signal)
| eval audit_session=if(
    signal="host_ssh_session_created"
        OR signal="host_command_execution",
    ses, null()
)
| eval technique_weight=case(
    signal="network_port_scan", 0.80,
    signal="network_ssh_inbound", 0.85,
    signal="host_ssh_session_created", 0.90,
    signal="host_command_execution", 0.75,
    true(), 0.50
)
| bin _time span=30m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    dc(audit_session) as audit_session_count
    values(audit_session) as sessions
    sum(technique_weight) as raw_score
    values(ssh_src_ip) as ssh_sources
    min(_time) as first_seen
    max(_time) as last_seen
    by _time attacker_ip
| where signal_count >= 3
| where audit_session_count <= 1
| eval combined_confidence=min(round(raw_score/signal_count * 1.10, 2), 1.0)
| where combined_confidence >= 0.80
| eval detection="Combined Lateral Movement Attack Chain Detected"
| eval severity=case(
    combined_confidence>=0.95,"CRITICAL",
    combined_confidence>=0.85,"HIGH",
    true(),"MEDIUM"
)
| eval description="Port scan + SSH lateral movement + host command execution detected in same 30-minute window from same attacker IP. Complete recon-to-access attack chain confirmed."
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table detection severity combined_confidence attacker_ip signal_count signals_detected audit_session_count sessions ssh_sources first_seen last_seen description
```

<img width="1253" height="507" alt="Screenshot 2026-07-21 at 6 45 30 PM" src="https://github.com/user-attachments/assets/f2d410cc-ca00-4f6b-9aa2-638864706b06" />


**Result:** CRITICAL at 1.0. Attacker `10.10.10.132` confirmed across port_scan, network_ssh_inbound, and host_ssh_session_created. Session 6190 validated.

**Alert Settings:**
- Title: `Combined Lateral Movement Attack Chain Detected`
- Alert type: Scheduled — `*/15 * * * *`
- Time Range: Last 60 minutes
- Expires: 24 hours
- Trigger: Number of Results greater than 0 — Per-Result
- Throttle: 1800 seconds
- Severity: Critical

---

## Phase 5 — Validation Summary

| Detection | Attack Used | Zeek Captured | Splunk Result | Eva Cycles | Status |
|---|---|---|---|---|---|
| 1 — Port Scan | nmap -sS / -A | 4,117 records | 0.95 CRITICAL | 1 | ✅ Saved |
| 2 — Host Discovery | nmap -PS22,80,8000 | TCP SYN probes | Documented — ARP blind spot | 2 | ✅ Saved |
| 3 — SSH Lateral Movement | ssh Kali→Ubuntu | SSH conn records | 0.85 HIGH | 4 | ✅ Saved |
| 4 — Combined Chain | Full attack sequence | All signals | 1.0 CRITICAL | 3 | ✅ Saved |

---

## Known Limitations

| Limitation | Impact | Resolution Path |
|---|---|---|
| ARP-based host discovery not detectable | nmap -sn on local subnet invisible to Zeek | Network TAP or switch mirror port for Layer 2 visibility |
| id.resp_p field unreliable in Splunk JSON parse | All port filters must use rex extraction | Configure props.conf field transforms for Zeek sourcetypes |
| Command execution not tied to SSH session in Detection 4 combined score | Possible false positives from concurrent local admin activity | Future: join on session ID across subsearch |
| Zeek cluster log aggregation lag (1-2 min) | Near-real-time detection window impacted | Acceptable for scheduled alerts; not suitable for real-time streaming |
| Detection 3 endpoint hardcoded to splunk-server | Only detects lateral movement TO this specific host | V2: dynamic hostname from host field |

---

## Technical Discoveries

**Zeek cluster mode vs standalone:** In standalone mode each interface gets its own Zeek process writing directly to `/opt/zeek/logs/current/`. In cluster mode workers forward events to the manager which writes logs centrally. Workers have no conn.log of their own — all logs aggregate at the manager. The 1-2 minute aggregation delay is a fundamental characteristic of cluster mode.

**Port 9991 Prometheus conflict:** Zeek cluster manager uses port 9991 for the Prometheus metrics endpoint. If a previous standalone Zeek instance is still holding this port the manager fails immediately with "Failed to setup server ports." Resolution: `sudo fuser -k 9991/tcp` before deploy.

**ARP is Layer 2:** `nmap -sn` on a local /24 subnet sends ARP requests to discover hosts. ARP never appears in Zeek's conn.log because conn.log records Layer 3/4 sessions (TCP, UDP, ICMP). This is a fundamental sensor placement constraint, not a detection logic flaw.

**auditd USER_START hostname field:** The `hostname=` field in auditd USER_START records contains the SSH client's IP address when an SSH session is opened. This is the correct correlation key between Zeek's `orig_ip` and auditd's view of the same connection — no shared session ID required across sourcetypes.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Network Service Discovery | T1046 | Detection 1, 4 |
| Remote System Discovery | T1018 | Detection 2 |
| Remote Services: SSH | T1021.004 | Detection 3, 4 |
| Command and Scripting Interpreter | T1059 | Detection 4 |

---
