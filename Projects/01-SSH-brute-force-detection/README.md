# Project 01 — SSH Brute Force Detection

## Overview
This project simulates a real-world SSH brute force attack against a Linux target and demonstrates the full SOC detection cycle — from attack generation to alert investigation. Using Kali Linux as the attack platform and Splunk as the SIEM, this project covers log ingestion, custom detection engineering, automated alerting, and incident investigation. Every step mirrors what a SOC analyst encounters when responding to credential-based attacks in enterprise environments.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux VM (192.168.1.226) |
| Target | Ubuntu Server — splunk-server (192.168.1.220) |
| SIEM | Splunk Enterprise 10.2.2 |
| Attack Tool | Hydra with RockYou.txt wordlist |
| Log Source | /var/log/auth.log via Splunk Universal Forwarder |
| Hypervisor | Proxmox VE 8.x on Dell OptiPlex 7060 Micro |

---

## Attack Simulation

### The Concept
SSH brute force attacks are one of the most common threats in enterprise environments. Attackers systematically try thousands of username and password combinations against exposed SSH services hoping to find valid credentials. The goal of this project is to simulate that attack, capture the evidence in a SIEM, and build automated detection that catches it without manual intervention.

### Establishing The Baseline
Before launching any attack, Splunk was verified to be receiving logs from the Ubuntu Server via the Splunk Universal Forwarder monitoring /var/log/auth.log. The initial log count confirmed the pipeline was operational.

<img width="2540" height="954" alt="Screenshot 2026-04-14 at 4 06 36 PM" src="https://github.com/user-attachments/assets/11c8a685-7870-4ae3-a7ab-934a8b46d458" />

### Launching The Attack
From the Kali Linux VM, Hydra was used to simulate a brute force attack against the Ubuntu Server's SSH service using the RockYou.txt wordlist — a real-world password list containing 14 million commonly used passwords derived from an actual data breach.

```bash
hydra -l labadmin -P /usr/share/wordlists/rockyou.txt 192.168.1.220 ssh -t 4 -V
```

**Command breakdown:**

| Flag | Purpose |
|---|---|
| `-l labadmin` | Target username |
| `-P rockyou.txt` | Password wordlist |
| `192.168.1.220` | Target IP — Ubuntu Server |
| `ssh` | Target protocol |
| `-t 4` | 4 parallel threads |
| `-V` | Verbose output showing each attempt |

<img width="838" height="524" alt="Screenshot 2026-04-14 at 4 27 10 PM" src="https://github.com/user-attachments/assets/a315b6a8-773c-4fb3-a192-ff811c78c2cc" />


---

## Detection

### Log Ingestion — Attack Traffic Captured
Within seconds of launching Hydra, Splunk began ingesting hundreds of failed authentication events from the Ubuntu Server. The log volume jumped from 26 baseline events to hundreds in real time — immediately visible in the Splunk dashboard.

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 4 28 44 PM" src="https://github.com/user-attachments/assets/8449854a-349d-4605-b327-a3123062ae60" />


### Detection Engineering — Building The SPL Query
Initial detection attempts using the standard src_ip field returned no results. Investigation of the raw log format revealed that Splunk's linux_secure sourcetype was not automatically extracting the source IP as a separate field. The IP address was embedded in the raw log string requiring manual regex extraction.

**The detection query:**
index=main sourcetype=linux_secure "Failed password" earliest=-24h
| rex field=_raw "Failed password for \S+ from (?P<src_ip>\d+.\d+.\d+.\d+)"
| stats count by src_ip
| where count > 5

**Query breakdown:**

| Component | Purpose |
|---|---|
| `sourcetype=linux_secure` | Filter to authentication logs only |
| `rex field=_raw` | Extract IP from raw log text using regex |
| `(?P<src_ip>\d+\.\d+\.\d+\.\d+)` | Regex pattern matching IPv4 format |
| `stats count by src_ip` | Group and count attempts per source IP |
| `where count > 5` | Filter out single failed attempts — flag repeated failures |

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 4 44 06 PM" src="https://github.com/user-attachments/assets/18f619cc-a923-436c-9fea-7279062acca9" />


### Automated Alert Configuration
The detection query was saved as a scheduled Splunk alert running every 5 minutes via cron schedule `*/5 * * * *`. The alert triggers when any results are returned — meaning any IP with more than 5 failed SSH attempts automatically fires a notification, eliminating the need for manual searching.

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 4 49 11 PM" src="https://github.com/user-attachments/assets/b40eebaa-6f8a-49f7-83ca-772091100bca" />


---

## Investigation

### Alert Triggered
The automated alert fired within the first 5 minute window confirming the detection rule was working correctly. The triggered alert appeared in Splunk's Activity panel showing medium severity with a direct link to the results.

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 4 52 59 PM" src="https://github.com/user-attachments/assets/44a3562c-322e-48b5-b899-e36483be1c4c" />

### Determining Breach Status
The most critical question in any brute force investigation is whether any attempt succeeded. A successful login following hundreds of failures indicates a full compromise rather than just an attempted attack.

**Query used to check for successful logins:**
index=main sourcetype=linux_secure "Accepted password" OR "Accepted publickey"

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 4 57 01 PM" src="https://github.com/user-attachments/assets/3d497e35-5cb6-4084-b150-af94e902f4f6" />


The results showed 2 accepted logins — both confirmed as legitimate SSH sessions established by me during the investigation. No unauthorized access occurred.

### Full Activity Correlation
A final correlation query was run to display both failed and accepted activity grouped by source IP — providing a complete picture of everything that touched the SSH service during the attack window.

index=main sourcetype=linux_secure earliest=-24h
| rex field=_raw "(?:Failed password|Accepted password) for \S+ from (?P<src_ip>\d+.\d+.\d+.\d+)"
| stats count by src_ip

<img width="1267" height="957" alt="Screenshot 2026-04-14 at 5 01 25 PM" src="https://github.com/user-attachments/assets/3a92380b-2e61-49b4-9098-37e1dd20cd07" />

This confirmed two distinct source IPs — Kali Linux generating the attack traffic and my MacBook generating the legitimate SSH sessions. Clear separation between malicious and legitimate activity.

---

## Findings

| Finding | Detail |
|---|---|
| Attack source | 192.168.1.226 — Kali Linux VM |
| Target account | labadmin |
| Total attempts | 2,515 |
| Attack duration | ~60 minutes |
| Successful breach | None confirmed |
| Detection method | Custom SPL query with regex field extraction |
| Time to detection | Under 5 minutes via automated alert |
| Legitimate logins | 2 — Taylor's SSH sessions confirmed |

---

## Challenges and Solutions

### Challenge — src_ip Field Not Extracted Automatically
**Issue:** The initial detection query using `stats count by src_ip` returned no results because Splunk's linux_secure sourcetype was not automatically parsing the source IP as a separate field from the raw log text.

**Resolution:** Investigated the raw log format directly in Splunk and identified the IP address embedded within the plain text string. Applied a rex command using a regex pattern to manually extract the IP address mid-query. This approach is more portable and reliable than relying on automatic field extraction since it works regardless of sourcetype configuration.

**Takeaway:** Understanding raw log formats and manual field extraction is a critical Splunk skill. Automatic field extraction cannot always be relied upon — knowing how to extract fields with regex mid-query is essential for real SOC detection engineering.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Repeated credential attempts against SSH |
| Valid Accounts | T1078 | Attacker objective — gain valid credentials |
| Remote Services | T1021.004 | SSH as the targeted remote service |

---

## Key Takeaways

**For Detection Engineers:**
Threshold based detection is highly effective for brute force — normal users rarely generate more than 2-3 failed logins. Any IP exceeding 5 failures in a short window warrants immediate investigation regardless of environment.

**For SOC Analysts:**
The most important question after identifying a brute force attack is not how many attempts occurred — it is whether any succeeded. Confirmed failed attempts are a threat. A single successful login after hundreds of failures is a breach.

**For Defenders:**
This simulation used RockYou.txt which starts with the most commonly used passwords first. Accounts using common passwords can be compromised within the first few hundred attempts. Strong unique passwords and MFA eliminate brute force as a viable attack vector entirely.

---

