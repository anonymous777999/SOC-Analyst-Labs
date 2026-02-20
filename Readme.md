# SOC Analyst Case Studies — Enterprise Incident Investigations

## Blue Team Incident Investigation Report

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow)

---

### 📋 Report Metadata

| Field | Details |
|-------|---------|
| **Analyst** | Senior SOC Analyst |
| **Date** | 2025 |
| **Lab Type** | Windows Threat Detection |
| **Classification** | Training Exercise |
| **Tools Used** | Splunk SIEM, Sysmon, Windows Security Logs |
| **Log Sources** | `security_log.csv`, `sysmon_log.csv` |
| **Event IDs Analyzed** | 4624, 4625, 4672, 4688 (Security) / 1, 3, 7, 11 (Sysmon) |

---

## 🔍 Investigation Overview

### Executive Summary

This detection lab simulates a **multi-stage intrusion** against a Windows enterprise environment. The attack chain includes initial access via brute-force credential attacks, followed by execution of malicious payloads, persistence mechanisms, and command-and-control (C2) communications.

The investigation leverages **Windows Security Event Logs** combined with **Sysmon telemetry** to detect, correlate, and attribute adversary techniques across the kill chain.

### 🎯 Lab Objectives

| # | Objective | Status |
|---|-----------|--------|
| 1 | Detect brute-force authentication attacks using Event ID 4625 | ✅ |
| 2 | Identify credential compromise (failed → successful login pattern) | ✅ |
| 3 | Hunt for suspicious process executions via Sysmon Event ID 1 | ✅ |
| 4 | Detect C2 beaconing activity through Sysmon Event ID 3 | ✅ |
| 5 | Analyze parent-child process anomalies for malware execution | ✅ |
| 6 | Map all findings to MITRE ATT&CK Framework | ✅ |

---

## 🧪 Detection Use Cases

### Use Case 1: Brute Force Detection (Event ID 4625)

#### 📖 Description
Event ID **4625** indicates a failed login attempt. A high volume of these events from the same source targeting the same account is a strong indicator of brute-force or password spraying attacks.

```SPL
source="security_log.csv" EventID="4625"
| stats count by AccountName, SourceIP
| where count > 3
| rename AccountName as user, SourceIP as src_ip
```
---

## Use Case 2: Credential Compromise Detection (Failed → Success)
📖 Description
A successful login (Event ID 4624) preceded by multiple failed attempts indicates a compromised credential. This pattern is critical for detecting successful brute-force attacks.

```SPL
 source="security_log.csv" (EventID=4624 OR EventID=4625)
| sort 0 AccountName _time
| streamstats current=f window=1 last(EventID) as prev_event last(_time) as prev_time by AccountName
| where EventID=4624 AND prev_event=4625
| eval time_diff = round((_time - prev_time),2)
| table AccountName SourceIP time_diff
```

---

## Use Case 3: Suspicious Process Execution (Sysmon Event ID 1)
📖 Description
Sysmon Event ID 1 logs process creation with full command-line visibility. We hunt for known malicious patterns: encoded PowerShell, suspicious binaries in temp folders, and LOLBins abuse.

🔎 SPL Query

```SPL
source="sysmon_log.csv" EventID=1
| rename Image as proc_path, ParentImage as parent_proc
| where like(proc_path, "C:\\Windows\\Temp\\%")
    OR like(proc_path, "%AppData\\Roaming%")
    OR like(proc_path, "%ProgramData%")
    OR like(proc_path, "C:\\Users\\Public\\%")
| table proc_path parent_proc
```
---

## Use Case 4: External C2 Beaconing (Sysmon Event ID 3)
📖 Description
Sysmon Event ID 3 captures network connections made by processes. We identify potential C2 traffic by analyzing external connections from suspicious processes, unusual ports, and periodic beaconing patterns.

🔎 SPL Query
```SPL
source="sysmon_log.csv" EventID=3
| table _time DestinationIP Image ParentImage
| where DestinationIP!="192.168.%" AND DestinationIP!="10.%"
```
---

## Use Case 5: Parent-Child Process Anomalies
📖 Description
Legitimate Windows processes have expected parent-child relationships. Anomalies such as cmd.exe or powershell.exe spawning unknown executables, or WINWORD.EXE spawning shells, indicate malware execution.

🔎 SPL Query

```SPL
source="sysmon_log.csv" EventID=1
| where ParentImage="C:\\Windows\\System32\\cmd.exe"
    OR ParentImage="C:\\Windows\\System32\\powershell.exe"
| table Image ParentImage
```
---

## Long-Term Hardening
Action	Details
🔐 Enforce MFA	Require multi-factor authentication for all service accounts
🔒 Account Lockout	Implement lockout after 5 failed attempts (15-minute window)
📊 Enhanced Logging	Enable PowerShell ScriptBlock logging and command-line auditing
🚫 Application Whitelisting	Block execution from Temp, Downloads, and AppData folders
🌐 Network Segmentation	Restrict outbound traffic from workstations to known-good destinations
🔍 EDR Deployment	Deploy endpoint detection and response solution
