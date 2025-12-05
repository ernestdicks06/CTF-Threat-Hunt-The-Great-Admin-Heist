
### Threat Hunt – The Great Admin Heist
### Azuki Import/Export | Microsoft Defender for Endpoint (MDE)

![Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_for_Endpoint-blue)
![Category](https://img.shields.io/badge/Category-Threat_Hunting-red)

---

### 1. Scenario Overview

Azuki Import/Export (梓貿易株式会社) is a 23-person logistics company operating across Japan and Southeast Asia. After a pricing leak caused the loss of a major shipping contract by exactly 3%, sensitive supplier pricing data was later observed on underground forums.

This threat hunt focuses on the administrator workstation **`AZUKI-SL`**, using Microsoft Defender for Endpoint (MDE) telemetry to determine:

- How the attacker gained access  
- Which accounts were compromised  
- What tools and techniques were used  
- How data was staged and exfiltrated  
- What persistence and anti-forensic techniques were left behind  

---

### 2. Executive Summary

On **2025-11-19**, an attacker accessed **`AZUKI-SL`** via exposed RDP using the compromised account **`kenji.sato`** from external IP **`88.97.178.12`**. Once on the system, the attacker:

- Downloaded and executed malicious payloads using **PowerShell** and **LoLBins**  
- Modified **Windows Defender exclusions** and used **hidden directories** for staging  
- Established **persistence** via a **scheduled task** and a **rogue admin account**  
- Used a credential dump tool (**`Mm.exe`**) to extract credentials from LSASS  
- Staged sensitive data into an archive (**`exportdata.zip`**)  
- Exfiltrated data over **HTTPS via Discord**  
- Attempted **anti-forensics** by clearing Windows event logs with `wevtutil`  

**Impact:** High  
**Status:** Fully investigated (lab simulation)  

---

### 3. How I Solved Each Flag (Walkthrough + KQL)

---

### 🚩 Flag 1 – Initial Access IP  
Question: Question: Identify the source IP address of the Remote Desktop Protocol connection?

**Answer**:** `88.97.178.12`  
**MITRE:** T1133 – External Remote Services

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
| order by Timestamp desc
```

Screenshot: <img width="1894" height="478" alt="image" src="https://github.com/user-attachments/assets/2eda25fa-4443-4e98-b478-4875ea9f3ad8" />


---
### 🚩 Flag 2 – Compromised Account

Question: Which account was used for the RDP compromise?

**Answer**: kenji.sato

**MITRE**: T1078 – Valid Accounts

```kql
DeviceLogonEvents
| where DeviceName == "AZUKI-SL"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| distinct AccountName
```
Explanation: 
Tightned the RDP query to only that suspicious IP and extracted the account involved. The result was kenji.sato.

Screenshot: <img width="1903" height="850" alt="image" src="https://github.com/user-attachments/assets/bec88398-6904-4aa4-8114-0c204480b6c6" />


---

### 🚩 Flag 3 – Discovery Command

Question: What discovery command did the attacker use?

**Answer**: arp -a

**MITRE**: T1018 – Remote System Discovery


```KQL
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| project Timestamp, ProcessCommandLine, DeviceName, ProcessId, MD5
| where ProcessCommandLine has "arp"
```

Explanation:
Looked at process command lines for ARP usuage. The attacker ran arp -a enumerate local network neighbors.

Screenshot: <img width="1897" height="433" alt="image" src="https://github.com/user-attachments/assets/dd5ee7ab-bf93-4d74-b6c3-4f4b81dff662" />



---

### 🚩 Flag 4 – Hidden Directory Used for Staging

Question: Which hidden directory was used for staging?

**Answer***: C:\ProgramData\WindowsCache

**MITRE**: T1096 – Hidden Files and Directories

```KQL 
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "attrib.exe"
| where ProcessCommandLine has "+h"
 and ProcessCommandLine has "+s"
```

## Step-by-step explanation:

FileName == "attrib.exe" – I looked for Windows attrib utility executions.                                                                  
                                                                                                                                         
ProcessCommandLine has "+h" – +h sets the hidden attribute.                                                                                                              
                                                                                                                                        
ProcessCommandLine has "+s" – +s sets the system attribute.                                                                             

The command-line parameters revealed the path being hidden as C:\ProgramData\WindowsCache, indicating staging activity in a hidden folder.



Screenshot:
---

### 🚩 Flag 5 – Defender Extension Exclusions

Question: How many new file extensions were excluded in Defender?

**Answer**: 3 extensions

**MITRE**: T1562.001 – Impair Defenses (Disable Security Tools)

<strong>KQL – Registry Changes to Defender Extension Exclusions</strong>
```kql
DeviceRegistryEvents
| where DeviceName == "AZUKI-SL"
| where RegistryKey contains @"Microsoft\Windows Defender\Exclusions\Extensions"
```

Step-by-step explanation:

DeviceRegistryEvents – I moved to registry telemetry to see configuration tampering.

RegistryKey contains "Exclusions\\Extensions" – Focused on Defender’s extension exclusion key.

Investigating the RegistryValueData for these events showed three malicious file extensions being exempted from scanning, weakening Defender coverage.



Screenshot:
---

### 🚩 Flag 6 – Defender Path Exclusion

Question: Which path was excluded from Defender scanning?

**Answer**: C:\Users\KENJI~1.SAT\AppData\Local\Temp

<strong>KQL – Registry Changes to Defender Path Exclusions</strong>
```kql
DeviceRegistryEvents
| where DeviceName == "AZUKI-SL"
| where RegistryKey contains @"Microsoft\Windows Defender\Exclusions\Paths"
```

Step-by-step explanation:

Same approach as Flag 5, but pointed at the Paths exclusion key instead of Extensions.

By reviewing the RegistryKey and RegistryValueData, I confirmed that an exclusion was added for:

C:\Users\KENJI~1.SAT\AppData\Local\Temp

Excluding this Temp path allows malware dropped there to bypass Defender inspection.



Screenshot:
---

### 🚩 Flag 7 – Living-off-the-Land Downloader

Question: Which LoLBin was abused to download content?

**Answer**: certutil.exe

**MITRE**: T1218 – Signed Binary Proxy Execution

<strong>KQL – Find certutil Downloader Activity</strong>
```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "certutil.exe"
| where ProcessCommandLine has_any ("http:", "https:")
```

Step-by-step explanation:

Targeted known LoLBins often used for downloading (e.g., certutil).

FileName == "certutil.exe" – Limit to that binary.

ProcessCommandLine has_any ("http:", "https:") – Look for usage where URLs are present.

The results showed certutil being used with an HTTP/HTTPS URL, indicating a download of remote payloads.


Screenshot:
---

### 🚩 Flag 8 – Scheduled Task Name (Persistence)

Question: What is the name of the persistence scheduled task?
**Answer**: Windows Update Check
**MITRE**: T1053.005 – Scheduled Task

<strong>KQL – Identify Malicious Scheduled Task Creation</strong>
```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
```

Step-by-step explanation:

FileName == "schtasks.exe" – Look for command-line creation of scheduled tasks.

ProcessCommandLine has "/create" – Filter for commands that are explicitly creating tasks.

Reviewing the output, I found a command line similar to:
schtasks /create /tn "Windows Update Check" ...

The /tn parameter revealed the scheduled task name: Windows Update Check.

Screenshot:
---
### 🚩 Flag 9 – Scheduled Task Payload Path

Question: What binary is executed by the scheduled task?
**Answer**: C:\ProgramData\WindowsCache\svchost.exe

<strong>KQL – Extract Payload from Scheduled Task Command</strong>
```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, ProcessCommandLine
```

Step-by-step explanation:

Reused the Flag 8 query and added project to focus on the full command line.

Reviewing ProcessCommandLine, I located the /tr (task run) parameter.

The /tr argument showed that the task launches:
C:\ProgramData\WindowsCache\svchost.exe

This confirmed the malicious payload associated with the scheduled persistence.
---

### 🚩 Flag 10 – Command & Control (C2) IP

Question: What IP did the malware use as C2?
**Answer**: 78.141.196.6

><strong>KQL – Find Suspicious Network Connections from Malicious svchost</strong>
```kql
DeviceNetworkEvents
| where DeviceName == "AZUKI-SL"
| where InitiatingProcessFileName == "svchost.exe"
| summarize by RemoteIP, RemotePort
```

Step-by-step explanation:

DeviceNetworkEvents – Switched to network telemetry tied to processes.

InitiatingProcessFileName == "svchost.exe" – Focus on svchost, which was our malicious payload path.

summarize by RemoteIP, RemotePort – List out all remote IP/port pairs that this process contacted.

Among normal system traffic, a suspicious external IP stood out: 78.141.196.6 on an HTTPS port, flagged as the C2.
---

### 🚩 Flag 11 – Credential Dump Tool

Question: What binary was used to dump credentials?
**Answer**: Mm.exe
**MITRE**: T1003.001 – OS Credential Dumping (LSASS)

<strong>KQL – Find Suspicious EXE in Staging Paths</strong>
```kql
DeviceFileEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "Mm.exe"
```

Step-by-step explanation:

I searched file creation and modification events using DeviceFileEvents.

Narrowed the search to the suspicious file name Mm.exe, as indicated in the hunt.

Results showed this binary placed in staging locations used by the attacker, consistent with a credential dump utility.
---

### 🚩 Flag 12 – LSASS Dump Command

Question: What LSASS-related command was executed?
**Answer**: sekurlsa::logonpasswords

<strong>KQL – Detect Mimikatz-like sekurlsa Usage</strong>
```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where ProcessCommandLine has "sekurlsa::logonpasswords"
```

Step-by-step explanation:

Still in DeviceProcessEvents, I looked for classic Mimikatz command modules.

ProcessCommandLine has "sekurlsa::logonpasswords" – This is a strong indicator of credential theft from LSASS.

The query returned the malicious process execution containing this command, tying it to the credential dump activity.
---

### 🚩 Flag 13 – Data Staging Archive

Question: What file was used to stage data before exfiltration?
**Answer**: exportdata.zip
**MITRE**: T1560 – Archive Collected Data

<strong>KQL – Find Suspicious ZIP Creation</strong></summary>
```kql
DeviceFileEvents
| where DeviceName == "AZUKI-SL"
| where FileName endswith ".zip"
| where FolderPath has_any ("ProgramData", "WindowsCache", "Temp")
```

Step-by-step explanation:

Filtered for .zip file creations to look for staging archives.

Limited folder paths to suspicious locations used earlier (ProgramData, WindowsCache, Temp).

Among the results, exportdata.zip (or variant export-data.zip) appeared in these staging directories, strongly tied to the exfil workflow.
---

### 🚩 Flag 14 – Exfiltration Channel (Cloud Service)

Question: Which cloud service was used to exfiltrate data?
**Answer**: discord.com
**MITRE**: T1567.002 – Exfiltration to Cloud Services

<strong>KQL – Identify Cloud Service Used for Exfiltration</strong>
```kql
DeviceNetworkEvents
| where DeviceName == "AZUKI-SL"
| where RemoteUrl has "discord"
```


Step-by-step explanation:

Returned to DeviceNetworkEvents to investigate outbound traffic around the time of data staging.

RemoteUrl has "discord" – Filtered for connections to Discord domains.

The presence of repeated HTTPS connections to discord.com aligned with the exfiltration timeline, confirming Discord as the exfil channel.
---

### 🚩 Flag 15 – Log Tampering / Anti-Forensics

Question: Which command was used to clear the Windows event logs?
**Answer**: wevtutil cl Security
MITRE: T1070.001 – Clear Windows Event Logs

<strong>KQL – Detect wevtutil Log Clearing</strong>
```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
```


Step-by-step explanation:

FileName == "wevtutil.exe" – Focus on the native Windows log management tool.

ProcessCommandLine has "cl" – cl stands for clear, commonly used to wipe logs.

Inspecting the full ProcessCommandLine showed wevtutil cl Security, confirming that the attacker cleared the Security event log as part of anti-forensics.
---

### 🚩 Flag 16 – Anti-Forensics (Log Tampering)  
****Answer**:** `Security`  
**MITRE:** T1070.001 – Clear Windows Event Logs

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

Explanation:
Filtered for executions of wevtutil.exe with the cl (clear-log) argument within the investigation window. The command wevtutil cl Security confirmed the attacker cleared the Security event log to destroy forensic evidence.
---


4. Indicators of Compromise (IOCs)
Type	Value
Attacker IP	88.97.178.12
C2 IP	78.141.196.6
Compromised Account	kenji.sato
Persistence Account	support
Malicious Script	wupdate.ps1
Credential Tool	Mm.exe
Staging Archive	exportdata.zip
Exfil Service	discord.com
Hidden Directory	C:\ProgramData\WindowsCache
Excluded Path	C:\Users\KENJI~1.SAT\AppData\Local\Temp
5. MITRE ATT&CK Summary
Tactic	Technique ID	Technique Name
Initial Access	T1133	External Remote Services (RDP)
Execution	T1059.001	PowerShell
Persistence	T1053.005	Scheduled Task
Persistence	T1098	Account Manipulation
Defense Evasion	T1112	Modify Registry
Defense Evasion	T1562.001	Disable Security Tools
Defense Evasion	T1096	Hidden Files and Directories
Credential Access	T1003.001	OS Credential Dumping (LSASS)
Discovery	T1018	Remote System Discovery
Lateral Movement	T1021.001	Remote Desktop Protocol
Collection	T1560	Archive Collected Data
Exfiltration	T1567.002	Exfiltration to Cloud Storage Services
Exfiltration	T1048	Exfiltration Over Encrypted Channel (HTTPS)
Anti-Forensics	T1070.001	Clear Windows Event Logs
6. Tools Used

Microsoft Defender for Endpoint (MDE)

Advanced Hunting (KQL)

Windows Event Logs

MITRE ATT&CK Navigator (conceptually)

7. Lessons Learned

Exposed RDP without MFA is a high-risk entry point.

Defender exclusions (paths/extensions) should be tightly controlled and monitored.

Scheduled tasks, new local admins, and log clearing are high-signal events that should generate alerts.

Cloud collaboration apps (Discord, etc.) can double as covert exfiltration channels.
