
### Threat Hunt – The Great Admin Heist
### Azuki Import/Export | Microsoft Defender for Endpoint (MDE)

![Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_for_Endpoint-blue)
![Category](https://img.shields.io/badge/Category-Threat_Hunting-red)

+ Analyst: Ernest Dicks
+ Platform: Microsoft Defender for Endpoint (MDE)
+ Tools: Advacned Hunting KQL, Microsoft Defender Tables, MITRE Microsoft Defender for Endpoint (MDE), Windows Events Logs

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

---

### 3. How I Solved Each Flag (Walkthrough + KQL)

---

### 🚩 Flag 1 – Initial Access IP  
Question: Question: Identify the source IP address of the Remote Desktop Protocol connection?

**Answer**: `88.97.178.12`  

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

**Answer**: `kenji.sato`

```kql
DeviceLogonEvents
| where DeviceName == "AZUKI-SL"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| distinct AccountName
```
## Step-by-step explanation:

Tightned the RDP query to only that suspicious IP and extracted the account involved. The result was kenji.sato.

Screenshot: <img width="1903" height="850" alt="image" src="https://github.com/user-attachments/assets/bec88398-6904-4aa4-8114-0c204480b6c6" />


---

### 🚩 Flag 3 – Discovery Command

Question: What discovery command did the attacker use?

**Answer**: `arp -a`

```KQL
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| project Timestamp, ProcessCommandLine, DeviceName, ProcessId, MD5
| where ProcessCommandLine has "arp"
```

## Step-by-step explanation:

Looked at process command lines for ARP usuage. The attacker ran arp -a enumerate local network neighbors.

Screenshot: <img width="1897" height="433" alt="image" src="https://github.com/user-attachments/assets/dd5ee7ab-bf93-4d74-b6c3-4f4b81dff662" />



---

### 🚩 Flag 4 – Hidden Directory Used for Staging

Question: Which hidden directory was used for staging?

**Answer***: `C:\ProgramData\WindowsCache`

```KQL 
let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName =~ "attrib.exe"
    or (FileName =~ "cmd.exe" and ProcessCommandLine has "attrib")
    or (FileName =~ "powershell.exe" and ProcessCommandLine has "attrib")
| where ProcessCommandLine has_any ("+h", "+s")
| project DeviceId,
          AttribTime = Timestamp,
          AttribCmd = ProcessCommandLine,
          AttribProc = FileName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by AttribTime desc
```

## Step-by-step explanation:

FileName == "attrib.exe" – I looked for Windows attrib utility executions.                                                                  
                                                                                                                                         
ProcessCommandLine has "+h" – +h sets the hidden attribute.                                                                                                              
                                                                                                                                        
ProcessCommandLine has "+s" – +s sets the system attribute.                                                                             

The command-line parameters revealed the path being hidden as C:\ProgramData\WindowsCache, indicating staging activity in a hidden folder.



Screenshot: <img width="1907" height="531" alt="image" src="https://github.com/user-attachments/assets/8509a3b9-d99e-4b51-aba0-d49c509fd05a" />

---

### 🚩 Flag 5 – Defender Extension Exclusions

Question: How many new file extensions were excluded in Defender?

**Answer**: `3 extensions`


```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where RegistryKey has @"Software\Microsoft\Windows Defender\Exclusions"
| where ActionType =~ "RegistryValueSet"
| where RegistryValueName in (".bat", ".ps1", ".exe")
| distinct RegistryValueName

```

## Step-by-step explanation:

DeviceRegistryEvents – I moved to registry telemetry to see configuration tampering.

RegistryKey contains "Exclusions\\Extensions" – Focused on Defender’s extension exclusion key.

Investigating the RegistryValueData for these events showed three malicious file extensions being exempted from scanning, weakening Defender coverage.



Screenshot: <img width="1885" height="330" alt="image" src="https://github.com/user-attachments/assets/23031054-2168-41c8-a646-adf58672e9e9" />

---

### 🚩 Flag 6 – Defender Path Exclusion

Question: Which path was excluded from Defender scanning?

**Answer**: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

<strong>KQL – Registry Changes to Defender Path Exclusions</strong>
```kql
let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T23:59:59Z);

DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where RegistryKey has @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
| where ActionType =~ "RegistryValueSet"
| distinct Timestamp, RegistryValueName
| order by Timestamp asc

```

## Step-by-step explanation:

Same approach as Flag 5, but pointed at the Paths exclusion key instead of Extensions.

By reviewing the RegistryKey and RegistryValueData, I confirmed that an exclusion was added for:

C:\Users\KENJI~1.SAT\AppData\Local\Temp

Excluding this Temp path allows malware dropped there to bypass Defender inspection.



Screenshot: <img width="1888" height="415" alt="image" src="https://github.com/user-attachments/assets/54c0b5a1-1756-4162-9800-ebd36dfb69ff" />

---

### 🚩 Flag 7 – Living-off-the-Land Downloader

Question: Which LoLBin was abused to download content?

**Answer**: `certutil.exe`

```kql
DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "certutil.exe"
| where ProcessCommandLine has_any ("http:", "https:")
```

## Step-by-step explanation:

Targeted known LoLBins often used for downloading (e.g., certutil).

FileName == "certutil.exe" – Limit to that binary.

ProcessCommandLine has_any ("http:", "https:") – Look for usage where URLs are present.

The results showed certutil being used with an HTTP/HTTPS URL, indicating a download of remote payloads.


Screenshot: <img width="1903" height="451" alt="image" src="https://github.com/user-attachments/assets/2a09bdc9-0768-4e3d-bd58-4cb11323d880" />

---

### 🚩 Flag 8 – Scheduled Task Name (Persistence)

Question: What is the name of the persistence scheduled task?
**Answer**: `Windows Update Check`

```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| extend TaskName = extract(@"(?i)/tn\s+\""?([^\""]+)\""?", 1, ProcessCommandLine)
| project Timestamp, DeviceName, TaskName, ProcessCommandLine
| order by Timestamp asc
```

## Step-by-step explanation:

FileName == "schtasks.exe" – Look for command-line creation of scheduled tasks.

ProcessCommandLine has "/create" – Filter for commands that are explicitly creating tasks.

Reviewing the output, I found a command line similar to:
schtasks /create /tn "Windows Update Check" ...

The /tn parameter revealed the scheduled task name: Windows Update Check.

Screenshot: <img width="1914" height="454" alt="image" src="https://github.com/user-attachments/assets/90f095b1-dd88-4821-95f3-74150fe20d01" />

---
### 🚩 Flag 9 – Scheduled Task Payload Path

Question: What binary is executed by the scheduled task?
**Answer**: `C:\ProgramData\WindowsCache\svchost.exe`


```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| extend TaskName = extract(@"(?i)/tn\s+\""?([^\""]+)\""?", 1, ProcessCommandLine)
| project Timestamp, DeviceName, TaskName, ProcessCommandLine
| order by Timestamp asc

```

## Step-by-step explanation:

Reused the Flag 8 query and added project to focus on the full command line.

Reviewing ProcessCommandLine, I located the /tr (task run) parameter.

The /tr argument showed that the task launches:
C:\ProgramData\WindowsCache\svchost.exe

This confirmed the malicious payload associated with the scheduled persistence.
---

### 🚩 Flag 10 – Command & Control (C2) IP

Question: Identify the IP address of the command and control server?
**Answer**: `78.141.196.6`

```kql
// Find outbound connections from the malicious executable
let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
  | where ActionType == "ConnectionSuccess"
| where DeviceName contains "azuki-sl"
| where RemotePort in (443, 80)
| where InitiatingProcessFileName in~ ("svchost.exe", "wupdate.ps1", "powershell.exe")
| where RemoteIP != "" and RemoteIP !startswith "10."
| summarize EventCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
  by RemoteIP
| order by EventCount desc
| take 90

```

## Step-by-step explanation:

DeviceNetworkEvents – Switched to network telemetry tied to processes.

InitiatingProcessFileName == "svchost.exe" – Focus on svchost, which was our malicious payload path.

summarize by RemoteIP, RemotePort – List out all remote IP/port pairs that this process contacted.

Among normal system traffic, a suspicious external IP stood out: 78.141.196.6 on an HTTPS port, flagged as the C2.

Screenshot: <img width="1866" height="844" alt="image" src="https://github.com/user-attachments/assets/835c6440-2707-4de8-8904-8e638b4e0682" />

---

### 🚩 Flag 11 – Credential Dump Tool

Question: Identify the destination port used for command and control communications?
**Answer**: `443`

```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "azuki"
| where InitiatingProcessFileName =~ "svchost.exe"
    or InitiatingProcessFileName =~ "wupdate.ps1"
    or InitiatingProcessFileName =~ "powershell.exe"
| where RemoteIP != "" and RemoteIP !startswith "10."
| project Timestamp,
          DeviceName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          Protocol
| order by Timestamp asc

```

## Step-by-step explanation:

I searched file creation and modification events using DeviceFileEvents.

Narrowed the search to the suspicious file name Mm.exe, as indicated in the hunt.

Results showed this binary placed in staging locations used by the attacker, consistent with a credential dump utility.

Screenshot:  <img width="1870" height="805" alt="image" src="https://github.com/user-attachments/assets/cf35d15a-1031-48b5-860d-7b480c336198" />

---

### 🚩 Flag 12 – LSASS Dump Command

Question: Identify the filename of the credential dumping tool?
**Answer**: `mm.exe`

```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where FolderPath has_any ("ProgramData", "WindowsCache", "Temp")
| where FileName matches regex @"^[a-zA-Z0-9]{1,3}\.exe$"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc


```
## Step-by-step explanation:

I set a time range from November 19 to November 22, 2025 to focus only on activity related to the suspected intrusion window.

Using the DeviceFileEvents table, I searched for file creation activity in known attacker staging directories, specifically ProgramData, WindowsCache, and Temp.

I then filtered for suspicious executable names made up of only 1–3 characters using a regex pattern, since attackers often use short, random file names to avoid detection

The results returned multiple short-named executables dropped into these staging paths, which strongly indicates malicious tool staging associated with the attack chain.

Screenshot: <img width="1897" height="526" alt="image" src="https://github.com/user-attachments/assets/f61563d4-dcd5-4d0c-80d2-0cfd8334863c" />

---

### 🚩 Flag 13 – Data Staging Archive

Question: Identify the module used to extract logon passwords from memory?
**Answer**: `sekurlsa::logonpasswords`

```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where ProcessCommandLine has_any ("sekurlsa::", "logonpasswords")
| project Timestamp,
          DeviceName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          ProcessCommandLine
| order by Timestamp asc

```

## Step-by-step explanation:

I first set a focused time window from November 19 to November 22, 2025 so I was only looking at process activity during the suspected attack period.

Using the DeviceProcessEvents table, I filtered on processes where the ProcessCommandLine contained either "sekurlsa::" or "logonpasswords", which are classic Mimikatz module names used for credential dumping from LSASS.

From there, I projected key fields like the timestamp, device name, initiating process, and full command lines to clearly see how and where the tool was executed.

The results showed processes executing these Mimikatz commands, which directly ties this activity to credential theft behavior in the environment.

Screenshot: <img width="1894" height="330" alt="image" src="https://github.com/user-attachments/assets/53c864a3-e650-4aa5-b114-1b71d50972b2" />

---

### 🚩 Flag 14 – Exfiltration Channel (Cloud Service)

Question: Identify the compressed archive filename used for data exfiltration?
**Answer**: `export-data.zip`

```kql
let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
| where FileName contains "export"
| where FolderPath has_any ("ProgramData", "WindowsCache", "Temp")
| project Timestamp, FileName, FolderPath
| order by Timestamp asc

```


## Step-by-step explanation:

I started by setting a time window from November 19 to November 22, 2025 to make sure I was only looking at file activity during the suspected attack period.

Using the DeviceFileEvents table, I filtered on events where the ActionType was "FileCreated", so I was only seeing newly created files, not reads or modifications.

From there, I narrowed it down to “.zip” files that contained the word “export” in the file name, since that pattern often lines up with data being packaged for exfiltration (for example, exported logs or user data).

Finally, I restricted the results to files created in ProgramData, WindowsCache, or Temp, which are common attacker staging directories, and projected the timestamp, filename, and folder path to clearly see when and where these export archives were created as part of potential data staging for exfiltration.

---

### 🚩 Flag 15 – Log Tampering / Anti-Forensics

Question: Identify the cloud service used to exfiltrate stolen data?
**Answer**: `discord`

```kql

```


## Step-by-step explanation:

FileName == "wevtutil.exe" – Focus on the native Windows log management tool.

ProcessCommandLine has "cl" – cl stands for clear, commonly used to wipe logs.

Inspecting the full ProcessCommandLine showed wevtutil cl Security, confirming that the attacker cleared the Security event log as part of anti-forensics.

---

### 🚩 Flag 16 – Anti-Forensics (Log Tampering)  
****Answer**:** `Security`  

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

## Step-by-step explanation:

I started by narrowing the time range to November 19–22, 2025 so I was only looking at process activity during the suspected attack window.

Using the DeviceProcessEvents table, I filtered specifically for the process wevtutil.exe, which is a Windows built-in utility used to manage event logs.

From there, I looked for commands where the ProcessCommandLine contained "cl", which is commonly used with wevtutil to clear event logs.

Finally, I projected the timestamp, device name, and full process command line, and sorted the results in descending order so I could quickly see the most recent attempts to clear or tamper with event logs, which lines up with defense evasion behavior.

Screenshot: <img width="1902" height="686" alt="image" src="https://github.com/user-attachments/assets/94bea4a6-f64c-45d2-a576-3fad0158b16b" />

---
### 🚩 Flag 17 – Anti-Forensics (Log Tampering)  
Question: Identify the backdoor account username created by the attacker?
**Answer**:** `Support`  


```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

## Step-by-step explanation:
I used the DeviceProcessEvents table and kept the same StartTime and EndTime window to stay within the confirmed attack timeframe.

I filtered for process command lines that contained /add, since that switch is commonly used when adding new user accounts.

I then added another filter for the word administrators to specifically isolate commands that were attempting to add a user to the local Administrators group.

Using the extract function, I pulled out the exact username that was added to the Administrators group directly from the command line for easier review.

Finally, I projected the timestamp, full command line, and extracted admin username, and ordered the results by time to clearly show when each privilege escalation attempt occurred.

Screenshot: <img width="1884" height="362" alt="image" src="https://github.com/user-attachments/assets/f9227c0e-478f-4073-8e0a-9cc7000ce132" />

---
---
### 🚩 Flag 18  EXECUTION ( Malicious Script )
Question:  Identify the PowerShell script file used to automate the attack chain?
**Answer**:** `wupdate.ps1`  


```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

## Step-by-step explanation:
I focused on DeviceProcessEvents within the confirmed attack window using the same StartTime and EndTime.

From there, I filtered for powershell.exe processes that were using Invoke-WebRequest/iwr with an OutFile parameter and a URL, which is a common pattern for downloading malicious scripts.

I then used extract on the ProcessCommandLine to pull out the actual .ps1 file name being written to disk via -OutFile.

The results showed PowerShell downloading and saving a script named wpudate.ps1, which I identified as the PowerShell script used to automate the attack chain.

Screenshot: <img width="1894" height="337" alt="image" src="https://github.com/user-attachments/assets/33dd2810-84ff-4940-935b-e8023789fce2" />

---

---
### 🚩 Flag 19 - LATERAL MOVEMENT - (Secondary Target)
Question: What IP address was targeted for lateral movement?
**Answer**:** `10.1.0.188`  


```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

Step-by-step explanation:
I started by using the DeviceProcessEvents table within the confirmed attack window using the same StartTime and EndTime.

From there, I filtered on processes where the FileName was either cmdkey.exe or mstsc.exe, since both are commonly used during lateral movement prep (saving credentials and launching Remote Desktop sessions).

I then used the extract function with a regex pattern to pull out any IP address from the ProcessCommandLine, treating that as the target system the attacker was trying to reach.

Next, I projected the timestamp, device name, filename, full command line, and the extracted TargetIP so I could clearly see which hosts were being targeted.

Finally, I filtered out any rows where TargetIP was empty and sorted everything in ascending time order to build a clean view of which remote systems the attacker was preparing to connect to and when.

Screenshot: <img width="1895" height="360" alt="image" src="https://github.com/user-attachments/assets/1b1842cb-143a-43d0-9dfe-d2a2b54905f3" />


---

---
### 🚩 Flag 20 – Anti-Forensics (Log Tampering)  
Question: Identify the remote access tool used for lateral movement?
**Answer**:** `mstsc.exe`  


```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

## ## Step-by-step explanation:
I used the DeviceProcessEvents table and kept the same StartTime and EndTime window to stay within the confirmed attack timeframe.

Using the DeviceProcessEvents table, I filtered specifically for the process wevtutil.exe, which is a built-in Windows tool used to manage event logs.

Then I narrowed it down further to commands where the ProcessCommandLine contained "cl", which is typically used with wevtutil to clear event logs.

Finally, I projected the timestamp, device name, and full process command line, and sorted the results in descending order, so I could quickly see the most recent attempts to clear or tamper with event logs, which lines up with defense evasion activity.

Screenshot: <img width="1885" height="459" alt="image" src="https://github.com/user-attachments/assets/0d4b3453-a830-41f4-b347-133d029ab0df" />


---

Recommendations
---




7. Lessons Learned

Exposed RDP without MFA is a high-risk entry point.

Defender exclusions (paths/extensions) should be tightly controlled and monitored.

Scheduled tasks, new local admins, and log clearing are high-signal events that should generate alerts.

Cloud collaboration apps (Discord, etc.) can double as covert exfiltration channels.
