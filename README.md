
### Threat Hunt – The Great Admin Heist
### Azuki Import/Export | Microsoft Defender for Endpoint (MDE)

![Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_for_Endpoint-blue)
![Category](https://img.shields.io/badge/Category-Threat_Hunting-red)

+ Analyst: Ernest Dicks
+ Platform: Microsoft Defender for Endpoint (MDE)
+ Tools: Advacned Hunting KQL, Microsoft Defender for Endpoint (MDE), Windows Events Logs
+ Date: Nov 22, 2025

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

/*
I started by looking for any RemoteInteractive logons on the target device during the incident window to see if there were
suspicious remote sessions and get a feel for what IPs and accounts were involved.
*/

let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');
let device = "azuki-sl";
DeviceLogonEvents
| where DeviceName == device
| where Timestamp between (StartTime .. EndTime)
| where LogonType == "RemoteInteractive"

/*
Once I confirmed that kenji.sato was the compromised account, I refined the search to only that account on the same device
 and timeframe, included both RemoteInteractive and Network logon types, and forced RemoteIP to be populated.
This let me reliably identify the exact RemoteIP used during the attacker’s remote access session and submit the correct flag.
*/

let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');
let device = "azuki-sl";
DeviceLogonEvents
| where DeviceName == device
| where AccountName == "kenji.sato"
| where Timestamp between (StartTime .. EndTime)
| where LogonType in( "RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| order  by Timestamp desc
```

Screenshot: <img width="1894" height="478" alt="image" src="https://github.com/user-attachments/assets/2eda25fa-4443-4e98-b478-4875ea9f3ad8" />


---
### 🚩 Flag 2 – Compromised Account

Question: Which account was used for the RDP compromise?

**Answer**: `kenji.sato`

```kql

 /*
The compromised account identified for Flag 2 was derived directly from the remote RDP session uncovered in Flag 1.  
 After isolating the malicious RemoteIP in Flag 1, I correlated that IP with DeviceLogonEvents to determine which 
account authenticated from that external source. The account consistently associated with the suspicious RemoteIP 
 during the incident window was confirmed as the compromised user for initial access.
*/

DeviceLogonEvents
| where DeviceName == "AZUKI-SL"
| where LogonType in( "RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| distinct AccountName
```

Screenshot: <img width="1903" height="850" alt="image" src="https://github.com/user-attachments/assets/bec88398-6904-4aa4-8114-0c204480b6c6" />


---

### 🚩 Flag 3 – Discovery Command

Question: What discovery command did the attacker use?

**Answer**: `ARP.EXE -a`

```KQL
/*
 This query hunts for network reconnaissance activity on the compromised host by searching for processes whose 
 command line contains common enumeration switches (-a or /a), which are frequently used with utilities like arp.exe 
 to list network neighbors. This helps identify post-compromise discovery activity following initial access.
*/

DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| project Timestamp, ProcessCommandLine, DeviceName, ProcessId, MD5
| where ProcessCommandLine has "arp"
```

Screenshot: <img width="1897" height="433" alt="image" src="https://github.com/user-attachments/assets/dd5ee7ab-bf93-4d74-b6c3-4f4b81dff662" />


---

### 🚩 Flag 4 – Hidden Directory Used for Staging

Question: Which hidden directory was used for staging?

**Answer***: `C:\ProgramData\WindowsCache`

```KQL

/* I used this query to look for any commands that were used to hide files or folders on the system during the attack window. 
  It checks for attrib being run directly or through Command Prompt or PowerShell, and looks specifically for the +h and +s 
  switches that mark items as hidden or system files. This helped me find where the attacker may have tried to hide their tools 
  or staging directory, and the output lets me see exactly who ran the command and how it was executed.
*/

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

Screenshot: <img width="1907" height="531" alt="image" src="https://github.com/user-attachments/assets/8509a3b9-d99e-4b51-aba0-d49c509fd05a" />


---

### 🚩 Flag 5 – Defender Extension Exclusions

Question: How many new file extensions were excluded in Defender?

**Answer**: `3`


```kql

/* After running this query, I reviewed all the file extensions that were added to Windows Defender
exclusions during the attack window. From the full list of results, I focused on the .bat, .ps1, and .exe extensions because they appeared at the very beginning of the 
 attack timeline. These stood out as the most relevant since they are commonly used to execute scripts and malware, indicating 
 they were likely added first to allow the attacker’s tools to run without being scanned.
*/

let StartTime = todatetime('2025-11-19T00:00:00Z');
let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where RegistryKey has @"Software\Microsoft\Windows Defender\Exclusions"
| where ActionType =~ "RegistryValueSet"
| where RegistryValueName in (".bat", ".ps1", ".exe")
| distinct RegistryValueName

```


Screenshot: <img width="1885" height="330" alt="image" src="https://github.com/user-attachments/assets/23031054-2168-41c8-a646-adf58672e9e9" />


---

### 🚩 Flag 6 – Defender Path Exclusion

Question: Which path was excluded from Defender scanning?

**Answer**: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

<strong>KQL – Registry Changes to Defender Path Exclusions</strong>
```kql

/* I used this query to find any folder paths that were added to Windows Defender’s exclusion list during the attack window.
 By filtering on the "Exclusions\\Paths" registry key and only keeping registry value set events, I was able to see exactly 
which directories were excluded from scanning.
*/

let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T23:59:59Z);

DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where RegistryKey has @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
| where ActionType =~ "RegistryValueSet"
| distinct Timestamp, RegistryValueName
| order by Timestamp asc

```


Screenshot: <img width="1888" height="415" alt="image" src="https://github.com/user-attachments/assets/54c0b5a1-1756-4162-9800-ebd36dfb69ff" />


---

### 🚩 Flag 7 – Living-off-the-Land Downloader

Question: Which LoLBin was abused to download content?

**Answer**: `certutil.exe`

```kql

/* I ran this query to look for any built-in Windows tools (LOLBins) that may have been abused to download files during the attack. 
 I filtered on common download-capable binaries like PowerShell, certutil, bitsadmin, curl, wget, mshta, and rundll32, and then 
 required the command line to contain an HTTP or HTTPS URL so I only see real download activity. 
 From there, I tagged each hit with a DownloaderType based on patterns in the command line (for example, certutil with -urlcache 
 or PowerShell using Invoke-WebRequest). This made it easier to quickly spot which native tool the attacker used for downloading 
 payloads and to answer the related flag about download utility abuse.
*/

DeviceProcessEvents
| where DeviceName == "AZUKI-SL"
| where FileName == "certutil.exe"
| where ProcessCommandLine has_any ("http:", "https:")


```


Screenshot: <img width="1903" height="451" alt="image" src="https://github.com/user-attachments/assets/2a09bdc9-0768-4e3d-bd58-4cb11323d880" />


---

### 🚩 Flag 8 – Scheduled Task Name (Persistence)

Question: What is the name of the persistence scheduled task?

**Answer**: `Windows Update Check`

```kql

/* I used this query to find any scheduled tasks that were created during the attack window. 
  By filtering for schtasks.exe with the /create option, I was able to isolate only task creation activity. 
  I then extracted the task name directly from the command line so I could clearly see what the attacker named 
  the task and match it to the persistence flag. Sorting by time helped me place the task creation correctly 
  in the attack timeline.
*/

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


Screenshot: <img width="1914" height="454" alt="image" src="https://github.com/user-attachments/assets/90f095b1-dd88-4821-95f3-74150fe20d01" />


---
### 🚩 Flag 9 – Scheduled Task Payload Path

Question: What binary is executed by the scheduled task?

**Answer**: `svchost.exe`


```kql

 /*
After I used this query to pull out the scheduled task name for persistence (Flag 8), I reused the same results to answer 
 Flag 9 by looking directly at the full ProcessCommandLine. The schtasks command includes a /tr parameter, which specifies 
 the executable that the task runs. By inspecting that /tr value in the command line for the malicious task, I was able to 
 identify the exact executable path configured in the scheduled task and use that as the answer for this flag.
*/

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

Screnshot: <img width="1885" height="522" alt="image" src="https://github.com/user-attachments/assets/bf5476b4-331a-4058-aad4-1b9dccaefae6" />


---

### 🚩 Flag 10 – Command & Control (C2) IP

Question: Identify the IP address of the command and control server?

**Answer**:  `78.141.196.6`

```kql
/* I used this query to look for any outbound network connections made by the suspected malicious processes during the attack window. 
   I focused on svchost.exe, wupdate.ps1, and powershell.exe because those were tied to earlier malicious activity. 
   I filtered out internal IP addresses so I only saw true external connections, then reviewed the remaining RemoteIP values.
*/
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


Screenshot: <img width="1866" height="844" alt="image" src="https://github.com/user-attachments/assets/835c6440-2707-4de8-8904-8e638b4e0682" />


---

### 🚩 Flag 11 – Credential Dump Tool

Question: Identify the destination port used for command and control communications?

**Answer**: `443`

```kqL

/*
 In this query, I focused on outbound connections from the suspected malicious processes (svchost.exe, wupdate.ps1, and powershell.exe) 
 on the azuki host during the known attack window. I filtered out internal IP addresses so I only saw external traffic, then looked at 
 the RemotePort field for those C2-style connections.
*/
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

Screenshot:  <img width="1870" height="805" alt="image" src="https://github.com/user-attachments/assets/cf35d15a-1031-48b5-860d-7b480c336198" />


---

### 🚩 Flag 12 – LSASS Dump Command

Question: Identify the filename of the credential dumping tool?

**Answer**: `mm.exe`

```kql
/*
 I used this query to look for suspicious executables that were created in common staging and temporary locations 
 like ProgramData, WindowsCache, and Temp during the attack window. I specifically filtered for very short 
1–3 character .exe filenames because attackers often rename credential dumping tools this way to blend in and 
 avoid detection. This helped me narrow in on the most likely malicious tool used during the credential access phase.
*/

let StartTime = todatetime('2025-11-19T00:00:00Z');

let EndTime = todatetime('2025-11-22T23:59:59Z');

DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where FolderPath has_any ("ProgramData", "WindowsCache", "Temp")
| where FileName matches regex @"^[a-zA-Z0-9]{1,3}\.exe$"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc


```


Screenshot: <img width="1897" height="526" alt="image" src="https://github.com/user-attachments/assets/f61563d4-dcd5-4d0c-80d2-0cfd8334863c" />


---

### 🚩 Flag 13 – Data Staging Archive

Question: Identify the module used to extract logon passwords from memory?

**Answer**: `sekurlsa::logonpasswords`

```kql

/*
  I identified a suspicious short-named executable staged in the malware directory, 
 which matched the hint about a renamed credential dumping tool. The next hint pointed to LSASS memory access,
which is a common target for tools like Mimikatz used to dump credentials. Knowing that Mimikatz uses the 
 "sekurlsa::logonpasswords" module to extract credentials from memory, I searched for those exact strings in the 
 ProcessCommandLine.
*/

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


Screenshot: <img width="1894" height="330" alt="image" src="https://github.com/user-attachments/assets/53c864a3-e650-4aa5-b114-1b71d50972b2" />

---

### 🚩 Flag 14 – Exfiltration Channel (Cloud Service)

Question: Identify the compressed archive filename used for data exfiltration?

**Answer**: `export-data.zip`

```kql

/*
 I ran this query to look for any ZIP files that were created in common staging or temporary locations during the attack window. 
 Since attackers often compress stolen data before exfiltrating it, I filtered on .zip files created under folders like ProgramData, 
 WindowsCache, and Temp. This helped me pinpoint the archive that was likely used to bundle the collected data
*/
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



---

### 🚩 Flag 15 – Log Tampering / Anti-Forensics

Question: Identify the cloud service used to exfiltrate stolen data?

**Answer**: `discord`

```kql

/* I ran this query to see all the different external websites and services that the "azuki" device communicated with.
  This helps me quickly spot any strange or unfamiliar domains that could be related to command-and-control
  activity, cloud services, or possible data exfiltration. THe first query returned 95 results, then I limited the results to
  the first 20 unique domains and planned to scan the results in batches until I found thecorrect flag.
*/

DeviceNetworkEvents
| where DeviceName contains "azuki"
| where RemoteUrl != ""
| distinct RemoteUrl 
| order by RemoteUrl asc 


DeviceNetworkEvents
| where DeviceName contains "azuki"
| where RemoteUrl != ""
| distinct RemoteUrl 
| order by RemoteUrl asc 
| take 20
```

Screenshot: <img width="1872" height="838" alt="image" src="https://github.com/user-attachments/assets/2be9ccdf-d119-4f02-af77-d5a946496853" />


---

### 🚩 Flag 16 – Anti-Forensics (Log Tampering)  

Question: Identify the first Windows event log cleared by the attacker?

**Answer**: `Security`  

```kql

/* I used this query to check if the attacker tried to cover their tracks by clearing any Windows event logs during the attack window. 
  By filtering for wevtutil.exe with the "cl" (clear log) command, I was able to isolate log deletion activity. I then extracted 
  the specific log name that was cleared from the command line so I could determine which log the attacker targeted first
*/

DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19T00:00:00Z) .. datetime(2025-11-22T23:59:59Z))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc

```


Screenshot: <img width="1902" height="686" alt="image" src="https://github.com/user-attachments/assets/94bea4a6-f64c-45d2-a576-3fad0158b16b" />

---
### 🚩 Flag 17 – Anti-Forensics (Log Tampering)  

Question: Identify the backdoor account username created by the attacker?

**Answer**: `Support`  


```kql

/* I used this query to look for any commands to add a user
  to the local Administrators group. I filtered for the "/add" and "administrators" keywords in the
  command line to catch possible privilege escalation or unauthorized admin account creation
  during the investigation time window.
*/
let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T23:59:59Z);

DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where ProcessCommandLine has "/add"
| where ProcessCommandLine has "administrators"
| extend AdminUser = extract(@"administrators\s+(\S+)", 1, ProcessCommandLine)
| project Timestamp, ProcessCommandLine, AdminUser
| order by Timestamp asc

```


Screenshot: <img width="1884" height="362" alt="image" src="https://github.com/user-attachments/assets/f9227c0e-478f-4073-8e0a-9cc7000ce132" />


---
---
### 🚩 Flag 18  EXECUTION ( Malicious Script )

Question:  Identify the PowerShell script file used to automate the attack chain?
**Answer**: `wupdate.ps1`  


```kql

/*
 I ran this query to look for PowerShell commands on the system that were used to download files from the internet.
 I filtered for common download methods like Invoke-WebRequest and "iwr", along with web URLs and the "OutFile"
 parameter, to identify potential malicious file downloads during the investigation time window.
*/

let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T00:00:00Z);

DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr", "http://", "https://")
| where ProcessCommandLine has "OutFile"
| project Timestamp,
          InitiatingProcessFileName,
          ProcessCommandLine
| order by Timestamp asc

```

Screenshot: <img width="1894" height="337" alt="image" src="https://github.com/user-attachments/assets/33dd2810-84ff-4940-935b-e8023789fce2" />

---

---

### 🚩 Flag 19 - LATERAL MOVEMENT - (Secondary Target)

Question: What IP address was targeted for lateral movement?
**Answer**: `10.1.0.188`  


```kql
/*
 I used this query to check for possible lateral movement activity by looking for commands
 associated with remote access and credential use, such as cmdkey and mstsc.
 I also extracted any IP addresses from the command line to identify which systems were
 potentially being targeted for remote connection during the investigation timeframe.
*/

let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T23:59:59Z);

// Look for lateral movement prep commands (cmdkey, mstsc, runas)
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName in~ ("cmdkey.exe", "mstsc.exe")
| extend TargetIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 0, ProcessCommandLine)
| project Timestamp,
          DeviceName,
          FileName,
          ProcessCommandLine,
          TargetIP
| where isnotempty(TargetIP)
| order by Timestamp asc

```


Screenshot: <img width="1895" height="360" alt="image" src="https://github.com/user-attachments/assets/1b1842cb-143a-43d0-9dfe-d2a2b54905f3" />


---

---
### 🚩 Flag 20 – Anti-Forensics (Log Tampering)  

Question: Identify the remote access tool used for lateral movement?
**Answer**: `mstsc.exe`  


```kql
/*
 I ran this query to find any Remote Desktop (RDP) connection attempts made using mstsc.exe
 during the investigation timeframe. I pulled out any IP addresses from the command line
 to see which systems were being targeted for remote access and to identify possible
lateral movement activity.
*/

let StartTime = datetime(2025-11-19T00:00:00Z);
let EndTime   = datetime(2025-11-22T23:59:59Z);

DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName =~ "mstsc.exe"
| extend Target = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 0, ProcessCommandLine)
| project Timestamp, FileName, 

```



Screenshot: <img width="1885" height="459" alt="image" src="https://github.com/user-attachments/assets/0d4b3453-a830-41f4-b347-133d029ab0df" />



---

✅ Recommendations 

+ Tighten monitoring on admin accounts
  
Admin accounts should be closely watched at all times. Any time a user is added to the Administrators group, or when admin tools are used, it should trigger an alert so this activity can be reviewed immediately.

+ Turn on full PowerShell and command logging
  
PowerShell was a major part of this investigation. Enabling detailed PowerShell logging and keeping full command-line logs will make it much easier to catch malicious downloads, scripts, and hidden activity in the future.

+ Watch outbound web traffic more closely
  
Outbound HTTPS traffic to unfamiliar cloud services should be monitored more aggressively. Large file uploads or connections to unknown websites could be a sign of data exfiltration and should be investigated quickly.

+ Lock down remote access between systems
  
Remote Desktop access should only be allowed where it is clearly necessary. Internal systems should be segmented, and any unusual remote connections between devices should be reviewed to prevent lateral movement.

+ Turn hunt queries into real security alerts
  
The queries used in this threat hunt should be converted into real-time alerts inside the SIEM or EDR. This will allow future suspicious activity to be detected immediately instead of only during manual investigations.

---

🧠 Final Thoughts

This threat hunt showed how important it is to look beyond alerts and dig directly into endpoint and network activity. By following the evidence step-by-step, 
I was able to piece together how administrative access, PowerShell activity, lateral movement, and outbound network traffic can all connect in a real 
attack scenario. Even though this was a lab environment, the techniques used closely mirror what would be seen in a real enterprise investigation. 
This project strengthened my ability to think like a defender, ask the right investigative questions, and validate suspicious behavior using data rather than 
assumptions. Moving forward, the skills and detection logic built here can be directly applied to real-world SOC and incident response operations.


