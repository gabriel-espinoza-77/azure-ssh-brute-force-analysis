# Initial Threat Hunt: Azure SSH Brute-Force (Manual Analysis via MDE Advanced Hunting)

## 1. Objective

To identify, analyze, and document SSH brute-force activity targeting virtual machines (VMs) within a Microsoft Azure tenant. This phase focuses on **manual threat hunting** using Microsoft Defender for Endpoint (MDE)’s Advanced Hunting capabilities, rather than relying on MDE's automated Incidents Dashboard. This decision was made to showcase practical investigation and hunting techniques as part of an end-to-end post-incident analysis.

---

## 2. Scope

- **Environment**: Microsoft Azure tenant  
- **Timeframe**: March 14, 2025 – April 3, 2025  
- **Tools Used**:
  - Microsoft Defender for Endpoint (Advanced Hunting)
  - VirusTotal
  - ChatGPT (for log interpretation and enrichment)

- **Access Constraints**:
  - Only VMs personally deployed by the analyst were accessible
  - Isolation of other users' devices was not permitted due to tenant policy
  - Log data was limited by a 30-day retention window, preventing full root-cause tracing of earliest activity

> 🔁 This investigation is conducted in two phases:  
> **Phase 1 (this file)**: Manual log-based hunting  
> **Phase 2**: Review of MDE’s Incidents Dashboard (see [`mde-dashboard-review.md`](./mde-dashboard-review.md))


---

## 3. Methodology

Investigation was initiated based on a Microsoft security alert indicating SSH brute-force behavior from internal IP `20.81.228.191`. Manual threat hunting was conducted using KQL queries across multiple schemas in MDE:

- `DeviceInfo` to identify affected systems
- `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` to trace behavior
- VirusTotal to enrich SHA-256 hashes and assess malware reputation
- MITRE ATT&CK used for TTP classification (linked in `mitre-attack-mapping.md`)

### Base Query Template

```kql
DeviceNetworkEvents
| where DeviceName == "<target_device>"
| where Timestamp between (datetime(<start>) .. datetime(<end>))
| where InitiatingProcessCommandLine !contains "nessus"
      and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
      and InitiatingProcessCommandLine !contains "tenable"
```
---

## 4. Findings

### 🔎 Finding #1 — Source Device Attribution

**Indicator:**  
`20.81.228.191` (internal Azure IP flagged in Microsoft security notice)

**Associated Device:**  
`sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

**Timeframe:**  
`March 14, 2025 @ 12:41 UTC` → `March 18, 2025 @ 02:24 UTC`

**Behavior Observed:**  
- Over **99,000** SSH connection attempts in a short timeframe  
- Brute-force behavior originating from a single internal system  
- IP-to-device attribution confirmed via `DeviceInfo` schema

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

**Query Used:**
```kql
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

**Status:** ✅ *Confirmed Malicious*

---

### 🔎 Finding #2 — Execution of `.bisis` SSH Brute-Force Binary

**Command Executed:**
```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-ssh-brute-force-command)

**Details:**  
- `.bisis` is a hidden binary located in a non-standard `/var/tmp/.update-logs/` path  
- Executes SSH attempts using a config file (`data.json`)  
- 8-second timeout suggests aggressive brute-forcing or scanning  
- Used repeatedly from the source device across multiple sessions

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where InitiatingProcessCommandLine !contains "nessus" and InitiatingProcessCommandLine !contains "/var/lib/waagent/"
and InitiatingProcessCommandLine !contains "tenable"
| where ActionType == "ConnectionRequest"
| summarize CommandOccurrence = count() by InitiatingProcessCommandLine, ActionType
| order by CommandOccurrence desc
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/0b6fb247-4307-4c8b-8ae7-f0ff4419c696" alt="Screenshot description" width="800"/>
</p>

**VirusTotal Score:** `6/64`  
**Likely Role:** SSH brute-force tool

**Mapped MITRE Techniques:**  
- `T1110.001` — Brute Force: Password Guessing  
- `T1059` — Command and Scripting Interpreter

**Status:** ✅ *Confirmed Malicious*

---

### 🔎 Finding #3 — Repeated Execution of `.bisis` and Obfuscated Payloads

**Command Observed:**
```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x /var/tmp/.update-logs/.bisis ; ulimit -n 999999 ; cat iplist | ./bisis ... ; ./x"
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-repeated-execution-command)

**Details:**  
- Executes `.bisis`, `.b`, and `x` — multiple hidden binaries  
- Uses `ulimit` to raise system limits for high concurrency  
- Behavior indicates repeated brute-force and secondary payload execution  
- No scheduled task or cron job confirmed

> 🖼️ *Insert Screenshot 3: Process tree or timeline showing `.bisis` and `./x` execution*

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where Timestamp between (datetime(2025-03-14T16:41:22.631607Z) .. datetime(2025-03-14T20:46:16.607719Z))
| where FolderPath contains "update-logs"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/ecc9ca13-cca3-42a5-84c7-e8d9b479d76a" alt="Process execution of .bisis and x" width="800"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/0ad63c32-9742-4013-822b-fe89b1c1f27e" alt="Process execution of .bisis and x" width="300"/>
  <img src="https://github.com/user-attachments/assets/1c5b83cd-5b2f-4985-bb88-2cf3fe6370fc" alt="Process execution of .bisis and x" width="300"/>
</p>


**VirusTotal Score (cache):** `31/64`  
**Likely Role:** Brute-force tool and follow-up loader

**Mapped MITRE Techniques:**  
- `T1027` — Obfuscated Files or Information  
- `T1036` — Masquerading

**Status:** ✅ *Confirmed Malicious*
