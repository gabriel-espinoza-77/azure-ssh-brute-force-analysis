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
> **Phase 2**: Review of MDE’s Incidents Dashboard (see [`mde-dashboard-review.md`](../mde-dashboard-review.md))


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

> 🖼️ *Insert Screenshot 1: DeviceInfo query showing IP-to-hostname mapping for `sakel-lunix-2`*

**Status:** ✅ *Confirmed Malicious*

---

### 🔎 Finding #2 — Execution of `.bisis` SSH Brute-Force Binary

**Command Executed:**
```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```
[View full command → `observed-commands.md`](analysis/observed-commands.md#bisis-ssh-brute-force-command)

**Details:**  
- `.bisis` is a hidden binary located in a non-standard `/var/tmp/.update-logs/` path  
- Executes SSH attempts using a config file (`data.json`)  
- 8-second timeout suggests aggressive brute-forcing or scanning  
- Used repeatedly from the source device across multiple sessions

> 🖼️ *Insert Screenshot 2: DeviceProcessEvents showing `.bisis` execution on `sakel-lunix-2`*

**VirusTotal Score:** `6/64`  
**Likely Role:** SSH brute-force tool

**Mapped MITRE Techniques:**  
- `T1110.001` — Brute Force: Password Guessing  
- `T1059` — Command and Scripting Interpreter

**Status:** ✅ *Confirmed Malicious*

---

### 🔎 Finding #3 — Persistence via Cron Jobs and Obfuscated Executables

**Command Observed:**
```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x /var/tmp/.update-logs/.bisis ; ulimit -n 999999 ; cat iplist | ./bisis ... ; ./x"
```
[View full command → `observed-commands.md`](../observed-commands.md#bisis-cron-command)

**Details:**  
- Launches `.bisis`, `.b`, and `x` — multiple hidden executables  
- Uses `ulimit` to raise system resource limits  
- Cron jobs and `disown` used to enable background persistence  
- Behavior consistent with long-term automation and stealth execution

> 🖼️ *Insert Screenshot 3: Cron configuration or background process tree showing persistence behavior*

**VirusTotal Score (cache):** `31/64`  
**Likely Role:** Persistence mechanism and loader

**Mapped MITRE Techniques:**  
- `T1053.003` — Scheduled Task/Job: Cron  
- `T1027` — Obfuscated Files or Information  
- `T1036` — Masquerading

**Status:** ✅ *Confirmed Malicious*
