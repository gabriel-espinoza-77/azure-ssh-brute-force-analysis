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
> **Phase 2**: Review of MDE’s Incidents Dashboard (see `mde-dashboard-review.md`)

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

