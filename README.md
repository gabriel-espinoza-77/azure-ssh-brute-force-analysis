# Post-Incident Analysis: Azure SSH Brute-Force

This project documents a real-world post-incident analysis involving SSH brute-force attacks against virtual machines (VMs) within a Microsoft Azure tenant. The investigation was initiated following a Microsoft Security Notice and involved both manual threat hunting and the use of Microsoft Defender for Endpoint's (MDE) built-in Incidents Dashboard.

<p align="center">
  <img src="https://github.com/user-attachments/assets/c32678db-9bae-4a96-9e64-b5937919a599" alt="Screenshot description" width="600"/>
</p>

The goal of this project is to showcase deep forensic investigation techniques, detection logic development, and an understanding of threat behavior patterns using Microsoft tools and threat intelligence sources.

---

## Project Structure

| Path | Description |
|------|-------------|
| [`analysis/initial-threat-hunt.md`](analysis/initial-threat-hunt.md) | Manual threat hunting using MDE’s Advanced Hunting queries |
| [`analysis/mde-dashboard-review.md`](analysis/mde-dashboard-review.md) | Review of alerts and incidents detected automatically by MDE |
| [`analysis/observed-commands.md`](analysis/observed-commands.md) | Full list of malicious commands, scripts, and execution flows |
| [`analysis/virustotal-summary.md`](analysis/virustotal-summary.md) | Summary of malware samples analyzed through VirusTotal |

---

## Tools & Technologies Used

- Microsoft Defender for Endpoint (Advanced Hunting)
- Microsoft Azure
- VirusTotal (static malware analysis)
- ChatGPT (supportive analysis and enrichment)
- MITRE ATT&CK Framework

---

## Objectives

- Trace the origin and spread of SSH brute-force attacks targeting internal Azure VMs
- Identify indicators of compromise (IOCs), scripts, persistence mechanisms, and lateral movement attempts
- Demonstrate manual detection and enrichment techniques outside of automated alerting
- Map adversarial behavior to MITRE ATT&CK techniques for structured understanding

---

## Disclaimer

**All analysis presented in this repository is for **educational and professional development** purposes only.  
No real production environments were harmed or interfered with during this investigation.  
All systems analyzed were under the analyst's authorized scope.  
This investigation was conducted within a controlled cyber range environment using a personal Microsoft Azure tenant.**
