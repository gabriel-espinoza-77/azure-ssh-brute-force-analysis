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

### February 17, 2025 8:37 PM — First Suspicious Activity (Not Detected)

Suspsicous activity was detected during the earliest stages of compromise on `Linux-VulnMgmt-Kobe`. A large number of failed SSH sign-in attempts followed by a successful brute-force login from a Microsoft Azure IP was detected. The system then executed scripts that disabled firewall protections and retrieved multiple malicious files from `194.32.145.243`.

**Note:** *Process starts the SSH daemon and listens for incoming SSH connections, subsequently, there was a successful logon from the source address 20.80.241.91. The address itself isn't known to be malicious as the address is form the Microsofts Azure cloud services, but the activity it performs after from this device shows that this is the inital Indicator of Compromise. The address performs many logon attempts but fails until they are successful indicating a successful brute-force.*

<p align="center">
  <img src="https://github.com/user-attachments/assets/9d1387fd-0dfe-47ed-b662-f961fc7cc5ab" alt="Screenshot description" width="700"/>
  <img src="https://github.com/user-attachments/assets/cac9b34b-0d24-4e30-aeb5-9cc31a8d8bd1" alt="Screenshot description" width="750"/>
</p>

Device later performs a process using this command:

```bash
bash -c "pkill firewalld  -9;pkill iptables -9;ulimit -e 999999;... -rf .bash_history; history -c
```
[View full command → `observed-commands.md`](./observed-commands.md#bisis-ssh-brute-force-command)

**Command Details:**
- Disables local firewall services by terminating `firewalld` and `iptables` processes
- Increases system resource limits via `ulimit` to support high-volume execution and network activity
- Downloads and executes multiple payloads(`logsbins.sh`, `logstftp1.sh` and `logstftp2.sh`) from the malicious IP `194.32.145.243` using `wget`, `curl` and `tftp`
- Performs cleanup operations by deleting payloads, clearing shell history, and removing evidence of execution

**VirusTotal Score:**
- `194.32.145.243`: `12/94`

**Note:** **


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


