## VirusTotal Summary – Files and Domains

| Name         | SHA256                                                              | VirusTotal Score | Likely Function         | Associated Command (if applicable)                                                                                             |
|--------------|----------------------------------------------------------------------|------------------|-------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| .b           | a9a4f021f91d1f35888c4e2fe7d2af2d458de8c8aba4f5815f1ed3125650c28f     | N/A              | !!Persistence Script      | `/bin/bash /var/tmp/.update-logs/./.b`                                                                                        |
| x            | 0e771c5965bc740210b4e75ac3b6686f5c3fbcf83604e8a2c578814347dea8c2     | N/A              | !!Auxiliary Payload       | Part of bash sequence after `.bisis` brute-force execution                                                                    |
| .bisis       | 2828ca39e2a5b0fd3b0968bc75b67b4c587a49c13929a6cb050b0989ee01cd22     | 6/64             | SSH Brute-Force Tool    | `/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8`                          |
| Update       | dbc96f3dc4f4bf0616cb3d9e661d911db421b7ef245304a976c5c09a1207b346     | N/A              | !!Loader / Dropper        | Executed after `History`, initiates `.bisis` and other payloads                                                               |
| History      | d915702b236eb69b9e3c518913580e65d4be0b3d320d28152549ef7bed93a23b     | N/A              | !!Initial Script Trigger  | `/bin/bash /var/tmp/.update-logs/./History`                                                                                   |
| UpzBUBnv     | 81d9ef2342cb1d7329a6b53297678c925b0b5380b2add63a140db83fa046a83d     | N/A              | !!Suspicious Executable   | Dropped via SCP; used as an early-stage executable on compromised system                                                     |
| cache/.balu  | 0e13e9e4443102bf5b26396b5319f528642b4f0477feb9c7f536fab379b73074     | 34/64            | Cryptominer             | Downloaded and executed as `./cache` via `./network` script                                                                  |
| kuak         | 11d43b9ef1678a889cfbca33ca13314d07824753965cafb28d4030644a2c5ccd     | 31/64            | Cryptominer             | Deployed by `./network` script; executed from `/var/tmp/Documents/kuak`                                                      |
| diicot       | 9462261543bfaf008f4748c76a7a2aec95d67f73315d1adea1833d51f9ec29f6     | 9/65             | Cryptominer             | Hidden file launched from `/var/tmp/Documents/.diicot`, tied to known Diicot campaigns                                       |
| dinpasiune.com | *No SHA256 (domain only)*                                          | 12/94            | Payload Hosting Domain  | Used in `./retea` script and curl commands to download and execute remote payloads                                           |
| 85.31.47.99  | *No SHA256 (IP address)*                                             | 11/94            | Payload Hosting IP      | Accessed via curl in `./network` and `./retea` scripts to download `cache` and `.balu` payloads                              |

---

### Descriptions and Observations

- **`.b`**: A persistence script likely used to schedule or trigger other payloads (e.g., via cron). VirusTotal score is low but behavior is consistent with persistence.
- **`x`**: Auxiliary file invoked after `.bisis` runs SSH brute-force attempts. Score is low; file may evade detection due to minimal signature.
- **`.bisis`**: Core brute-force tool used to launch SSH attacks on internal and external IPs. Score is moderate and flagged as PUA.PortScan.
- **`Update`**: Central loader used repeatedly across compromised devices. Responsible for invoking `.bisis`, `x`, and others. Often executed via cron.
- **`History`**: Triggers the initial infection chain; likely a shell script used to start execution of `Update`. Minimal detection likely due to obfuscation.
- **`UpzBUBnv`**: Suspicious binary transferred via SCP. Score of 8/64 and unknown purpose, but tightly linked to malicious sequences and lateral movement.
- **`cache` / `.balu`**: Clear cryptomining binary. High detection rate (34/64). Delivered via `curl` from known malicious infrastructure.
- **`kuak`**: Second cryptomining component. Detected aggressively (31/64), indicating known malicious signature.
- **`diicot`**: Lower VT score (9/65) than `kuak` but still flagged. Tied to known Romanian Diicot threat group malware.
- **`dinpasiune.com`**: Used to serve payloads in both `./retea` and `./network` scripts. Flagged on VirusTotal with a 12/94 score.
- **`85.31.47.99`**: IP associated with payload retrieval. Involved in both `cache` and `.balu` delivery; VT score is 11/94.

---

**Note**: Some file functions were inferred from observed behavior and command usage rather than static analysis alone. All VirusTotal scores are as of the latest scan and may fluctuate as new detections emerge.


