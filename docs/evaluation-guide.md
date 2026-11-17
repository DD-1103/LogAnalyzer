# Evaluation guide (thesis chapter 6)

This guide shows how to produce the numbers for the three research questions with the tools in this repository.
All commands are run from the repository root in a terminal (VS **Developer PowerShell** works).

Build the tools once:

```powershell
dotnet build tools/LogAnalyzer.Tools
$tools = "tools/LogAnalyzer.Tools/bin/Debug/net10.0/loganalyzer-tools.exe"
```

> **Data rule:** use only public datasets and logs you generate in your own lab. Never use logs from AKSK or any employer.

---

## 1. Datasets

| Dataset | What it tests | How labels are made |
|---|---|---|
| `samples/sample-access.log` (2,933 lines) | smoke test – written to match the rules, so 100 % only proves the engine works | hand-written `sample-access.labels.csv` |
| Synthetic log (`generate`) | RQ3 performance at any size; RQ1/RQ2 on realistic traffic mixes incl. evasive attacks and benign crawlers | generator writes labels per line |
| CSIC 2010 HTTP dataset | RQ1 signature rules on independent, public attack data | `normal` / `attack` from the two files |
| DVWA lab (Kali → Apache) | RQ1 + RQ2 on real tool traffic (sqlmap, Hydra, Nikto, gobuster) | `label-by-ip` (attacker VM IP) |

---

## 2. Synthetic logs (RQ3, plus a first RQ1/RQ2 look)

```powershell
& $tools generate --lines 1000000 --out big.log --seed 42          # writes big.log + big.labels.csv
& $tools bench --log big.log --labels big.labels.csv               # CPU-only timings + accuracy
```

Then upload `big.log` in the web app (Log files → Upload), wait for *Completed*, open the file:
the page shows **Parse + import**, **Detection** and **Total** time. Upload `big.labels.csv` on the **Evaluate** page.

Reference run (developer laptop, 24 logical CPUs, Debug build, seed 42):

| | value |
|---|---|
| lines | 1,000,000 (209 MB, 18,849 IPs, 2.0 % attacks) |
| parse (CPU only) | ≈ 8 s (≈ 125,000 lines/s) |
| rules | ≈ 1.5–2 s, 150 alerts |
| Isolation Forest | ≈ 0.3 s, 58 anomalous IPs |
| **rules only** | precision 99.7 %, recall 96.1 %, F1 97.9 %, FPR 0.01 % |
| **Isolation Forest only** | precision 87.9 %, recall 99.9 %, F1 93.5 %, FPR 0.28 % |
| **rules + Isolation Forest** | precision 87.7 %, recall 100 %, F1 93.4 %, FPR 0.29 % |

What the generator deliberately includes (so results are not trivially perfect):
* evasive payloads the regexes miss (e.g. `1 AND 5821=5821`, `WAITFOR DELAY`, `<details ontoggle=…>`, `/etc/hosts`, `..%c0%af`);
* sqlmap / dirbuster with a spoofed browser user agent (30 %);
* low-and-slow brute force (5–15 s between attempts, under the 20/min threshold);
* benign look-alikes: search-engine crawlers with old 404 links, odd but harmless searches (`o'neill`, `deals--`, `1=1 offer`), failed logins by real users, an uptime monitor.

Report these as *synthetic* results; the real accuracy claims come from CSIC 2010 and the lab.

**Protocol for RQ3:** run each size (100k, 500k, 1M, 2M) three times, report mean ± min/max of the web app's
*Total* time, plus machine specs (CPU, RAM, SSD, SQL Server edition). Note that SQL Server import dominates
(the CPU-only `bench` shows how much is parsing vs. database work).
Run the database in the **SIMPLE recovery model** (done on 2026-11-17; check with
`SELECT recovery_model_desc FROM sys.databases WHERE name = 'LogAnalyzerDb'`), otherwise every 1M-row import and
delete is fully logged once a backup exists. Also time the dashboard (`/`), a deep events page
(`/LogFiles/Details/{id}?page=20000`) and a rule *Test* on the 1M file. Files larger than the limits in
`Processing` (5M lines, 2 GB decompressed, 50x gzip ratio) are rejected; raise them in appsettings for bigger runs.

---

## 3. CSIC 2010 (RQ1)

1. Download the dataset yourself (search "HTTP DATASET CSIC 2010"; files `normalTrafficTest.txt` and
   `anomalousTrafficTest.txt`). Check the license / citation requirement and cite it in the thesis.
2. Convert:

   ```powershell
   & $tools csic --normal normalTrafficTest.txt --anomalous anomalousTrafficTest.txt --out csic.log
   & $tools csic --normal normalTrafficTest.txt --anomalous anomalousTrafficTest.txt --out csic-body.log --body-as-query
   ```

3. Upload both logs, then evaluate each with its `.labels.csv`.

Interpretation:
* Access logs never contain POST bodies, so the first file is the **realistic** scenario; `--body-as-query`
  is the **upper bound** if the server logged bodies (as a WAF would). The difference is a finding in itself.
* CSIC has no real clients or timestamps (they are synthesised), so only the **signature rules** are meaningful;
  disable the threshold and anomaly rules (or ignore their rows) for this dataset.
* CSIC "anomalous" also contains non-attack anomalies (typos, wrong parameter types), which lowers recall of
  attack signatures – discuss this, don't hide it.

---

## 4. DVWA lab (RQ1 + RQ2 with real tools)

### Setup (VirtualBox, host-only network 192.168.56.0/24)

| VM | Role | Example IP |
|---|---|---|
| Ubuntu Server 24.04 | Apache 2 + PHP + MariaDB + DVWA (target), Combined log format | 192.168.56.10 |
| Kali Linux | attacker | 192.168.56.101 |
| any Linux/Windows VM | normal user traffic (browser, or a script with curl) | 192.168.56.102 |

DVWA install (on the Ubuntu VM): follow the official DVWA README (`git clone https://github.com/digininja/DVWA`),
set security level to *low* first, then repeat with *medium*. Make sure Apache's `LogFormat` is `combined`.

### Normal traffic
Browse every DVWA page for 20–30 minutes from the user VM (log in, use each module with valid input),
or run a small script that requests the pages in a loop with random pauses. More normal traffic = a more
honest false-positive rate.

### Attacks (from Kali), one at a time, note start/end times

```bash
# Scanner
nikto -h http://192.168.56.10/DVWA/
# Directory enumeration
gobuster dir -u http://192.168.56.10/DVWA/ -w /usr/share/wordlists/dirb/common.txt
# SQL injection (cookie from a logged-in browser session)
sqlmap -u "http://192.168.56.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=...; security=low" --batch --level 3
# Brute force on the login form
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.56.10 http-post-form "/DVWA/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -t 4
# XSS and path traversal: manual payloads in the browser on the attacker VM, e.g.
#   /DVWA/vulnerabilities/xss_r/?name=<script>alert(1)</script>
#   /DVWA/vulnerabilities/fi/?page=../../../../etc/passwd
```

Repeat sqlmap and gobuster once with `--random-agent` / `-a "Mozilla/5.0 ..."` to measure how much the
scanner user-agent rule depends on honest tools.

### Label, upload, evaluate

```bash
scp user@192.168.56.10:/var/log/apache2/access.log dvwa-access.log
```
```powershell
& $tools label-by-ip --log dvwa-access.log --attackers 192.168.56.101 --out dvwa.labels.csv
```

Upload `dvwa-access.log`, wait for *Completed*, then **Evaluate** with `dvwa.labels.csv`.
Record the overall metrics, the per-type table and the **Rules vs. anomaly detection** table (RQ2).

Note: because the lab uses private IPs, GeoIP and threat-intel lookups are skipped by design (private
addresses are never sent to external services). Demonstrate threat intel with the synthetic or sample logs.

---

## 5. Threat-intel effect (GreyNoise rule)

With a GreyNoise key configured, process a log that contains known internet scanners (e.g. a real
honeypot log you are allowed to use, or the sample log). The **Threat intel** page shows how many
alerts were lowered and from which severity. Report: alerts per severity before vs. after, and whether
any lowered alert was a true targeted attack (it should not be).

---

## 6. What to put in the thesis tables

* Table 6.x – dataset summary (lines, attacks per type, source).
* Table 6.x – overall precision / recall / F1 / FPR per dataset (rules only).
* Table 6.x – per-attack-type recall per dataset, with the reason for each miss (evasive payload, spoofed UA, slow rate…).
* Table 6.x – RQ2: rules vs. Isolation Forest vs. both, per dataset.
* Table 6.x – RQ3: time vs. file size (3 runs each), lines/s, hardware.
* Threats to validity: synthetic data written by the author, CSIC's synthetic IPs/timestamps, small lab, single machine.
