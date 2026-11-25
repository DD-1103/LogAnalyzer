# LogAnalyzer

**Design and Implementation of an Information System for Detecting Web Attacks Through Web Server Log Analysis**
Master's diploma project – Information Systems Engineering, Faculty of Natural Sciences (FSHN), University of Tirana.

LogAnalyzer imports Apache / Nginx access logs, detects web attacks with signature, threshold and machine-learning
(Isolation Forest) rules, enriches attacker IPs with GeoIP and threat intelligence (AbuseIPDB, GreyNoise, VirusTotal and
others), and gives analysts a dashboard, an alert triage workflow and PDF/CSV reports. It also reads firewall logs
(port scans, network sweeps, brute force, floods, C2 connections, IPS events, failed logins).

## Features

| Area | What it does |
|---|---|
| Ingestion | Upload `.log` / `.txt` / `.gz` (≤ 500 MB). The log format is detected automatically or chosen on upload; a background worker parses the file and bulk-inserts events (SqlBulkCopy). A file of which no line can be read is marked Failed with an explanation. Parse and detection times are stored per file. |
| Firewall logs | Format detected from the first lines (or chosen at upload): FortiGate, Palo Alto PAN-OS, Cisco ASA / FTD, Check Point, Sophos, SonicWall, Juniper SRX, pfSense / OPNsense, Linux netfilter (iptables, UFW, firewalld, nftables), Windows Defender Firewall, WatchGuard, MikroTik, Huawei USG, Meraki MX, Stormshield, Zyxel, AWS VPC flow logs; vendor-neutral CEF, LEEF, JSON lines and key=value. Written from public documentation, not verified on real devices. |
| Detection | **Signature** rules (regex on URL decoded twice, user agent or referrer), **threshold** rules (N matching requests per IP in a sliding window), **anomaly** rule (Isolation Forest over 11 per-IP behaviour features, with an explanation per alert); for firewall logs also **distinct-count** rules (different ports per host, different hosts) with action and port filters. Web rules never run on firewall files and vice versa. Regex timeout + ReDoS check on save. |
| Rules (Admin) | Create / edit / enable / disable / delete; **test a rule against a stored log before saving**. |
| Alerts | One alert per (rule, IP) with all evidence lines; status workflow New → Investigating → False positive / Closed, notes, assignment; CSV export (formula-injection safe). |
| Enrichment | Offline GeoIP (DB-IP Lite / MaxMind GeoLite2). Threat intel providers behind one interface, cached per IP. GreyNoise "benign" lowers alert severity (original kept for evaluation). Private IPs are never sent out. |
| Dashboard & reports | Traffic over time, alerts by severity / type, attack map, top attacking IPs with reputation; PDF incident report per log file. |
| Evaluation | Upload a ground-truth labels CSV → precision, recall, F1, FPR, confusion matrix, per attack type, and **rules vs. Isolation Forest vs. both** (RQ2). |
| Users (Admin) | Admin / Analyst roles, create, change role, disable, unlock, reset password; change own password. SOC 1 / SOC 2 tiers with escalation and notifications. |
| Sessions | Several accounts in one browser: each tab can use its own session slot (`/s/1` … `/s/9`, account menu → *Sign in another account*). |
| Security | Every page requires login; lockout after 5 failures; login rate limit per IP; HttpOnly/Secure/SameSite=Strict cookie; antiforgery on all POSTs; strict CSP (no inline JS) and security headers; append-only **audit log**; secrets in user-secrets. |

## Tech stack

ASP.NET Core 10 MVC · EF Core 10 + SQL Server · ASP.NET Core Identity · BackgroundService + `Channel<T>` ·
Bootstrap 5.3 · Chart.js 4 · Leaflet 1.9 + OpenStreetMap · MaxMind.GeoIP2 · QuestPDF · xUnit.

## Getting started

Requirements: .NET 10 SDK, SQL Server (Developer/Express; the connection string uses `Server=localhost`), Visual Studio 2026 or `dotnet` CLI.

```powershell
git clone <repo>
cd LogAnalyzer
dotnet run --project src/LogAnalyzer.Web --launch-profile https
```

Open https://localhost:7180. Pending migrations are applied automatically at startup, and the development
seed accounts from `appsettings.Development.json` are created (change these for anything but local development).

GeoIP (optional): download *DB-IP IP to City Lite* (`.mmdb`, CC BY 4.0) or MaxMind GeoLite2-City into
`src/LogAnalyzer.Web/App_Data/`. Any `*city*.mmdb` there is picked up automatically.

### Threat-intelligence API keys (optional)

Keys are stored with user-secrets, never in `appsettings.json`:

```powershell
cd src/LogAnalyzer.Web
dotnet user-secrets set "Enrichment:AbuseIpDbApiKey" "KEY"
dotnet user-secrets set "Enrichment:GreyNoiseApiKey" "KEY"
dotnet user-secrets set "Enrichment:VirusTotalApiKey" "KEY"
```

Restart the app, open **Threat intel → provider → Test with 8.8.8.8**. Without a key every page still works and
shows how to add one. Free-tier limits are respected (`Enrichment:*MaxPerRun`, VirusTotal spacing of 15 s).

| Route | Purpose |
|---|---|
| `/ThreatIntel` | provider status, cached verdicts, GreyNoise severity effect |
| `/ThreatIntel/Provider/{abuseipdb\|greynoise\|virustotal}` | setup, quota, cached answers, Test (Admin) |
| `/ThreatIntel/Lookup?ip=` | everything known about one IP, live refresh |
| `/ThreatIntel/Api/{provider}/{ip}` | cached answer as JSON |

### Database migrations

```powershell
cd src/LogAnalyzer.Web
dotnet ef migrations add <Name>
```

## Tests and tools

```powershell
dotnet test                                   # unit tests: parsers, formats, rules, Isolation Forest, providers, sessions, security fixes
dotnet build tools/LogAnalyzer.Tools
tools/LogAnalyzer.Tools/bin/Debug/net10.0/loganalyzer-tools.exe        # usage
```

`loganalyzer-tools` commands: `generate` (synthetic labelled access log of any size), `generate-firewall` (synthetic
labelled firewall log in five formats), `detect` (which format a file has and how many lines can be read, offline),
`csic` (CSIC 2010 converter), `label-by-ip` (DVWA lab ground truth), `bench` (in-memory throughput + accuracy, web logs).
See **[docs/evaluation-guide.md](docs/evaluation-guide.md)** for the full evaluation protocol.

## Project structure

```
src/LogAnalyzer.Web/
  Controllers/   Account, Home (dashboard), LogFiles, Alerts, Rules, ThreatIntel, Users, Audit
  Services/      LogParser, LogFormats/ (one class per firewall vendor), LogProcessing (queue + worker),
                 DetectionCore, DetectionEngine, FirewallFilters, SessionSlots, AnomalyDetection (Isolation Forest), RuleManagement (validator, tester),
                 ThreatIntel (providers, cache, GreyNoise rule), IpEnrichment (GeoIP),
                 EvaluationService, DashboardService, ReportService, AuditLog, SecurityHeaders
  Data/          AppDbContext, DbSeeder (roles, seed users, default rules)
  Models/        entities and enums        Views/  Razor views        wwwroot/js  site, dashboard, rule form
tests/LogAnalyzer.Tests/     xUnit tests
tools/LogAnalyzer.Tools/     generate / generate-firewall / detect / csic / label-by-ip / bench
samples/                     sample-access.log + labels, firewall/ (one synthetic sample per format)
docs/                        evaluation guide
```

## Data and ethics

Only public datasets and self-generated lab data are used. No logs from any employer are processed.
IP addresses from private ranges are never sent to external services; public attacker IPs are sent only to the
threat-intelligence providers that the operator configured.

## Attribution

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). Map data © OpenStreetMap contributors.
