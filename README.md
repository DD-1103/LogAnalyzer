# LogAnalyzer

**Design and Implementation of an Information System for Detecting Web Attacks Through Web Server Log Analysis**
Master's diploma project – Information Systems Engineering, Faculty of Natural Sciences (FSHN), University of Tirana.

LogAnalyzer imports Apache / Nginx access logs, detects web attacks with signature, threshold and machine-learning
(Isolation Forest) rules, enriches attacker IPs with GeoIP and threat intelligence (AbuseIPDB, GreyNoise, VirusTotal),
and gives analysts a dashboard, an alert triage workflow and PDF/CSV reports.

## Features

| Area | What it does |
|---|---|
| Ingestion | Upload `.log` / `.txt` / `.gz` (≤ 500 MB). Background worker parses Common/Combined Log Format and bulk-inserts events (SqlBulkCopy). Parse and detection times are stored per file. |
| Detection | **Signature** rules (regex on URL decoded twice, user agent or referrer), **threshold** rules (N matching requests per IP in a sliding window), **anomaly** rule (Isolation Forest over 11 per-IP behaviour features, with an explanation per alert). Regex timeout + ReDoS check on save. |
| Rules (Admin) | Create / edit / enable / disable / delete; **test a rule against a stored log before saving**. |
| Alerts | One alert per (rule, IP) with all evidence lines; status workflow New → Investigating → False positive / Closed, notes, assignment; CSV export (formula-injection safe). |
| Enrichment | Offline GeoIP (DB-IP Lite / MaxMind GeoLite2). Threat intel providers behind one interface, cached per IP. GreyNoise "benign" lowers alert severity (original kept for evaluation). Private IPs are never sent out. |
| Dashboard & reports | Traffic over time, alerts by severity / type, attack map, top attacking IPs with reputation; PDF incident report per log file. |
| Evaluation | Upload a ground-truth labels CSV → precision, recall, F1, FPR, confusion matrix, per attack type, and **rules vs. Isolation Forest vs. both** (RQ2). |
| Users (Admin) | Admin / Analyst roles, create, change role, disable, unlock, reset password; change own password. |
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
dotnet test                                   # 74 unit tests: parser, decoding, CSV, rules, Isolation Forest, providers
dotnet build tools/LogAnalyzer.Tools
tools/LogAnalyzer.Tools/bin/Debug/net10.0/loganalyzer-tools.exe        # usage
```

`loganalyzer-tools` commands: `generate` (synthetic labelled log of any size), `csic` (CSIC 2010 converter),
`label-by-ip` (DVWA lab ground truth), `bench` (in-memory throughput + accuracy).
See **[docs/evaluation-guide.md](docs/evaluation-guide.md)** for the full evaluation protocol.

## Project structure

```
src/LogAnalyzer.Web/
  Controllers/   Account, Home (dashboard), LogFiles, Alerts, Rules, ThreatIntel, Users, Audit
  Services/      LogParser, LogProcessing (queue + worker), DetectionCore, DetectionEngine,
                 AnomalyDetection (Isolation Forest), RuleManagement (validator, tester),
                 ThreatIntel (providers, cache, GreyNoise rule), IpEnrichment (GeoIP),
                 EvaluationService, DashboardService, ReportService, AuditLog, SecurityHeaders
  Data/          AppDbContext, DbSeeder (roles, seed users, default rules)
  Models/        entities and enums        Views/  Razor views        wwwroot/js  site, dashboard, rule form
tests/LogAnalyzer.Tests/     xUnit tests
tools/LogAnalyzer.Tools/     generate / csic / label-by-ip / bench
samples/                     sample-access.log + labels
docs/                        evaluation guide
```

## Data and ethics

Only public datasets and self-generated lab data are used. No logs from any employer are processed.
IP addresses from private ranges are never sent to external services; public attacker IPs are sent only to the
threat-intelligence providers that the operator configured.

## Attribution

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). Map data © OpenStreetMap contributors.
