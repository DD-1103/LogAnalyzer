# LogAnalyzer — Project Context & Handover

## 1. Who / what / why
- **Owner:** Daniel Dervishi — Master's student, *Information Systems Engineering*, Faculty of Natural Sciences (FSHN), University of Tirana. Works as a SOC analyst at AKSK (Albania's National Cyber Security Authority): Microsoft Defender for Endpoint, Sentinel, Elastic/Kibana, KQL. Prefers concise, direct, command-ready answers.
- **Project:** Diploma thesis + working app. **"Design and Implementation of an Information System for Detecting Web Attacks Through Web Server Log Analysis."**
- **Proposed supervisors:** **Odeta Kromici** (teaches Software Project Management; also lectures in the new Cyber Security Master's) and **Julian Fejzaj** (networking; supervised Daniel's earlier HSRP/EtherChannel project). **Not** Endri Xhina.
- **How the topic was chosen:** first brainstorm (LLM alert triage, detection-as-code, SOC process mining, gov-website monitoring, NIS2 compliance platform, UEBA, threat-intel platform) → Daniel wanted something *different from Verdix* (his compliance SaaS) and *easier* → second list (website security scanner, log analyzer, phishing URL detector, asset/CVE tracker, awareness platform, incident ticketing) → shortlisted #1 scanner vs #2 log analyzer → **chose the Web Server Log Analyzer.**
- A formal proposal exists as a Claude Doc titled **"Diploma Proposal: Web Server Log Analyzer"** (problem, objectives, RQs, scope, FR1–FR10, architecture, detection logic, methodology, thesis chapters, 16-week timeline, tools, ethics). It was updated to say ASP.NET Core 10 / .NET 10 LTS and lists the supervisors.

### Research questions
- **RQ1:** How accurately can a rule-based engine detect common web attacks in access logs?
- **RQ2:** Does adding anomaly detection (Isolation Forest) improve detection vs. rules alone?
- **RQ3:** Can the system process large log volumes (1M+ lines) in acceptable time on ordinary hardware?

### Scope
- In: Apache/Nginx access logs (Common/Combined Log Format); brute force, SQLi, XSS, path traversal/LFI, scanners, directory enumeration; GeoIP + reputation enrichment; dashboard, alerts with severity, roles (Admin/Analyst), reports.
- Out: real-time blocking/WAF, non-HTTP logs (firewall, Windows events), **any real logs from AKSK or any employer** — only public datasets and self-generated lab data.

### Functional requirements (from proposal)
FR1 login + roles Admin/Analyst · FR2 upload .log/.txt/.gz · FR3 parse to structured events · FR4 rules in DB, admins add/edit/disable · FR5 alerts with type, severity, IP, evidence · FR6 GeoIP + reputation · FR7 dashboard (top IPs, over time, types, map) · FR8 search/filter · FR9 alert status workflow · FR10 PDF/CSV export.
Non-functional: 1M lines < 2 min, hashed passwords/secure auth, responsive UI, modular detectors.

## 2. Environment (Daniel's Windows laptop "DANIEL")
- **Visual Studio Community 2026** (18.11.x, use the normal one, not Insiders); VS 2022 also installed; SSMS 22.
- **.NET 10 SDK**; `dotnet-ef` global tool 10.0.x installed.
- **SQL Server:** two instances:
  - `localhost` (default instance, SQL Server 17 / 2025, appears to be **Developer edition** — no 10 GB limit) ← **the app uses this**.
  - `DANIEL\SQLEXPRESS` (Express) — also has the old `HotelManagement` DB; not used by LogAnalyzer.
- Repo path: `C:\Users\User\source\repos\LogAnalyzer`
- Run/test: open `LogAnalyzer.slnx` in VS 2026 → **▶ https** (https://localhost:7180, http://localhost:5180).
- EF commands are run from VS **Developer PowerShell** in `src\LogAnalyzer.Web` (the Package Manager Console `Add-Migration` failed with a generic error, so use the CLI):
  ```
  cd src\LogAnalyzer.Web
  dotnet ef migrations add <Name>
  ```
  The app applies pending migrations automatically on startup (`DbSeeder` → `MigrateAsync`), so `database update` is not needed.
- **Seed admin login (dev only):** `admin@loganalyzer.local` / `Admin#2026!` (in `appsettings.Development.json` → `SeedAdmin`).
- Git: Daniel was told to use VS "Add to Source Control → Git" and commit after each step (check whether it's done).

## 3. Tech stack
ASP.NET Core 10 MVC (C#, nullable, primary constructors) · EF Core 10 + SQL Server · ASP.NET Identity (custom login, no Identity UI) · BackgroundService + `Channel<int>` queue (instead of Hangfire) · SqlBulkCopy for bulk inserts · Bootstrap 5.3 dark theme + Bootstrap Icons (CDN) · Chart.js 4.4 · Leaflet 1.9.4 + OpenStreetMap tiles (CSS-darkened; CARTO tiles were dropped because they now need an API key) · MaxMind.GeoIP2 5.x (reads DB-IP or GeoLite2 .mmdb) · QuestPDF 2025.x (Community license) · System.Security.Cryptography.Pkcs 10.0.* pinned to override vulnerable 9.0.11 transitive dependency (NU1902/NU1903 fixed).

csproj uses floating versions `10.0.*`, `5.*`, `2025.*`. `UserSecretsId = loganalyzer-web-2026`.

## 4. Solution structure
```
LogAnalyzer/
├─ LogAnalyzer.slnx
├─ .gitignore              (bin, obj, .vs, App_Data/, *.log except samples/*.log)
├─ CLAUDE.md               (this file)
├─ samples/
│   ├─ sample-access.log         2,933 lines: 2,600 normal + 330 attacks + 3 malformed
│   └─ sample-access.labels.csv  ground truth "line,label"
└─ src/LogAnalyzer.Web/
    ├─ Program.cs
    ├─ appsettings.json / appsettings.Development.json
    ├─ Properties/launchSettings.json
    ├─ App_Data/            (gitignored) uploads/{id}.log|.log.gz, dbip-city-lite-2026-11.mmdb
    ├─ Controllers/  Account, Home, LogFiles, Alerts, Rules
    ├─ Data/         AppDbContext, DbSeeder (+Roles consts), DesignTimeDbContextFactory
    ├─ Helpers/      Format.cs (badges, labels, Bytes, Percent, Csv escaping)
    ├─ Migrations/   InitialCreate, NavNotifications, GeoEnrichment
    ├─ Models/       Entities.cs, Enums.cs
    ├─ Services/     LogParser, LogFileStorage, LogProcessing (queue+worker), DetectionEngine (+UrlDecoder),
    │                EvaluationService, IpEnrichment (GeoIpLookup, AbuseIpDbClient, IpEnrichmentService),
    │                DashboardService, ReportService
    ├─ ViewModels/   ViewModels.cs
    ├─ Views/        Account, Home, LogFiles (Index/Upload/Details/Evaluate), Alerts (Index/Details), Rules, Shared/_Layout
    └─ wwwroot/css/site.css
```

## 5. Configuration
`appsettings.json`
```json
"ConnectionStrings": { "DefaultConnection": "Server=localhost;Database=LogAnalyzerDb;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True" },
"Enrichment": { "GeoLiteCityDb": "App_Data/GeoLite2-City.mmdb", "AbuseIpDbApiKey": "" }
```
- GeoIP: if the configured file is missing, `GeoIpLookup` auto-picks any `*city*.mmdb` in `App_Data` (currently **DB-IP City Lite**, CC BY 4.0 → attribution "IP Geolocation by DB-IP" is shown under the map and must stay).
- API keys go in **user-secrets**, never in appsettings:
  ```
  dotnet user-secrets set "Enrichment:AbuseIpDbApiKey" "KEY"
  dotnet user-secrets set "Enrichment:GreyNoiseApiKey" "KEY"     (planned)
  dotnet user-secrets set "Enrichment:VirusTotalApiKey" "KEY"    (planned)
  ```

## 6. Database model (LogAnalyzerDb)
- **AppUser** : IdentityUser + FullName, AlertsSeenAt?, RulesSeenAt? (per-user nav-badge tracking)
- **LogFile**: Id, FileName, SizeBytes, UploadedAt, UploadedById, Status (Pending/Processing/Analyzing/Completed/Failed, stored as string), TotalLines, ParsedLines, FailedLines, ErrorMessage, ProcessedAt
- **LogEvent**: Id(long), LogFileId, LineNumber, ClientIp, Timestamp(DateTimeOffset), Method, Url, Protocol, StatusCode, ResponseSize, Referrer, UserAgent, RawLine. Indexes on LogFileId, ClientIp, Timestamp.
- **DetectionRule**: Name (unique), Description, AttackType, Severity, Kind (Signature/Threshold), Field (Url/UserAgent/Referrer), Pattern, Threshold, WindowSeconds, MethodFilter, PathPattern, StatusFilter, IsEnabled
- **Alert**: Title, RuleId, LogFileId, SourceIp, AttackType, Severity, Status (New/Investigating/FalsePositive/Closed), FirstSeen, LastSeen, EventCount, Notes, AssignedToId, CreatedAt
- **AlertEvidence**: AlertId → LogEventId (unique pair). LogEvent FK is NoAction (SQL Server multiple-cascade-path rule) → evidence must be deleted before events.
- **IpInfo** (key Ip): CountryCode, CountryName, City, Latitude, Longitude, AbuseScore, LastChecked (7-day cache)
- Enums stored as strings → sorting by severity/status uses explicit CASE ranks in LINQ.

## 7. What is built (steps 1–4 DONE and tested)
### Step 1 — Scaffold
Identity with roles Admin/Analyst, global `AuthorizeFilter` (every page needs login), lockout 5 tries/15 min, password ≥10 + symbol, HttpOnly/Secure/SameSite=Strict cookie, antiforgery on POSTs, seeding of roles/admin/6 default rules, dark Bootstrap layout.

### Step 2 — Upload & parsing
- Upload page (.log/.txt/.gz, 500 MB limit), file saved as `App_Data/uploads/{id}.log` (never the user's file name → no path traversal).
- `CombinedLogParser` (source-generated regex, handles escaped quotes, malformed request lines, `-0700` offsets).
- `LogProcessingWorker` (BackgroundService): streams file (gzip supported), SqlBulkCopy batches of 5,000, progress updates, resumes unfinished files on startup, logs lines/sec (for RQ3).
- Log files list (auto-refresh while busy), details page with paginated events + filter by IP/status; Admin-only delete.

### Step 3 — Detection, alerts, evaluation
- `DetectionEngine`: signature rules (regex on URL decoded twice / User-Agent / Referrer) and threshold rules (sliding window per IP). Regex timeout 250 ms (ReDoS protection). One alert per (rule, IP), all evidence bulk-inserted. Runs automatically after parsing (status Processing → Analyzing → Completed); Admin "Re-run detection" button.
- 6 seeded rules: SQL injection signatures (High), XSS signatures (Medium), Path traversal/LFI (High), Known scanner user agents (Medium), Login brute force ≥20 POST to login paths in 60 s (High), Directory enumeration ≥50×404 in 60 s (Medium).
- Alerts page (filters, pagination, "new since last visit" marker), alert details (rule, evidence with decoded URLs, location/abuse, triage form: status + notes; Investigating auto-assigns the analyst), Rules page (logic, alert counts, Admin on/off toggle).
- **Evaluation page**: upload labels CSV → precision, recall, F1, FPR, accuracy, confusion matrix, per-attack-type table. Labels: normal, sqli, xss, traversal, bruteforce, direnum, scanner (malformed ignored).
- **Result on sample log:** TP 330, FP 0, FN 0, TN 2,600 → 100% precision/recall/F1. Per type: DirectoryEnumeration recall 94% (9 non-404 gobuster lines caught only by the scanner rule), Scanner precision 8.7% (sqlmap/gobuster lines also match the UA rule — rule overlap, not real FPs). **Important for the thesis:** the sample was written by us to match the rules, so 100% only proves the engine works; real numbers must come from CSIC 2010 + DVWA lab.
- Nav badges (polled every 10 s via `/Home/NavCounts`): Log files = processing spinner; Alerts = +N alerts created since the user last opened Alerts; Rules = +N rules that fired since last opening Rules. Cleared on visiting the page.

### Step 4 — Dashboard, enrichment, reports
- Dashboard (scope filter per log file): stat cards, requests-over-time (all vs malicious, hourly), alerts by severity (doughnut), malicious requests by attack type (bar), attack-origin map, top attacking IPs (location, abuse score, malicious requests, attack types, max severity), latest alerts. JSON for charts is serialized with System.Text.Json (escapes `<>&` → no XSS); map popups built with `textContent`.
- IP enrichment runs after detection for alert source IPs only; private/loopback IPs are never sent to external services; AbuseIPDB client ready (no key yet → "—").
- GeoIP verified on the sample: 185.220.101.45 DE Berlin · 103.75.190.12 MY Kuala Lumpur · 91.240.118.172 HK · 194.26.29.113 RU St Petersburg · 45.146.164.110 RU St Petersburg · 162.142.125.9 US Ann Arbor (Censys range).
- **CSV export** of filtered alerts (UTF-8 BOM, CSV-injection protection: cells starting with = + - @ are prefixed with ').
- **PDF incident report** per log file (summary, alerts table, per-alert details with 3 evidence samples).
- Note: two copies of the sample log were uploaded (ids 1 and 2) → dashboard counts are doubled; delete one.

## 8. Known gotchas / lessons
- When files were pushed to the laptop remotely, some writes silently landed as the *previous* version (appsettings.json and the csproj once, Index.cshtml/site.css once) → always verify file content/size after writing. (With Claude Code working locally this should no longer be an issue.)
- The app uses `localhost`, not `.\SQLEXPRESS` (connection string was never switched; kept on purpose for the Developer edition).
- In SSMS/VS SQL Server Object Explorer you must connect to `localhost` to see `LogAnalyzerDb`.
- Package Manager Console EF commands error out; use `dotnet ef` from the terminal in the project folder.
- `EF.IsDesignTime` guards seeding; `DesignTimeDbContextFactory` exists for EF tools.
- MaxMind GeoLite2 sign-up form was broken ("intended use is required") → switched to DB-IP Lite (no account). GeoLite2 also works if its .mmdb is dropped in App_Data.

## 9. Decisions & advice already given
- **Zimmerman tools / Chainsaw (Windows forensics):** out of the proposal's scope → postponed. Possible later "Windows event log module" (run Chainsaw + Sigma on uploaded .evtx, show results in the same Alerts page) as an extension chapter or future work; changing core scope needs supervisor approval.
- **Threat intel:** add **GreyNoise** (identifies benign mass scanners → lower severity / reduce alert fatigue — good evaluation angle) and **VirusTotal** (optional multi-vendor verdict). **Do NOT use Daniel's work GTI account** (AKSK license, logging, quota, key leakage) → create personal/free accounts with the **university email**. **Snyk** is not an IP source — mention only in a secure-development section (we already use `dotnet list package --vulnerable`).
- Daniel opens accounts for AbuseIPDB, GreyNoise, VirusTotal with the school account (pending).
- Suggested Claude skills for later: LogAnalyzer project conventions, thesis writing (needs faculty guidelines), detection-rule writing, incident report, KQL hunting.

## 10. Roadmap (what's left)
- **Step 5 — Threat intel providers:** refactor enrichment into a provider interface; AbuseIPDB (key), GreyNoise Community, VirusTotal; store results in IpInfo (new columns → migration); show on alert/dashboard/PDF; rule: GreyNoise "benign" → downgrade severity (measure before/after alert counts).
- **Step 6 — Rule & user management (FR1, FR4):** Admin create/edit/delete rules with regex validation + test-against-sample; Admin creates/disables Analyst accounts; Analyst cannot change rules.
- **Step 7 — ML anomaly detection (RQ2):** Isolation Forest (Python scikit-learn microservice via REST, or ML.NET alternative) on per-IP features (request rate, 4xx ratio, unique URLs, avg URL length…); new AttackType.Anomaly alerts; compare rules vs rules+ML on evaluation page.
- **Step 8 — Real evaluation:** CSIC 2010 dataset (convert to access-log format + labels), DVWA lab on Apache attacked with sqlmap/Hydra/Nikto/gobuster (Kali VM in VirtualBox) to produce labelled logs, 1M+ line performance test (parse + detection timings) — results for chapter 6.
- **Step 9 — Quality:** unit tests (parser, detection engine, CSV escaping), security headers/CSP, audit log, README, screenshots.
- **Then:** write thesis chapters (1 Intro · 2 Literature review: OWASP, ELK, GoAccess, Wazuh/OSSEC, ModSecurity · 3 Requirements/UML · 4 Design/ER/architecture · 5 Implementation · 6 Testing & evaluation · 7 Conclusions/future work).
- **Optional:** Chainsaw/EZ tools module, live log ingestion, more log formats, automatic blocking.
- Estimate given: ~6–8 more sessions of coding, app done in ~2 weeks, then lab + writing.

## 11. Working conventions for Claude
- Answer concisely and command-ready; Daniel works step by step in VS 2026 and sends screenshots.
- Keep the existing patterns: primary-constructor services, enums as strings, `Format` helpers for badges, Bootstrap dark UI, `[ValidateAntiForgeryToken]` on POSTs, `[Authorize(Roles = Roles.Admin)]` for admin actions, log user actions with ILogger.
- Schema change → tell Daniel to run `dotnet ef migrations add <Name>` in `src\LogAnalyzer.Web`, then restart (auto-migrate).
- Security first (this is a security thesis): validate input, never trust log data in HTML/JS/CSV, secrets in user-secrets, no real employer data.
- After each step: build, test in browser, commit to Git.
