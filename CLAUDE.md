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

### Functional requirements (from proposal) — all implemented
FR1 login + roles Admin/Analyst · FR2 upload .log/.txt/.gz · FR3 parse to structured events · FR4 rules in DB, admins add/edit/disable · FR5 alerts with type, severity, IP, evidence · FR6 GeoIP + reputation · FR7 dashboard (top IPs, over time, types, map) · FR8 search/filter · FR9 alert status workflow · FR10 PDF/CSV export.
Non-functional: 1M lines < 2 min (CPU part measured ≈ 10 s; end-to-end with SQL Server still to be measured in the app), hashed passwords/secure auth, responsive UI, modular detectors.

## 2. Environment (Daniel's Windows laptop "DANIEL")
- **Visual Studio Community 2026** (18.11.x, use the normal one, not Insiders); VS 2022 also installed; SSMS 22.
- **.NET 10 SDK**; `dotnet-ef` global tool 10.0.x installed (10.0.14, runtime 10.0.15 → harmless warning).
- **SQL Server:** two instances:
  - `localhost` (default instance, SQL Server 17 / 2025, appears to be **Developer edition** — no 10 GB limit) ← **the app uses this**.
  - `DANIEL\SQLEXPRESS` (Express) — also has the old `HotelManagement` DB; not used by LogAnalyzer.
- Repo path: `C:\Users\User\source\repos\LogAnalyzer`
- Run/test: open `LogAnalyzer.slnx` in VS 2026 → **▶ https** (https://localhost:7180, http://localhost:5180). Claude Code uses `.claude/launch.json` (config "loganalyzer") for the browser preview.
- EF commands from a terminal in `src\LogAnalyzer.Web` (Package Manager Console fails):
  ```
  cd src\LogAnalyzer.Web
  dotnet ef migrations add <Name>
  ```
  The app applies migrations on startup only when some are pending (`DbSeeder`: `GetPendingMigrationsAsync` → `MigrateAsync`); EF migration/infrastructure logs are at Warning, so normal start-ups show no "Migration" lines.
- When debugging from Visual Studio (F5), `ConsoleWindow.HideWhenDebuggedByVisualStudio` hides the log console (Daniel closed it by accident, which stops the app). Only if a debugger is attached and the console belongs to VsDebugConsole/devenv alone; terminals and Ctrl+F5 keep it. Logs: VS Output window. `LOGANALYZER_SHOW_CONSOLE=1` disables the hiding.
- **Seed logins:** e-mails in `appsettings.Development.json` (`admin@loganalyzer.local`, `analyst@loganalyzer.local`); passwords **never in files** – only user-secrets / env vars (`dotnet user-secrets set "SeedAdmin:Password" "..."`, `SeedAdmin__Password`). Created only if missing; seeded accounts and passwords set by an admin get `MustChangePassword` (redirect to Change password). The existing dev accounts keep their old passwords – change the admin password before the jury demo. The analyst is seeded only in Development.
- **Launch profiles:** `https` = Development (developer exception page). **`demo` = environment "Demo" for the jury**: generic error page, HSTS, `appsettings.Demo.json` + user-secrets. Claude Code preview configs: `loganalyzer`, `loganalyzer-demo`.
- **Git:** repo initialised 2026-11-13, remote `origin` = private GitHub repo `DD-1103/LogAnalyzer`. Steps 5–9 were done on branch `steps-5-9` and fast-forward merged into `main` and pushed on 2026-11-13 (the branch also exists on GitHub and can be deleted). `.gitattributes` normalises line endings (CRLF warnings on commit are harmless).
- `sqlcmd` is available (`sqlcmd -S localhost -E -C -d LogAnalyzerDb -Q "..."`).

## 3. Tech stack
ASP.NET Core 10 MVC (C#, nullable, primary constructors) · EF Core 10 + SQL Server · ASP.NET Identity (custom login, no Identity UI) · BackgroundService + `Channel<ProcessingJob>` queue (instead of Hangfire) · SqlBulkCopy (TableLock) for bulk inserts · Bootstrap 5.3.3 + Bootstrap Icons 1.11.3 (self-hosted in `wwwroot/lib`, no CDN) re-skinned by the **Liquid Glass** design system (`wwwroot/css/glass.css`, light + dark) · Chart.js 4.4.4 · Leaflet 1.9.4 (both in `wwwroot/lib`) + OpenStreetMap tiles (CSS-darkened) · MaxMind.GeoIP2 5.x (reads DB-IP or GeoLite2 .mmdb) · QuestPDF 2025.x (Community license) · System.Security.Cryptography.Pkcs 10.0.* pinned (NU1902/NU1903 fix) · ASP.NET Core rate limiter · xUnit (tests) · Isolation Forest implemented in C# (no Python/ML.NET dependency).

Exact package versions (10.0.15, MaxMind 5.4.1, QuestPDF 2025.12.4) + `packages.lock.json` (since audit fix 22). `UserSecretsId = loganalyzer-web-2026`.

## 4. Solution structure
```
LogAnalyzer/
├─ LogAnalyzer.slnx            (src / tests / tools folders)
├─ .gitignore, .gitattributes, README.md, CLAUDE.md
├─ .claude/launch.json         (browser preview config for Claude Code)
├─ docs/evaluation-guide.md    (CSIC 2010, DVWA lab, RQ3 protocol, thesis tables)
├─ docs/security-audit/       REPORT.md (2026-11-17 full audit, score 7.5/10) + findings/NN-*.md (30 fix tickets)
├─ samples/  sample-access.log (2,933 lines) + sample-access.labels.csv
├─ src/LogAnalyzer.Web/
│   ├─ Program.cs  appsettings*.json  Properties/launchSettings.json
│   ├─ App_Data/   (gitignored) uploads/{id}.log|.log.gz, dbip-city-lite-2026-11.mmdb
│   ├─ Controllers/ Account, Home, LogFiles, Alerts, Rules, ThreatIntel, Users, Audit
│   ├─ Data/        AppDbContext, DbSeeder (+Roles, DefaultRules() public), DesignTimeDbContextFactory
│   ├─ Helpers/     Format.cs (badges, labels, Bytes, Percent, Csv, VerdictBadge, ReputationShort, TimeAgo)
│   ├─ Migrations/  InitialCreate, NavNotifications, GeoEnrichment, ThreatIntelAndAudit, RulesUsersAnomaly, ProcessingTimings
│   ├─ Models/      Entities.cs, Enums.cs
│   ├─ Services/    LogParser, LogFileStorage, LogProcessing (ProcessingJob, queue, worker),
│   │               DetectionCore (pure matching), DetectionEngine (DB wrapper), AnomalyDetection (IsolationForest,
│   │               IpProfile, IpFeatureAccumulator, AnomalyDetector), RuleManagement (RuleValidator, RuleTester),
│   │               ThreatIntel (EnrichmentOptions, IThreatIntelProvider, 3 providers, ProviderThrottle, ThreatIntelService),
│   │               IpEnrichment (GeoIpLookup, IpEnrichmentService = GeoIP only + IsPublic), EvaluationService,
│   │               DashboardService, ReportService, AuditLog, UserConfirmation, SecurityHeaders
│   ├─ ViewModels/  ViewModels.cs
│   ├─ Views/       Account (Login, ChangePassword), Home, LogFiles, Alerts, Rules (Index, Edit), ThreatIntel (Index,
│   │               Provider, Lookup), Users (Index, Create), Audit, Shared (_Layout, _ReputationCard)
│   └─ wwwroot/     css/glass.css (design system), css/site.css (app helpers), css/views-a|b|c.css (per view group),
│                   js/theme-init.js (theme before paint), js/site.js (theme, glass light, ripple, reveal, count-up,
│                   nav badges, js-confirm, js-autosubmit), js/dashboard.js (theme-aware charts), js/rule-form.js
├─ tests/LogAnalyzer.Tests/    xUnit, 74 tests
└─ tools/LogAnalyzer.Tools/    console app "loganalyzer-tools": generate, csic, label-by-ip, bench
```

## 5. Configuration
`appsettings.json`
```json
"ConnectionStrings": { "DefaultConnection": "Server=localhost;Database=LogAnalyzerDb;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True" },
"Enrichment": {
  "GeoLiteCityDb": "App_Data/GeoLite2-City.mmdb",
  "AbuseIpDbApiKey": "", "GreyNoiseApiKey": "", "VirusTotalApiKey": "",
  "CacheDays": 7, "AbuseIpDbMaxPerRun": 200, "GreyNoiseMaxPerRun": 25, "VirusTotalMaxPerRun": 4,
  "VirusTotalMinIntervalSeconds": 15, "GreyNoiseDowngradeBenign": true
}
```
- Bound to `EnrichmentOptions` (IOptions). GeoIP: if the configured file is missing, any `*city*.mmdb` in `App_Data` is used (currently **DB-IP City Lite**, CC BY 4.0 → attribution "IP Geolocation by DB-IP" must stay under the map).
- API keys go in **user-secrets** (run in `src\LogAnalyzer.Web`), then restart and press *Test* on the provider page:
  ```
  dotnet user-secrets set "Enrichment:AbuseIpDbApiKey" "KEY"
  dotnet user-secrets set "Enrichment:GreyNoiseApiKey" "KEY"
  dotnet user-secrets set "Enrichment:VirusTotalApiKey" "KEY"
  ```

## 6. Database model (LogAnalyzerDb)
- **AppUser** : IdentityUser + FullName, IsDisabled, CreatedAt, LastLoginAt, AlertsSeenAt?, RulesSeenAt?
- **LogFile**: Id, FileName, SizeBytes, UploadedAt, UploadedById, Status (Pending/Processing/Analyzing/Completed/Failed, string), TotalLines, ParsedLines, FailedLines, ErrorMessage, ProcessedAt, **ParseMilliseconds, DetectionMilliseconds**
- **LogEvent**: Id(long), LogFileId, LineNumber, ClientIp, Timestamp(DateTimeOffset), Method, Url, Protocol, StatusCode, ResponseSize, Referrer, UserAgent, RawLine. Indexes on LogFileId, ClientIp, Timestamp.
- **DetectionRule**: Name (unique), Description, AttackType, Severity, Kind (**Signature/Threshold/Anomaly**), Field, Pattern, Threshold (anomaly: min requests per IP), WindowSeconds, MethodFilter, PathPattern, StatusFilter, **ScoreThreshold** (anomaly), IsEnabled
- **Alert**: Title, RuleId, LogFileId, SourceIp, AttackType, Severity, Status, FirstSeen, LastSeen, EventCount, **Score, Details** (anomaly), **OriginalSeverity, SeverityNote** (GreyNoise downgrade), Notes, AssignedToId, CreatedAt
- **AlertEvidence**: AlertId → LogEventId (unique pair). LogEvent FK is NoAction → evidence must be deleted before events.
- **IpInfo** (key Ip): CountryCode, CountryName, City, Latitude, Longitude, AbuseScore (synced from AbuseIPDB), LastChecked
- **IpReputation**: Ip + Provider (unique), Verdict (Unknown/Benign/Suspicious/Malicious/NotFound/Error/Skipped), Score 0–100, Summary, AttributesJson, Error, CheckedAt
- **AuditEntry**: Timestamp, UserName, Action (e.g. Login.Failed, Rule.Edit, User.Disable, LogFile.Upload, Alert.Update, ThreatIntel.Lookup), Target, Details, IpAddress — append-only
- Enums stored as strings → sorting by severity/status uses explicit CASE ranks in LINQ.
- The default Isolation Forest rule is inserted by the `RulesUsersAnomaly` migration (SQL with IF NOT EXISTS); DbSeeder seeds the 6 classic rules only when no non-anomaly rule exists.

## 7. What is built (steps 1–9 DONE)
### Step 1 — Scaffold
Identity with roles, global `AuthorizeFilter`, lockout 5 tries/15 min, password ≥10 + symbol, HttpOnly/Secure/SameSite=Strict cookie, antiforgery on POSTs, seeding, dark Bootstrap layout.

### Step 2 — Upload & parsing
Upload (.log/.txt/.gz, 500 MB), file saved as `App_Data/uploads/{id}.log`; `CombinedLogParser` (source-generated regex); `LogProcessingWorker` streams + SqlBulkCopy batches of 5,000, progress, resume on startup (Pending/Processing → full re-parse, Analyzing → detection only).

### Step 3 — Detection, alerts, evaluation
Signature + threshold rules (URL decoded twice, regex timeout 250 ms), one alert per (rule, IP); alerts list/details/triage; rules page; evaluation page (labels CSV → metrics). Sample log result: 100% (sample written to match rules → only proves the engine works). Nav badges.

### Step 4 — Dashboard, enrichment, reports
Dashboard (stats, timeline, severity, types, map, top IPs, latest alerts), GeoIP, CSV export (formula-injection safe), PDF report.

### Step 5 — Threat intel (2026-11-13)
- `IThreatIntelProvider` + `ThreatIntelProviderBase` (HTTP status → readable errors: 401/403 key rejected, 429 quota, 5xx unavailable; JSON errors never throw). Providers: **AbuseIPDB** v2 `/check` (header `Key`), **GreyNoise** Community v3 `/v3/community/{ip}` (header `key`, 404 = not noise), **VirusTotal** v3 `/ip_addresses/{ip}` (header `x-apikey`). Static `ParseResponse` per provider (unit-tested).
- Not configured → verdict *Skipped* with the user-secrets command; private IPs → *Skipped*, never sent.
- `ThreatIntelService`: cache per (IP, provider), `EnrichAsync` with per-run limits, `ProviderThrottle` (VT 15 s; UI requests don't wait, they get "try again in N s"), `ApplyGreyNoiseRuleAsync` (benign/RIOT → severity −1, OriginalSeverity kept).
- Worker order: parse → detection → GeoIP → **Completed** → threat intel + GreyNoise rule (best effort, so slow APIs don't delay the file).
- Routes: `/ThreatIntel`, `/ThreatIntel/Provider/{abuseipdb|greynoise|virustotal}`, `/ThreatIntel/Lookup?ip=`, POST `/ThreatIntel/Refresh`, POST `/ThreatIntel/Test/{slug}` (Admin, uses 8.8.8.8), GET `/ThreatIntel/Api/{slug}/{ip}` (cached JSON). Reputation cards on alert details, badges in dashboard top IPs, line in PDF, ↓ icon in alert list for lowered alerts.
- "Re-run detection" now queues a background job (was synchronous in the request).
- Verified in browser: all routes 200/404/400 as expected without keys. **Not yet verified with real API keys** (no keys yet) — provider parsing is covered by unit tests with realistic JSON.

### Step 6 — Rule & user management (FR1, FR4)
- Rules: Admin create/edit (one form for 3 kinds, `rule-form.js` shows/disables fields per kind), delete only if the rule has no alerts (else disable), unique names, `RuleValidator` (compile + **ReDoS probe** with 100 ms timeout on adversarial inputs), **Test before saving** (`RuleTester`: runs the unsaved rule on a stored log, up to 500k events, shows matches/alerts/top IPs/samples).
- Users (`/Users`, Admin): create, change role, disable/enable (security stamp updated → session ends within 1 min), unlock, reset password; cannot change/disable self or the last active admin. Disabled users can't sign in (`EnabledUserConfirmation` + `RequireConfirmedAccount`; same generic error message). Change own password (`/Account/ChangePassword`). Analyst gets AccessDenied on Users/Audit/rule editing (verified).
- Audit log page `/Audit` (Admin) with user/action filters.

### Step 7 — Isolation Forest (RQ2)
- `DetectionCore` extracted (pure, unit-testable); `DetectionEngine` streams events into it.
- `IsolationForest` in C#: 100 trees, ψ = min(256, n), height limit ⌈log2 ψ⌉, score 2^(−E[h]/c(ψ)), seed 42.
- 11 per-IP features: requests (log), requests/min (log), 4xx ratio, 5xx ratio, unique path ratio, avg URL length (log), POST ratio, suspicious-char ratio, missing UA ratio, distinct UAs (log), query-string ratio. Needs ≥ 8 IPs with ≥ Threshold requests.
- Alert = all events of the IP, title "Anomalous behaviour from IP (score 0.xx)", explanation = top 3 features by robust z-score (median/MAD), e.g. "requests per minute 20 (typical 0.07)".
- Default rule "Anomalous client behaviour (Isolation Forest)": Low, min 20 requests, score ≥ 0.62.
- Evaluation page adds **Rules only / Anomaly only / Rules + anomaly** table.
- Sample log: 51 IPs, 6 anomalous (exactly the attacker IPs) → 100% for all three (synthetic sample, attackers send only attacks).

### Step 8 — Evaluation tooling (RQ1–RQ3)
- Parse and detection time stored per LogFile and shown on the file page; SqlBulkCopy uses TableLock.
- `tools/LogAnalyzer.Tools` (`loganalyzer-tools.exe`): `generate` (actor-based synthetic log: sessions, crawlers, uptime monitor, campaigns incl. evasive payloads, spoofed UAs, slow brute force, benign odd searches), `csic` (CSIC 2010 → CLF + labels, `--body-as-query` upper bound), `label-by-ip` (DVWA lab), `bench` (CPU-only parse+rules+IF, with `--labels` prints accuracy).
- **Reference results (1M synthetic lines, seed 42, Debug, 24 CPUs):** parse ≈ 8 s (~125k lines/s), rules ≈ 1.5–2 s, IF ≈ 0.3 s, total ≈ 10 s. Rules only P 99.7% / R 96.1% / F1 97.9% / FPR 0.01%; IF only P 87.9% / R 99.9%; rules+IF P 87.7% / R 100% / F1 93.4% / FPR 0.29%. Per-label recall (rules): bruteforce 100, scanner 100, direnum 96.9, xss 89.4, sqli 85.8, traversal 69.8.
- `docs/evaluation-guide.md` = full protocol (datasets, DVWA VirtualBox lab, attack commands, labelling, thesis tables, threats to validity).

### Step 9 — Quality
- 74 xUnit tests at step 9, 180 after the audit fixes (parser, decoder, CSV, IsPublic, metrics, labels parsing, default rules positive/negative, threshold window, validator/ReDoS, Isolation Forest, anomaly detector, providers via fake `HttpMessageHandler`, throttle). Run `dotnet test`.
- `SecurityHeadersMiddleware`: CSP `script-src 'self'` (since the audit fixes all libraries are self-hosted; no inline JS — all scripts in wwwroot/js; dashboard data in a `<script type="application/json">` block; inline `on*` handlers replaced by `js-confirm` / `js-autosubmit` classes), `style-src` allows `'unsafe-inline'` (style attributes), X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP. Verified: injected inline script is blocked, charts and map still work.
- Login rate limiter: 10 POSTs/min per IP → 429 (verified).
- Audit entries for logins, logout, uploads, deletes, re-runs, evaluations, PDF, triage, CSV export, rule/user changes, threat-intel lookups/tests.
- README.md.

### Step 10 — Liquid Glass UI redesign (2026-11-13, branch `ui-liquid-glass`)
- iOS-style glass for the jury demo, every view restyled. Head agent built the design system + layout; three parallel agents (git worktrees) restyled view groups A (dashboard, account, error), B (log files, alerts), C (rules, threat intel, users, audit); merged and verified page by page.
- **Themes:** `data-bs-theme` light / dark on `<html>`, preference light/dark/auto in localStorage `la-theme`, set before paint by `theme-init.js`; toggle button `.js-theme-toggle` in the nav cycles light → dark → auto with a circular View Transition; `lg:themechange` event is dispatched (dashboard.js rebuilds charts, recolours map markers). Dark = soft graphite-navy `#1a1f2d`, never black.
- **Tokens** (glass.css §1): `--lg-surface*`, `--lg-edge*`, `--lg-hairline`, `--lg-text/-2/-3`, Apple colours as `--lg-{accent|red|orange|green|teal|indigo|gray}-rgb` + accessible `-ink-rgb`; Bootstrap `--bs-*` variables mapped to them, so all Bootstrap components follow both themes.
- **Glass recipe**: `.card`, `.lg-panel`, `.lg-glass`, `.table-responsive` get frosted fill + pointer-following specular rim (`--mx/--my` set by site.js) + sheen; no glass inside glass (inner table-responsive/card become clear).
- **Building blocks**: `lg-page-header` + `lg-title` + `lg-subtitle` + `lg-actions`, `lg-section-title`, `card lg-stat` (+ `lg-stat-top/label/value/meta`), `lg-icon` (+ `-sm/-lg`) with `lg-tint-{blue|red|orange|green|teal|indigo|gray}`, `lg-glow` (uses the element's lg-tint), `lg-toolbar` (filters), `lg-chip`, `lg-kv` (dl), `lg-empty`, `lg-meter`, `lg-auth`/`lg-auth-card`, `lg-brandmark`. Add `data-countup` to a number to animate it. Severity → badge: Critical `text-bg-danger`, High `-warning`, Medium `-info`, Low `-secondary` (badges are tinted capsules).
- **Motion**: buttons spring on hover, sheen sweep, press scale + ripple; scroll reveal (`data-reveal`, set by site.js on cards/panels/rows) with failsafes so content is never left hidden; aura-light backdrop (ribbons + beam); all off with prefers-reduced-motion; solid surfaces with prefers-reduced-transparency.
- **Clear "Liquid Glass" material (glass.css §9b, iOS 26/27 style):** instead of frosted glass, surfaces are clear (blur 1.5–5 px, faint tint) with specular edges (`--lg-specular` inset highlights). Two materials: *clear* (nav, stat tiles, toolbars, breadcrumbs, outline buttons, pagination) and *regular* (cards, tables, alerts, menus: a little more tint for readability). Filled buttons are tinted glass. The backdrop is "aura lights" (Daniel rejected floating balls and photos): 4 blurred light ribbons `.lg-aura` (tokens `--lg-aura-{sky|blue|violet|pink|mint|peach}`, `--lg-aura-opacity`, `--lg-aura-blend` = normal light / screen dark) sway (`translate`/`rotate`) and breathe (`scale`) slowly, plus a turning conic light beam (`.lg-backdrop::before`, 90 s). Only transform properties animate. Apple wallpapers are not used (copyright).
- **Lens refraction:** `Views/Shared/_LiquidGlassFilters.cshtml` holds 3 SVG filters (`#lg-lens` compact, `#lg-lens-panel` cards, `#lg-lens-bar` wide bars) = `feImage` displacement map (data: URI, edge ramps) + `feDisplacementMap` (scale 22–30 px). Applied as `backdrop-filter: url(#...) blur() saturate()` only when `html.lg-refract` is set by theme-init.js (Chromium via `navigator.userAgentData`, and not prefers-reduced-transparency); Firefox/Safari get clear glass without bending.
- **No sideways scrolling (Daniel's requirement):** pages only scroll vertically. site.js §7 gives every table cell its header as `data-label`; when a `.table-responsive > table` is wider than its box it gets `.lg-stacked` (glass.css §9c) and each row becomes a card of "label: value" lines (re-evaluated on resize). Wide screens keep normal tables. Dashboard "Top attacking IPs" has 4 columns (Attacker with location + reputation, attack-type chips, requests, max). Verified 0 px overflow at 1920/1440/1280/1024/768/390 on all pages. New tables: keep columns few, let text wrap, no `text-nowrap` on long text.
- Fixes found during the redesign: Chart.js `defaults.animation` must be modified, not replaced (charts did not draw); nav collapses below xl; count-up always ends on the server value.
- Verified: all 31 pages 200 in both themes, forms (rule test/save/toggle, triage, evaluate upload, login/logout) work, no horizontal overflow at 375 px, CSP intact (no inline JS / on* / style attributes in views).

## 8. Known gotchas / lessons
- The app uses `localhost`, not `.\SQLEXPRESS`. In SSMS connect to `localhost` to see `LogAnalyzerDb`.
- Package Manager Console EF commands error out; use `dotnet ef` in the project folder.
- `EF.IsDesignTime` guards seeding; `DesignTimeDbContextFactory` exists for EF tools.
- MaxMind GeoLite2 sign-up form was broken → DB-IP Lite used.
- Screenshots of the hidden Claude browser pane freeze CSS transitions mid-way (content looks faded); remove `lg-motion` from `<html>` before screenshots. The app also refuses to load in an iframe (frame-ancestors 'none').
- `git add -A` while agents run would add `.claude/worktrees/` — it is now in .gitignore.
- New controller actions need `[HttpGet]` or `[HttpPost]` (test `EveryControllerAction_HasAnExplicitHttpVerb`); XML comments in .props/.csproj must not contain `--`.
- Don't name action parameters / query params `action` (clashes with MVC route value) — use e.g. `intent`, `type`.
- Stop the running app before `dotnet build` from the CLI (bin files are locked while it runs).
- Duplicate sample uploads were cleaned on 2026-11-13: only log file **#4** (sample-access.log) remains.
- The Desktop copy of this file (`OneDrive\Desktop\CLAUDE.md`) is the old version — this repo file is the source of truth.

### Audit fixes (2026-11-17, branch `security-fixes`)
- **Worker** (`LogProcessing.cs`): jobs Parse / Detect / Delete; the loop never throws (DB down → logged, next job); shutdown is not a failure; `LogFile.ProcessingAttempts` (≥ 3 interrupted runs → Failed); Admin *Process again* on Failed files (`LogFiles/Reprocess`); user-safe error messages; 10 min command timeout in worker scopes.
- **Delete** runs in the worker: status `Deleting`, batched `DELETE TOP (n)` via `LogFileCleanup` (evidence → alerts → events → file); also used before re-parse and by DetectionEngine.
- **Input limits** (`ProcessingOptions`, section `Processing`): MaxDecompressedBytes 2 GB and 50x ratio (min 64 MB) via `LimitedReadStream`, MaxLines 5M, `BoundedLineReader` 16 KB (longer lines = failed); over the limits → Failed and partial events removed.
- **Threat intel** runs in its own `ThreatIntelWorker` (`ThreatIntelQueue`, 10 min budget per file); `ILogFileThreatIntel` = ThreatIntelService.
- **Threshold rules** linear (`SlidingWindow` with pending counter); evidence identical to the old algorithm (property test).
- **DB:** LogEvents indexes `(LogFileId, LineNumber)`, `(LogFileId, Timestamp, LineNumber)`, `ClientIp`; `LogFileHourStats` (per file/hour Total + Flagged, rebuilt after detection, backfilled by migration `ProcessingLimitsAndIndexes`) feeds the dashboard chart. Database in SIMPLE recovery.
- **Auth/config:** `AppUser.MustChangePassword` + `AppUserClaimsPrincipalFactory` claim + `RequirePasswordChangeFilter` (JSON requests get 403); `ClientNetwork.RateLimitKey` (IPv4-mapped → IPv4, IPv6 per /64); `ForwardedHeaders:KnownProxies`; `Database:MigrateOnStartup`; `AllowedHosts` = localhost; `appsettings.Development.json` not published; no-store on signed-in responses.
- **Regex (04):** `DetectionCore.Build` compiles every pattern with `RegexOptions.NonBacktracking` (linear, no ReDoS); only patterns with backreferences/lookarounds/atomic groups fall back to the backtracking engine (`CompiledRule.Backtracking`, validator probes only those). A timeout counts as a match (fail-closed, `RuleHit.TimedOutEvents`, alert Details), after 50 timeouts the rule is skipped for the rest of the file; notes go to `LogFile.DetectionWarnings` (file page) and the rule tester.
- **IP policy (03):** `IpAddressPolicy.TryGetPublic` (used by `IpEnrichmentService.IsPublic` and the providers): IPv4-mapped → IPv4, blocks private/CGNAT/documentation/benchmark/6to4/multicast, IPv6 only 2000::/3; providers get the canonical string.
- **Threat-intel cache (07):** a failed/throttled/skipped lookup never replaces a real verdict → `IpReputation.LastAttemptAt/LastAttemptError` (card shows "Last refresh failed"); unique-key race (SQL 2601/2627) → reload and retry, also for IpInfos.
- **Fan-out (10):** max `DetectionEngine.MaxAlertsPerRule` = 1000 alerts per rule and file, the long tail merged into one alert "N other IPs" (`DetectionCore.CapPerRule`, evidence kept → metrics exact); PDF shows top 200 alerts, samples in one query; CSV streamed.
- **Evaluation (29):** `EvaluationService.Compute` (pure) reports unparsed attack/normal lines and an end-to-end row (unparsed attacks = FN); unique-path ratio divides by min(n, 5000).
- **Sessions/auth (11, 13, 14, 16, 19):** one login error message for every failure + dummy hash for unknown e-mails; `RevalidateSessionFilter` re-checks the user (enabled, security stamp, Admin role) on every POST and admin page; Logout rotates the stamp; Change password is rate-limited and counts towards lockout; last-admin guard ignores disabled admins and runs under a lock; `AuditLog.Clean` strips control characters (use it for user text in ILogger calls too).
- **Threat intel (17, 24, 28):** rate-limit policy `ti-lookup` (30/min per user); daily budgets `Enrichment:*DailyBudget` (in memory, reset on restart); provider HttpClients without redirects, 1 MB max body. **`Enrichment:AutoLookup` is false by default** – set it to true (appsettings or user-secrets) for automatic lookups after each file (roadmap step 1); `RetentionDays` 90 + `DataRetentionWorker` (daily). Client IPs are stored canonically (`IpAddressPolicy.Canonical`).
- **Framework (27, 22):** global `AutoValidateAntiforgeryToken`; every action needs an explicit `[HttpGet]`/`[HttpPost]` (a reflection test fails otherwise). Package versions are exact, `Directory.Build.props` enables lock files – add packages with `dotnet add package X --version x.y.z` and commit the updated `packages.lock.json`.
- Others: labels CSV ≤ 20 MB, label ≤ 64 chars (20); rule delete blocked while a file is busy (23); alerts paging tie-breaker + `[EnumDataType]` (25); CSV/JS edge cases (30).
- Tests: `SecurityFixTests.cs`, `ProcessingFixTests.cs`, `DetectionFixTests.cs`, `HardeningFixTests.cs` (180 total; EF InMemory for threat-intel tests).

## 9. Decisions & advice already given
- **Zimmerman tools / Chainsaw:** out of scope → possible future "Windows event log module" (needs supervisor approval).
- **Threat intel:** use personal/free accounts with the **university email**; **do NOT use the work GTI account** (AKSK license, logging, quota, key leakage). Snyk is not an IP source — mention only in a secure-development section (`dotnet list package --vulnerable`).
- Isolation Forest implemented in C# instead of a Python microservice: no extra runtime, reproducible (seeded), explainable; mention scikit-learn as the reference implementation in the thesis.
- CSIC 2010 only evaluates signature rules (no real IPs/timestamps); access logs have no POST bodies → report realistic vs. `--body-as-query` upper bound.
- Rules with alerts are disabled, not deleted (traceability); users are disabled, not deleted.

## 10. Roadmap (what's left)
- **Security audit 2026-11-17:** `docs/security-audit/REPORT.md` – 0 critical, 2 High, 8 Medium, 16 Low, 4 Info. Fix order in REPORT §3; each `findings/NN-*.md` is a self-contained fix ticket ("Fix docs/security-audit/findings/NN-...md"). Update its Status line when fixed. **All 30 findings fixed on branch `security-fixes`** (not merged yet).
0. **Review the `ui-liquid-glass` branch in the browser (both themes), then merge into `main` and push.**
1. **API keys** (AbuseIPDB, GreyNoise, VirusTotal) with the university email → `dotnet user-secrets set ...` (+ `dotnet user-secrets set "Enrichment:AutoLookup" "true"` for automatic lookups) → Test button on each provider page → re-run detection on a file with public attacker IPs → check cards / dashboard / PDF / GreyNoise downgrades.
2. **RQ3 end-to-end:** `loganalyzer-tools generate --lines 1000000 --out big.log`, upload in the app (100k / 500k / 1M / 2M, 3 runs each), read times on the file page; check delete of a 1M-line file (cascade delete may be slow — consider batched delete if it times out).
3. **RQ1/RQ2 real data:** CSIC 2010 (download, `csic` command, both variants) and DVWA lab (VirtualBox: Ubuntu+Apache+DVWA, Kali, normal-traffic VM; nikto/gobuster/sqlmap/hydra + manual XSS/LFI; `label-by-ip`) → Evaluate page tables.
4. Screenshots for the thesis (dashboard, alerts, alert details with threat intel, rule tester, evaluation, users, audit).
5. Write thesis chapters (1 Intro · 2 Literature review: OWASP, ELK, GoAccess, Wazuh/OSSEC, ModSecurity, Isolation Forest paper · 3 Requirements/UML · 4 Design/ER/architecture · 5 Implementation · 6 Testing & evaluation (use docs/evaluation-guide.md) · 7 Conclusions/future work).
- Optional: tune IF threshold per dataset, batch delete for huge files, Windows event log module (Chainsaw/Sigma), live log ingestion, more log formats, automatic blocking.

## 11. Working conventions for Claude
- Answer concisely and command-ready; Daniel works step by step in VS 2026 and sends screenshots.
- Keep the existing patterns: primary-constructor services, enums as strings, `Format` helpers for badges, Bootstrap dark UI, `[ValidateAntiForgeryToken]` on POSTs, `[Authorize(Roles = Roles.Admin)]` for admin actions, log user actions with ILogger **and** `IAuditLog`.
- **No inline JavaScript or `on*` attributes** (CSP): put scripts in `wwwroot/js`, use `js-confirm` / `js-autosubmit`.
- **UI:** build new views from the Liquid Glass classes (Step 10) and test both themes; theme-dependent colours come from CSS tokens (`--lg-*`), never hard-coded hex in views or JS.
- Detection logic goes into `DetectionCore` / `AnomalyDetector` (pure) with unit tests; `DetectionEngine` stays a thin DB wrapper.
- Schema change → `dotnet ef migrations add <Name>` in `src\LogAnalyzer.Web`, then restart (auto-migrate).
- Security first (security thesis): validate input, never trust log data in HTML/JS/CSV, secrets in user-secrets, no real employer data, private IPs never leave the machine.
- After each step: build, `dotnet test`, test in browser, commit to Git (work on a branch, merge after review).
