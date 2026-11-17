# LogAnalyzer – full security & reliability audit

**Date:** 2026-11-17 · **Branch:** `ui-liquid-glass` (commit 3398cd3) · **Type:** white-box code review + live tests against the running app (localhost, owner-authorised)

## 1. Verdict

**No critical vulnerability. No RCE, SQL injection, XSS, CSRF, IDOR, open redirect, path traversal or SSRF was found** – the classic web-attack classes are handled correctly and were confirmed with a hostile log file in the live app. The real risks are **scale and robustness** (what breaks with 1–2M-line logs and failures), a **privacy gap** in the "private IPs never leave the machine" promise, and a **detection-evasion** path for badly written admin rules.

| Area | Score | Comment |
|---|:---:|---|
| Injection (SQLi, command, deserialization, XXE) | **10/10** | No raw SQL, no dangerous APIs; bulk insert with fixed mappings |
| Output encoding / XSS / CSP | **9.5/10** | Everything encoded, strict CSP, no inline JS; only CDN without SRI |
| Authentication & authorization | **8/10** | Every action correctly protected; enumeration, revocation window, seed passwords |
| Input / resource limits | **6/10** | gzip bombs, unbounded lines, unlimited alerts, ReDoS fail-open |
| Reliability at RQ3 scale | **5/10** | Quadratic threshold rules, delete timeouts, worker can stop the host |
| Privacy / threat-intel integration | **6.5/10** | Mapped/special IPs leak, cache overwrites, quota abuse |
| Code quality & tests | **8/10** | Clean structure, 0 warnings, 74 tests; no tests for worker/evaluation/report |
| **Overall** | **7.5/10 (B+)** | Secure by design for the web layer; needs hardening for big files before RQ3 |

## 2. Findings at a glance (30)

| # | Severity | Kind | Finding | Status |
|---|---|---|---|---|
| [01](findings/01-threshold-evidence-quadratic.md) | **High** | Will break | Threshold rules are quadratic on fast scanners – detection alone ~170 s for 1M lines at 200 req/s (RQ3 fails) | **Fixed** |
| [02](findings/02-large-file-delete-timeout.md) | **High** | Will break | Deleting / re-parsing a 1–2M line file times out (30 s) and leaves alerts without evidence | **Fixed** |
| [03](findings/03-private-ip-leak-to-threat-intel.md) | Medium | Vulnerability | `::ffff:10.x`, `100.64/10`, `::` … treated as public → internal IPs sent to AbuseIPDB/GreyNoise/VirusTotal | **Confirmed live** |
| [04](findings/04-regex-timeout-fails-open.md) | Medium | Vulnerability | Regex timeout = "no match": attackers can hide payloads from weak admin rules; validator misses `(\w+\s*)+` | Confirmed (experiment) |
| [05](findings/05-upload-expansion-and-unbounded-input.md) | Medium | Vulnerability | gzip bomb (3.5 MB → 10M rows), unbounded line length, int line counters | **Fixed** |
| [06](findings/06-worker-crash-and-cancel-handling.md) | Medium | Will break | A DB error inside the worker's catch stops the whole app; shutdown can mark files Failed | **Fixed** |
| [07](findings/07-threat-intel-cache-overwrite-and-race.md) | Medium | Broken | Rate-limited/failed lookup overwrites a good verdict; concurrent lookups → 500 | Confirmed |
| [08](findings/08-threat-intel-blocks-queue.md) | Medium | Will break | Threat-intel lookups block the upload queue (up to ~30 min) | **Fixed** |
| [09](findings/09-query-scaling-and-indexes.md) | Medium | Will break | Dashboard/events/detection queries scan all events; missing composite indexes | **Fixed** |
| [10](findings/10-report-and-alert-fanout.md) | Medium | Will break | PDF report N+1 queries; unlimited alerts from fake IP fields | Confirmed (code) |
| [11](findings/11-login-enumeration-and-admin-lockout.md) | Low | Vulnerability | Login reveals existing accounts; anyone can keep the admin locked out | Confirmed (code) |
| [12](findings/12-dev-seed-credentials.md) | Low | Hardening | Seed passwords committed/documented; fresh Production has no admin | **Fixed** |
| [13](findings/13-session-revocation-window.md) | Low | Hardening | Disabled admin keeps rights 60 s; logout doesn't revoke copied cookies | Confirmed |
| [14](findings/14-last-admin-guard-bugs.md) | Low | Broken | Last-admin guard: race to zero admins; can't demote a disabled admin | Confirmed (code) |
| [15](findings/15-rule-save-empty-name-500.md) | Low | Broken | Empty rule name → HTTP 500 NullReferenceException | **Fixed** |
| [16](findings/16-change-password-no-throttle.md) | Low | Hardening | Change password has no rate limit/lockout | Confirmed |
| [17](findings/17-threat-intel-quota-and-http-hardening.md) | Low | Hardening | Analysts can burn API quotas; HttpClient follows redirects, unbounded bodies | Confirmed / Likely |
| [18](findings/18-exception-details-in-ui.md) | Low | Hardening | Raw exception text (paths, SQL, account) shown in the UI | **Fixed** |
| [19](findings/19-log-and-audit-forging.md) | Low | Hardening | CR/LF from the login form forged into logs/audit | Confirmed (code) |
| [20](findings/20-evaluate-memory.md) | Low | Hardening | Evaluate loads 100 MB labels + all line numbers per request | Confirmed (code) |
| [21](findings/21-deployment-config-defaults.md) | Low | Hardening | Demo runs in Development (stack traces), TrustServerCertificate, no forwarded headers | **Fixed** |
| [22](findings/22-floating-package-versions.md) | Low | Hardening | Floating NuGet versions, no lock file (no vulnerable packages today) | Confirmed |
| [23](findings/23-rule-delete-during-detection.md) | Low | Broken | Deleting a rule during detection fails the file (FK) | Confirmed (code) |
| [24](findings/24-ip-normalisation-mismatch.md) | Low | Broken | IP lookup canonicalises, stored IPs don't → 0 counts, duplicate lookups | Confirmed (logic) |
| [25](findings/25-alerts-paging-and-triage-validation.md) | Low | Broken | Alert paging without tie-breaker; invalid status → misleading message | Confirmed (live for status) |
| [26](findings/26-browser-hardening.md) | Low | Hardening | CDN scripts without SRI; no `Cache-Control: no-store` on signed-in pages | **Fixed** |
| [27](findings/27-csrf-defense-in-depth.md) | Info | Hardening | No global antiforgery filter / verb-less actions (not exploitable today) | Confirmed |
| [28](findings/28-privacy-retention-and-auto-sharing.md) | Info | Hardening | No switch for automatic lookups, no retention limit | Confirmed |
| [29](findings/29-thesis-validity-notes.md) | Info | Hardening | Evaluation ignores unparsed attacks; anomaly feature skew; DB FULL recovery | Partly fixed (c) |
| [30](findings/30-frontend-edge-cases.md) | Info | Will break | CSV full-width signs, count-up locale, nested tables, autosubmit | Confirmed (code) |

**Kinds:** *Vulnerability* = can be abused · *Broken* = wrong today · *Will break* = fails at scale / under failure · *Hardening* = defence in depth.

## 3. Recommended fix order

1. **Before the jury demo (small, high visibility):** 15 (500 on empty rule name), 21 (run the demo outside Development → no stack traces), 12 (change/move the seed passwords), 06 (app must never stop on a DB error), 26 (self-host the 4 libraries → demo also works offline).
2. **Before the RQ3 measurements:** 01 (quadratic threshold rules), 02 (batched delete), 05 (upload limits), 09 (composite indexes), 29c (SIMPLE recovery), 08 (threat intel off the upload queue).
3. **Before writing the evaluation chapter:** 04 (timeouts must not hide attacks), 03 (privacy claim), 29a (count unparsed attacks), 07 (reliable threat-intel evidence), 10 (PDF for real logs).
4. **Then:** the remaining Low/Info items (authentication hardening 11, 13, 14, 16; 17–20, 22–25, 27, 28, 30).

Each finding file ends with a ready-to-paste instruction, e.g.:

```
Fix docs/security-audit/findings/01-threshold-evidence-quadratic.md: implement the fix and the tests described there, ...
```

### Fix progress

| Date | Branch | Fixed |
|---|---|---|
| 2026-11-17 | `security-fixes` | Before the jury demo: 15, 21, 12, 06, 26 · Before RQ3: 01, 02, 05, 09, 29c, 08 · also 18 (same code). 108 tests (was 74). |

## 4. Scope and method

**Covered:** all 8 controllers and every action (verb, route, role, antiforgery – table below), all services, data model and migrations, all 20+ Razor views and partials, all 4 JavaScript files and CSS, security headers/CSP, configuration, secrets, dependencies, tests, and the tools project.

**Five parallel audit agents**, each with its own checklist skills:

| Agent | Area | Skills used |
|---|---|---|
| A | Authentication, authorization, sessions, CSRF, redirects, business logic | security-review · BugHunter: hunt-auth-bypass, hunt-idor, hunt-csrf, hunt-session, hunt-brute-force, hunt-open-redirect, hunt-business-logic, hunt-race-condition |
| B | Injection, uploads, parsing, regex/ReDoS, resources, export | security-review · BugHunter: hunt-sqli, hunt-file-upload, hunt-lfi, hunt-rce, hunt-exceptional-conditions, hunt-business-logic |
| C | XSS, DOM, CSP, headers, clickjacking, third-party scripts | security-review · BugHunter: hunt-xss, hunt-dom, hunt-html-injection, hunt-clickjacking, hunt-host-header, hunt-cors |
| D | Outbound HTTP/SSRF, threat intel, config, secrets, logging, dependencies | security-review · BugHunter: hunt-ssrf, hunt-api-misconfig, hunt-source-leak, hunt-misc, hunt-exceptional-conditions |
| E | Reliability, scale, concurrency, migrations, test gaps | superpowers:systematic-debugging, engineering:code-review · BugHunter: hunt-race-condition, hunt-exceptional-conditions |

The lead auditor merged duplicates (several agents found the same IP, worker and upsert problems independently), removed one false positive (user-agent set was claimed unbounded; it is capped at 100), and re-verified findings in code and in the live app.

**Experiments run by the agents:** IP-classification probe of `IsPublic`; parser regex timing on 1M-char crafted lines (linear, 0–42 ms); ReDoS evasion of an admin rule; gzip ratio measurement; benchmark of threshold rules on the real `DetectionCore`; EF Core probes (large `Contains`, `GetPendingMigrationsAsync` on a new DB); `dotnet build` (0 warnings), `dotnet test` (74/74), `dotnet list package --vulnerable` (none).

## 5. Live tests (app running on localhost)

A hostile access log (430 lines) with XSS in URL / user agent / referrer / IP / method fields, `</script>` breakouts, CSV formula payloads, Unicode right-to-left override, null bytes, a 9,000-char URL and malformed lines was uploaded **under the file name `"><img src=x onerror=alert(9)>.log`** through the real upload form (CSRF token included), then removed again.

| Check | Result |
|---|---|
| Log files list, file details (2 pages), Evaluate, Alerts list, 4 alert details, Dashboard, rule tester file list, Audit log, IP lookup with `<script>` as IP | **0 injected elements, 0 inline scripts – all payloads shown as text** |
| Dashboard JSON data block with hostile values | Parsed correctly, no breakout |
| CSV export | No unneutralised formula cell |
| PDF report with hostile data | Generated (200, 86 KB) |
| `/ThreatIntel/Lookup?ip=10.0.0.5` vs `::ffff:10.0.0.5`, `100.64.1.1`, `::` | Private vs **treated as public** → finding 03 |
| Rule with empty name | **HTTP 500 NullReferenceException** → finding 15 |
| Triage with Status=99 | Rejected, but message "Notes are too long" → finding 25 |

## 6. Action / authorization map (summary)

Global `AuthorizeFilter` requires login everywhere except Login (GET/POST), AccessDenied and Error. Every POST has `[ValidateAntiForgeryToken]`; every binding model is a DTO (no over-posting).

| Controller | Analyst | Admin only |
|---|---|---|
| Account | Login, Logout, ChangePassword | – |
| Home | Dashboard, NavCounts | – |
| LogFiles | Index, Upload, Details, Evaluate, Report | RerunDetection, Delete |
| Alerts | Index, Details, Update (triage), Export | – |
| Rules | Index | Create, Edit, Save/Test, Toggle, Delete |
| ThreatIntel | Index, Provider, Lookup, Refresh, Api | Test |
| Users | – | all actions |
| Audit | – | Index |

## 7. Checked and safe (highlights)

- **SQL:** no raw SQL anywhere (the only migration SQL is a static literal); all filters are parameterised LINQ; SqlBulkCopy uses fixed column mappings and truncates to column sizes.
- **Files:** uploads are stored as `App_Data/uploads/{id}.log` – the user's file name is never used in a path; there is no download endpoint; App_Data is outside wwwroot; extension allow-list.
- **Code execution:** no BinaryFormatter, TypeNameHandling, XML parsers, `Process.Start` or dynamic code (tools project included).
- **XSS:** Razor encodes everything; the only `Html.Raw` is the JSON block (escaped by System.Text.Json); JavaScript uses `textContent`/`setAttribute` only; Leaflet popups built with DOM nodes; Chart.js draws on canvas.
- **CSP & headers:** no inline scripts or event handlers; `frame-ancestors 'none'` + `X-Frame-Options: DENY`; `object-src 'none'`, `base-uri`, `form-action` locked; nosniff, Referrer-Policy, Permissions-Policy, COOP; HSTS outside Development.
- **Redirects:** Login and threat-intel `returnUrl` use `Url.IsLocalUrl` + `LocalRedirect`.
- **SSRF:** provider hosts are fixed HTTPS constants; the IP is passed through `Uri.EscapeDataString`.
- **Sessions:** cookie HttpOnly, Secure, SameSite=Strict; security stamp rotated on disable/role change/password reset; disabled users cannot sign in (same generic message).
- **Secrets:** API keys only from configuration/user-secrets, never rendered or logged; no keys in git history.
- **Dependencies:** no known vulnerable packages (web + tests).
- **Startup:** migration check works on a brand-new database; EF `Contains` with >2,100 values works (OPENJSON).

## 8. Notes for the thesis

- This audit itself is good material for the *Testing & evaluation* and *Security* chapters: the method (parallel white-box review by vulnerability class + live hostile-input test), the coverage table and the "safe" list document the security of the system; findings 01, 04 and 29 are threats to validity of RQ1–RQ3 and should be fixed (or discussed) before measuring.
- Findings 03 and 28 belong in the *Ethics / privacy* section (what data leaves the system, and when).
