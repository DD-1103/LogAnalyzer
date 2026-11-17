# 21 · Deployment defaults: Development mode in demos, TrustServerCertificate, no forwarded headers, AllowedHosts *

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Configuration |
| **CWE** | CWE-16 Configuration / CWE-295 |
| **Status** | Confirmed (config) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Properties/launchSettings.json (Development)`
- `src/LogAnalyzer.Web/appsettings.json (connection string, AllowedHosts)`
- `src/LogAnalyzer.Web/Program.cs (rate limiter partitions by RemoteIpAddress, no UseForwardedHeaders)`

## What is wrong
(a) The demo runs in Development: the developer exception page shows stack traces to anyone who triggers an error. (b) `TrustServerCertificate=True` disables SQL TLS validation. (c) Behind a reverse proxy every user would share one login rate-limit bucket and the audit log would record the proxy IP. (d) `AllowedHosts: *`. (e) Auto-migration needs DDL rights for the app account.

## Evidence
`"ASPNETCORE_ENVIRONMENT": "Development"`; `TrustServerCertificate=True`.

## How to reproduce
Trigger any 500 (e.g. finding rule-save-empty-name-500) during the demo -> full stack trace.

## Impact
Information disclosure during the demo; weaker setup if ever deployed.

## How to fix
1. Add a `Demo`/Production launch profile for the jury (exception handler + HSTS).
2. Keep `TrustServerCertificate` only in appsettings.Development.json.
3. Add `UseForwardedHeaders` with `KnownProxies` when deployed behind a proxy; partition IPv6 by /64.
4. Set real `AllowedHosts` in Production; run migrations with a separate account.

## Tests to add (definition of done)
Production-environment smoke test: an exception returns the generic /Home/Error page without stack trace.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/21-deployment-config-defaults.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
