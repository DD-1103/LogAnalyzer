# 17 · Any analyst can burn API quotas; provider HttpClients follow redirects with the key and read unbounded bodies

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Threat intel |
| **CWE** | CWE-770 / CWE-200 |
| **Status** | Fixed (branch `security-fixes`): rate limit "ti-lookup" (30/min per user) on Refresh/Test, daily budget per provider, no redirects, 1 MB response limit; verified live (31st → 429) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/ThreatIntelController.cs:110-147 (Refresh, no limit)`
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs:106-107, 440 (throttle only for VirusTotal)`
- `src/LogAnalyzer.Web/Program.cs:80-82 (default HttpClient handler)`

## What is wrong
Refresh is open to every signed-in user and only VirusTotal is throttled, so a loop exhausts AbuseIPDB (1,000/day) and GreyNoise. The default handler follows redirects (custom key headers would be re-sent) and buffers bodies up to ~2 GB.

## Evidence
`AddHttpClient<AbuseIpDbProvider>(c => c.Timeout = ...)` with default handler; `await response.Content.ReadAsStringAsync(ct)`.

## How to reproduce
Script 1,000 POSTs to /ThreatIntel/Refresh -> automatic enrichment returns 429 for the rest of the day.

## Impact
Threat intel stops working; possible key disclosure if a vendor endpoint misbehaves.

## How to fix
1. Rate-limit policy `ti-lookup` per user (e.g. 30/min) on Refresh; serve fresh cache unless an admin forces a refresh; daily budget per provider.
2. `.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false })` and `MaxResponseContentBufferSize = 1_000_000`; treat 3xx as Failed.

## Tests to add (definition of done)
31st Refresh within a minute -> 429; fake 302 -> Error and no second request; 2 MB body -> Error.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/17-threat-intel-quota-and-http-hardening.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
