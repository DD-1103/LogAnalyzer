# 07 · A failed or rate-limited lookup overwrites a good cached verdict; concurrent first lookups crash with a 500

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Broken |
| **Area** | Threat intel |
| **CWE** | CWE-841 Improper enforcement of behavioral workflow / CWE-362 Race condition |
| **Status** | Fixed (branch `security-fixes`): failed/throttled lookups keep the earlier verdict (LastAttemptAt/LastAttemptError), unique-key race retried; verified live |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs:438-469 (RefreshAsync check-then-insert and unconditional overwrite)`
- `src/LogAnalyzer.Web/Services/IpEnrichment.cs:112-141 (IpInfos, same pattern)`
- `src/LogAnalyzer.Web/Controllers/ThreatIntelController.cs:110-147`

## What is wrong
Every outcome is saved over the cached row - also throttled, 401/403, 429, 5xx and timeouts. A double-click on *Refresh (VirusTotal)* within 15 s replaces "Malicious 12/90" with "Error: Rate limit". The insert is check-then-add; two concurrent lookups of a new IP violate the unique (Ip, Provider) index -> DbUpdateException (500 in the UI, aborted enrichment in the worker).

## Evidence
```csharp
else if (!await throttle.TryEnterAsync(...)) result = ReputationResult.Failed("Rate limit...");
...
row.Verdict = result.Verdict; row.Score = result.Score; row.Error = ...; // always
```

## How to reproduce
With a VirusTotal key: open an alert whose IP is Malicious, click Refresh twice quickly -> the card shows Error. Or click Refresh while the worker enriches the same IP.

## Impact
Triage evidence (shown on alert details, dashboard, PDF) is lost; random 500 errors; GreyNoise downgrade skipped for the file.

## How to fix
1. Do not persist Error/Skipped over an existing good verdict: keep the old verdict and store the failure in `Error` + a new `LastAttemptAt` (migration), or don't save throttled results at all.
2. Make the upsert race-safe: catch `DbUpdateException` with SQL error 2601/2627, reload and update (or use MERGE).

## Tests to add (definition of done)
- Fake provider: seed Malicious, refresh with exhausted throttle / Failed result -> still Malicious.
- Two parallel RefreshAsync calls for a new IP -> no exception, one row.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/07-threat-intel-cache-overwrite-and-race.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
