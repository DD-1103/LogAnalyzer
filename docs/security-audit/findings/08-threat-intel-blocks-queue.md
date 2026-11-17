# 08 · Threat-intel lookups run inside the single upload worker, so the next upload waits up to ~30 minutes

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Will break |
| **Area** | Background worker / threat intel |
| **CWE** | CWE-400 Uncontrolled resource consumption |
| **Status** | Fixed (branch `security-fixes`): own ThreatIntelWorker + queue with a time budget per file |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:229-240`
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs:486-499`

## What is wrong
After a file is Completed, the same worker awaits all reputation lookups (up to 200 AbuseIPDB x 10 s timeout, 25 GreyNoise, 4 VirusTotal 15 s apart) before it starts the next queued file.

## Evidence
`await sp.GetRequiredService<ThreatIntelService>().RunForLogFileAsync(id, ct);` runs in the same `await foreach` as parsing.

## How to reproduce
Configure API keys (roadmap step 1), upload a file with many public IPs, then a second file: the second stays Pending for minutes.

## Impact
Looks frozen during the demo; queued uploads stall.

## How to fix
Move threat intel to its own `Channel<int>` + BackgroundService (or a low-priority job type the worker processes only when idle) with a total time budget per file.

## Tests to add (definition of done)
Fake provider that delays 5 s: the second file reaches Processing before the first file's threat intel finishes.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/08-threat-intel-blocks-queue.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
