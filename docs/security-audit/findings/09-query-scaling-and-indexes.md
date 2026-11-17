# 09 · Dashboard, events list and detection sort/group all events - pages slow down as data grows

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Will break |
| **Area** | Database / performance |
| **CWE** | CWE-405 Asymmetric resource consumption |
| **Status** | Likely (query shapes + index list; not measured) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/DashboardService.cs (hourly GroupBy over all events + EXISTS on AlertEvidence)`
- `src/LogAnalyzer.Web/Controllers/LogFilesController.cs:97-109 (ORDER BY LineNumber OFFSET)`
- `src/LogAnalyzer.Web/Services/DetectionEngine.cs:61-66 and RuleManagement.cs:102-105 (ORDER BY Timestamp, LineNumber)`
- `src/LogAnalyzer.Web/Data/AppDbContext.cs:45-47 (single-column indexes only)`

## What is wrong
Only single-column indexes exist on LogEvents (LogFileId, ClientIp, Timestamp). The "All log files" dashboard aggregates every event twice per page load; deep pages of the events list sort a whole file; ClientIp/Timestamp indexes slow every bulk insert but are not used with a LogFileId filter.

## Evidence
After the RQ3 runs (4 x 1M lines) every dashboard load scans ~4M rows twice.

## How to reproduce
Upload several 1M-line files, open `/` and `/LogFiles/Details/{id}?page=20000`, time them.

## Impact
Slow pages during the jury demo; RQ3 insert speed lower than necessary.

## How to fix
1. Add composite indexes `(LogFileId, LineNumber)` and `(LogFileId, Timestamp, LineNumber)` (migration).
2. Drop the standalone `Timestamp` index (keep `ClientIp` only if Lookup needs it).
3. Store per-file hourly counts when processing (small `FileHourStats` table) or default the dashboard to the latest file.

## Tests to add (definition of done)
Add timing of `/`, deep events page and rule Test to the RQ3 benchmark protocol.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/09-query-scaling-and-indexes.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
