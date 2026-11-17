# 02 · Deleting (or re-parsing) a 1-2M line file times out and leaves it half-deleted

| | |
|---|---|
| **Severity** | High |
| **Kind** | Will break |
| **Area** | Log files / database |
| **CWE** | CWE-400 / CWE-460 Improper cleanup on thrown exception |
| **Status** | Likely (code path confirmed; exact timing depends on disk) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/LogFilesController.cs:213-215 (Delete)`
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:106-108 (re-parse cleanup)`
- `src/LogAnalyzer.Web/Services/DetectionEngine.cs:55-56`
- `src/LogAnalyzer.Web/Program.cs:13-14 (no CommandTimeout, default 30 s)`

## What is wrong
Delete first removes all evidence (committed), then `db.LogFiles.Remove(file); SaveChanges()` makes SQL Server cascade-delete 1-2M wide LogEvents rows (4 indexes, FK probes) in ONE statement under the default 30 s command timeout. On timeout the file stays, but its alerts have lost their evidence, and every retry times out again. The crash-resume path runs the same big ExecuteDelete and then marks the file Failed - Failed files can be neither re-run (needs Completed) nor deleted reliably.

## Evidence
```csharp
await db.AlertEvidence.Where(e => e.Alert!.LogFileId == id).ExecuteDeleteAsync();
db.LogFiles.Remove(file);
await db.SaveChangesAsync();   // cascades 1-2M LogEvents rows, 30 s timeout
```

## How to reproduce
1. Generate and upload a 2M-line log (`loganalyzer-tools generate --lines 2000000`).
2. Press Delete -> `SqlException: Execution Timeout Expired`.
3. Open the file: alerts exist but show 0 evidence. Deleting again fails the same way.

## Impact
Stuck, undeletable files after the RQ3 runs; broken dashboard/evaluation for that file; several GB of transaction log.

## How to fix
1. Delete in batches in a loop: evidence -> events -> alerts -> file, e.g. `DELETE TOP (20000) FROM LogEvents WHERE LogFileId = @id` until 0 rows (use `ExecuteSqlInterpolatedAsync`).
2. `db.Database.SetCommandTimeout(TimeSpan.FromMinutes(10))` in worker scopes.
3. Move deletion into the background worker (`ProcessingJob` kind Delete + status `Deleting`) so the HTTP request returns immediately.
4. Allow *Re-process* for Failed files.

## Tests to add (definition of done)
- Integration test (LocalDB): seed 200k events with evidence, delete with a 1 s per-batch timeout -> 0 rows left, no orphans.
- Simulated failure mid-delete leaves no alerts without evidence (delete alerts before/with their evidence).
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/02-large-file-delete-timeout.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
