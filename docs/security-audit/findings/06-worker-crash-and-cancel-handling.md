# 06 · One database hiccup can stop the whole app; a normal shutdown can mark a file Failed

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Will break |
| **Area** | Background worker |
| **CWE** | CWE-755 Improper handling of exceptional conditions |
| **Status** | Confirmed in code (not executed) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:45 (RequeueUnfinishedAsync, unguarded)`
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:57-65 (catch blocks)`
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:249-256 (MarkFailedAsync, unguarded)`

## What is wrong
If SQL Server is unavailable, the catch block calls `MarkFailedAsync`, which throws again; the exception escapes `ExecuteAsync` and .NET's default `BackgroundServiceExceptionBehavior.StopHost` stops the web app. Also, on shutdown SqlClient often reports cancellation as `SqlException`, not `OperationCanceledException`, so the file is marked Failed instead of resumed.

## Evidence
```csharp
catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
catch (Exception ex)
{
    logger.LogError(ex, ...);
    await MarkFailedAsync(id, ex.Message);   // can throw -> host stops
}
```

## How to reproduce
Upload a big log, restart the MSSQLSERVER service during the import -> the app process exits. Or press Ctrl+C during detection -> file may show Failed.

## Impact
The app dies in the middle of a demo or RQ3 run; files left Failed with no way to re-process.

## How to fix
1. `catch (Exception) when (stoppingToken.IsCancellationRequested) { break; }` before the general catch.
2. Wrap `MarkFailedAsync` and `RequeueUnfinishedAsync` in try/catch + log; the loop must never throw.
3. Add `ProcessingAttempts` to LogFile; after 3 failed attempts mark Failed instead of re-queuing forever.
4. Allow re-processing of Failed files from the UI (Admin).

## Tests to add (definition of done)
Worker test with a fake scope factory whose DbContext always throws -> ExecuteAsync keeps consuming the next job; cancelled token -> file not marked Failed.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/06-worker-crash-and-cancel-handling.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
