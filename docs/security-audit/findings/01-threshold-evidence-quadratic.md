# 01 · Threshold rules get quadratically slower on fast scanners (breaks the RQ3 time target)

| | |
|---|---|
| **Severity** | High |
| **Kind** | Will break |
| **Area** | Detection engine |
| **CWE** | CWE-407 Inefficient Algorithmic Complexity |
| **Status** | Fixed (branch `security-fixes`): linear evidence collection, equivalence + 200k-event tests |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/DetectionCore.cs:98-104 (threshold branch)`
- `src/LogAnalyzer.Web/Services/RuleManagement.cs (RuleTester runs the same code inside an HTTP request)`

## What is wrong
After a threshold rule fires, every following event of that IP re-adds the WHOLE sliding window to the hit (`foreach (var (ts, id) in window) hit.Add(id, ts);`). Cost is O(events x window size). Normal traffic is fine; a fast scanner (gobuster, hydra, nikto - exactly what the DVWA lab produces) makes the window large.

## Evidence
```csharp
if (window.Count >= r.Rule.Threshold)
{
    var hit = GetHit(r.Rule.Id, e.ClientIp);
    foreach (var (ts, id) in window)
        hit.Add(id, ts);
}
```
Measured (200k events, one IP, 404s, default Directory-enumeration rule 50/60 s): 5 req/s 0.96 s; 50 req/s 8.7 s; 200 req/s 34 s. 1M events at 200 req/s is about 170 s for detection alone - above the < 2 min RQ3 target.

## How to reproduce
1. `loganalyzer-tools generate` a log where one IP sends 200 req/s of 404s for 1-2 hours (or run gobuster in the DVWA lab).
2. Upload it; look at *Detection* time on the file page.
3. Or open Rules -> Edit -> Test with a threshold rule on that file: the request takes minutes.

## Impact
Fails RQ3 on realistic attack traffic, blocks the single background worker (all later uploads wait), and the rule tester request hangs.

## How to fix
Keep a per-(rule, IP) counter of events not yet added to the hit. When the threshold is (still) reached, add only those last N events instead of the whole window, then reset the counter to 0. Use a structure with index access (List/ring buffer) or simply remember that only the newest event needs adding once the window has been flushed once. Evidence must stay identical.

## Tests to add (definition of done)
- Property test: random event streams (including a window that drops below and re-crosses the threshold) give the SAME evidence set before and after the change.
- Performance guard: 200k events at 200 req/s from one IP finish in < 2 s.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/01-threshold-evidence-quadratic.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
