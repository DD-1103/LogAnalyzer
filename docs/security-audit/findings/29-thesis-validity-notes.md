# 29 · Evaluation ignores unparsed malicious lines; anomaly feature skewed for huge scanners; DB in FULL recovery

| | |
|---|---|
| **Severity** | Info |
| **Kind** | Hardening (thesis validity / performance) |
| **Area** | Evaluation / anomaly detection |
| **CWE** | - |
| **Status** | Confirmed |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/EvaluationService.cs (labelled lines without event counted as ignored)`
- `src/LogAnalyzer.Web/Services/AnomalyDetection.cs (Paths capped at 5000 but ratio divides by all requests)`
- `Database LogAnalyzerDb (recovery model FULL)`

## What is wrong
(a) A malicious line the parser could not read is counted as ignored, not as a false negative, so recall can look better than end-to-end reality. (b) An IP with 100k+ requests gets a tiny unique-path ratio and looks normal on that feature. (c) FULL recovery makes every 1M-row insert/delete fully logged once a backup exists.

## Evidence
-

## How to reproduce
-

## Impact
Results could be challenged by the jury; slower RQ3 runs.

## How to fix
(a) Report "malicious but not parsed" separately or add an end-to-end row. (b) Divide by `min(n, MaxTrackedPaths)`. (c) `ALTER DATABASE LogAnalyzerDb SET RECOVERY SIMPLE;` and note it in the RQ3 protocol.

## Tests to add (definition of done)
EvaluateAsync with a malicious label on an unparsed line -> separate counter; 20k distinct paths -> ratio ~1.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/29-thesis-validity-notes.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
