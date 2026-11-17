# 23 · Deleting a rule while detection runs fails the whole file (foreign-key error)

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Broken |
| **Area** | Rules / detection |
| **CWE** | CWE-367 |
| **Status** | Fixed (branch `security-fixes`): rules cannot be deleted while a file is processed; findings of a rule deleted meanwhile are dropped instead of failing the file |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/RulesController.cs (Delete)`
- `src/LogAnalyzer.Web/Services/DetectionEngine.cs:44, 55-56, 120-123`

## What is wrong
The engine deletes the file's old alerts first, so a rule with alerts only on that file looks deletable; when the engine then saves new alerts for that rule, the Restrict FK fails and the file is marked Failed.

## Evidence
Delete allowed because `Alerts.Count(RuleId) == 0` during the run.

## How to reproduce
Re-run detection on a large file and delete a rule (that only matched that file) within those seconds.

## Impact
Failed file; must re-process.

## How to fix
Block rule deletion while any file is busy, or in `SaveAlertsAsync` drop findings for rules that no longer exist.

## Tests to add (definition of done)
Delete the rule between compile and save (test hook) -> file still completes.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/23-rule-delete-during-detection.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
