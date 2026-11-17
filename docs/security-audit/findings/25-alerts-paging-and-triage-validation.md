# 25 · Alert list paging can repeat/skip alerts; invalid triage status gives a misleading error

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Broken |
| **Area** | Alerts |
| **CWE** | - |
| **Status** | Confirmed (paging: code; status: live) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/AlertsController.cs:171-174 (Sort)`
- `src/LogAnalyzer.Web/Controllers/AlertsController.cs (Update)`
- `src/LogAnalyzer.Web/ViewModels/ViewModels.cs (AlertUpdateModel)`

## What is wrong
The sort has no unique tie-breaker, so alerts with equal LastSeen can move between pages. Posting Status=99 is rejected (good) but the flash says "Notes are too long".

## Evidence
Live: Status=99 -> "Notes are too long (max 4000 characters)."

## How to reproduce
Many alerts with the same LastSeen -> page through; or tamper the Status field.

## Impact
Analysts can miss alerts when paging; confusing message.

## How to fix
Append `.ThenByDescending(a => a.Id)`; add `[EnumDataType(typeof(AlertStatus))]` and show the real ModelState error.

## Tests to add (definition of done)
60 alerts with equal LastSeen: union of pages = all ids; Status=99 -> "Invalid status".
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/25-alerts-paging-and-triage-validation.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
