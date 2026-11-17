# 15 · Saving or testing a rule with an empty name crashes with HTTP 500

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Broken |
| **Area** | Rules |
| **CWE** | CWE-476 NULL pointer dereference |
| **Status** | Fixed (branch `security-fixes`): verified live, validation message instead of 500 |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/RulesController.cs:71 (`model.Normalize()` before the ModelState check)`
- `src/LogAnalyzer.Web/ViewModels/ViewModels.cs (RuleFormModel.Normalize: `Name = Name.Trim();`)`

## What is wrong
MVC binds an empty field to null, so `Name.Trim()` throws before validation can show "Name is required". In Development the stack trace page is shown.

## Evidence
Live: POST /Rules/Save with Name='' and intent=test -> 500 NullReferenceException.

## How to reproduce
Rules -> New rule -> leave Name empty -> Test (or Save).

## Impact
Crash page instead of a validation message (bad during a demo).

## How to fix
`Name = (Name ?? string.Empty).Trim();` and null-safe handling of the other strings in `Normalize()`; optionally add `required` on the input.

## Tests to add (definition of done)
`new RuleFormModel { Name = null! }.Normalize()` does not throw; controller returns the view with a ModelState error.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/15-rule-save-empty-name-500.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
