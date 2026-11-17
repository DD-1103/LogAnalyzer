# 27 · Verb-less actions and no global antiforgery filter (defence in depth)

| | |
|---|---|
| **Severity** | Info |
| **Kind** | Hardening |
| **Area** | Authorization |
| **CWE** | CWE-352 |
| **Status** | Confirmed; not exploitable today (all POSTs validated, SameSite=Strict) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Program.cs:48`
- `AlertsController Index/Export, RulesController Index, LogFilesController Report (no [HttpGet])`

## What is wrong
About 15 actions accept any verb; GET actions with small side effects (seen-at timestamps, audit rows).

## Evidence
-

## How to reproduce
-

## Impact
None today; protects future actions that forget the attribute.

## How to fix
`options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())` and `[HttpGet]` on read actions.

## Tests to add (definition of done)
Reflection test: every action is [HttpGet] or POST with antiforgery.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/27-csrf-defense-in-depth.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
