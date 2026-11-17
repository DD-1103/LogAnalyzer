# 30 · Small frontend edge cases (CSV full-width formula signs, count-up locale, nested tables, autosubmit)

| | |
|---|---|
| **Severity** | Info |
| **Kind** | Will break |
| **Area** | Frontend / export |
| **CWE** | CWE-1236 (CSV part) |
| **Status** | Confirmed in code; none triggered by current views |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Helpers/Format.cs:76-83 (Csv)`
- `src/LogAnalyzer.Web/wwwroot/js/site.js (count-up, setupTables, js-autosubmit)`

## What is wrong
(a) CSV neutralises only = + - @ \t \r at index 0 - not full-width ＝＋－＠ or a leading space/newline. (b) Count-up skips numbers that use '.' as thousands separator (other server cultures). (c) The stacked-table script would also label rows of nested tables. (d) `e.target.form.submit()` throws if a js-autosubmit select is outside a form.

## Evidence
`if ("=+-@\t\r".Contains(value[0])) value = "'" + value;`

## How to reproduce
-

## Impact
Cosmetic / defence in depth.

## How to fix
(a) Check the first non-whitespace char against `=+-@＝＋－＠\t\r\n`. (b) Detect the separator from the text. (c) Use `:scope > thead > tr > th` and `:scope > tbody > tr`. (d) `e.target.form?.requestSubmit()`.

## Tests to add (definition of done)
Format.Csv("＝1+1") and Format.Csv(" =1+1") start with "'.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/30-frontend-edge-cases.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
