# 18 · Raw exception messages (SQL, file paths, account names) are shown to all users

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Background worker |
| **CWE** | CWE-209 Information exposure through error messages |
| **Status** | Fixed (branch `security-fixes`): worker stores user-safe messages, full exception only in the log |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:64`
- `src/LogAnalyzer.Web/Views/LogFiles/Details.cshtml (ErrorMessage)`
- `src/LogAnalyzer.Web/Views/LogFiles/Index.cshtml (ErrorMessage)`

## What is wrong
`MarkFailedAsync(id, ex.Message)` stores SqlException/IOException/InvalidDataException text verbatim and every user sees it (HTML-encoded, so no XSS).

## Evidence
Uploading `x.gz` with non-gzip bytes shows the InvalidDataException text; a DB failure would show e.g. `Login failed for user 'DANIEL\User'`.

## How to reproduce
Upload a renamed text file as `.gz`.

## Impact
Internal paths/accounts/server names visible to analysts.

## How to fix
Map exceptions to friendly messages (InvalidDataException -> "Not a valid gzip file", SqlException -> "Database error (ref {id})", other -> "Processing failed (ref {id})"); log the full exception only.

## Tests to add (definition of done)
Unit test for the mapper: no path or SQL text in the output.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/18-exception-details-in-ui.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
