# 19 · Unauthenticated login input with CR/LF is written into console logs and the audit table

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Logging / audit |
| **CWE** | CWE-117 Improper output neutralization for logs |
| **Status** | Confirmed (code) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/AccountController.cs:42-57`
- `src/LogAnalyzer.Web/Services/AuditLog.cs:31-37`

## What is wrong
The typed email goes into `LogWarning("Failed login for {Email}")` and `AuditEntries.Target` unfiltered; control characters can forge log lines in a security product.

## Evidence
`await audit.WriteAsync("Login.Failed", model.Email, ...)`; AuditLog only truncates.

## How to reproduce
POST /Account/Login with `Email=x\r\ninfo: User admin logged in@x`.

## Impact
Misleading forensic trail; passwords typed into the email field end up in the audit log.

## How to fix
Strip/replace control characters in `AuditLog` (and a small helper for log arguments); reject control characters in `LoginViewModel.Email`.

## Tests to add (definition of done)
AuditLog stores details containing \r\n without control characters.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/19-log-and-audit-forging.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
