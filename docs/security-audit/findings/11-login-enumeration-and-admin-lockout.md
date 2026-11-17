# 11 · Login reveals which accounts exist (lockout message, timing) and lets anyone keep the admin locked

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Vulnerability |
| **Area** | Authentication |
| **CWE** | CWE-204 / CWE-208 / CWE-645 |
| **Status** | Confirmed (message); Likely (timing, framework behaviour). Not executed live to avoid locking the account. |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/AccountController.cs:47-58`
- `src/LogAnalyzer.Web/Program.cs:21-22, 54-56`

## What is wrong
Existing accounts get "Account locked..." after 5 wrong passwords; unknown addresses always get "Invalid email or password" and answer faster (no password hashing). With 5 tries every 15 minutes an anonymous attacker keeps `admin@loganalyzer.local` (name is in the repo) locked.

## Evidence
`if (result.IsLockedOut) ... "Account locked after too many failed attempts." else ... "Invalid email or password."`

## How to reproduce
POST /Account/Login 6x with a wrong password for an existing vs a made-up email; compare the 6th response.

## Impact
Account discovery; denial of service against administrators.

## How to fix
1. Same generic message for lockout (audit the lockout server-side only).
2. Equalise timing: for unknown users verify a dummy hash.
3. Keep the admin Unlock action; optionally exponential lockout.

## Tests to add (definition of done)
Integration test: after 5 failures the 6th response body is identical for existing and non-existing users.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/11-login-enumeration-and-admin-lockout.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
