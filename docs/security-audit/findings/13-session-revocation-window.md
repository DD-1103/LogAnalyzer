# 13 · Disabled/demoted admins keep rights for up to 60 s; logout does not invalidate a copied cookie

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Authentication / sessions |
| **CWE** | CWE-613 Insufficient session expiration / CWE-269 |
| **Status** | Fixed (branch `security-fixes`): `RevalidateSessionFilter` checks enabled + security stamp (+ Admin role) on every POST and admin page; Logout rotates the security stamp |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Program.cs:32 (ValidationInterval 1 min), 42-43 (8 h sliding cookie)`
- `src/LogAnalyzer.Web/Controllers/UsersController.cs:99, 125`
- `src/LogAnalyzer.Web/Controllers/AccountController.cs:64-71 (Logout)`

## What is wrong
Role claims in the cookie are trusted until the next security-stamp check (60 s): a just-disabled admin can still create a new Admin account. Logout only deletes the browser cookie; a stolen copy stays valid up to 8 h.

## Evidence
`o.ValidationInterval = TimeSpan.FromMinutes(1)`; Logout calls only `signInManager.SignOutAsync()`.

## How to reproduce
Admin B disables Admin A; within 60 s A posts /Users/Create with Role=Admin -> succeeds.

## Impact
Privilege persistence after revocation; replay of stolen cookies after logout.

## How to fix
1. For admin routes re-check the user in the DB on every request (authorization handler: `!IsDisabled && IsInRole(Admin)`), or validate the security stamp with interval 0 on /Users, /Rules (write), /Audit.
2. In Logout call `userManager.UpdateSecurityStampAsync(user)` before `SignOutAsync()`.

## Tests to add (definition of done)
Disable an admin then immediately POST /Users/Create with their cookie -> 403/redirect; old cookie after logout -> redirect to login.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/13-session-revocation-window.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
