# 16 · Change password has no rate limit or lockout (brute force with a stolen session)

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Authentication |
| **CWE** | CWE-307 |
| **Status** | Fixed (branch `security-fixes`): rate limit "login" on Change password, wrong current passwords count towards the lockout |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/AccountController.cs:76-93`

## What is wrong
`ChangePasswordAsync` checks the current password without counting failures, and the action has no rate limit.

## Evidence
No `[EnableRateLimiting]`; `CheckPasswordAsync` does not call `AccessFailedAsync`.

## How to reproduce
With a valid cookie, loop POST /Account/ChangePassword with guessed current passwords.

## Impact
Turns a temporary session theft into a known (maybe reused) password.

## How to fix
Add `[EnableRateLimiting("login")]` and verify the current password first with `signInManager.CheckPasswordSignInAsync(user, current, lockoutOnFailure: true)`.

## Tests to add (definition of done)
6 wrong current passwords -> 429 or lockout.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/16-change-password-no-throttle.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
