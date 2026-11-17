# 14 · Last-admin guard can be raced to zero admins and wrongly blocks demoting a disabled admin

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Broken |
| **Area** | User management |
| **CWE** | CWE-367 TOCTOU / CWE-697 Incorrect comparison |
| **Status** | Fixed (branch `security-fixes`): disabled admins do not count as "last active admin"; role/disable changes serialised by a lock |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/UsersController.cs:93, 115, 168-174`

## What is wrong
(a) Two admins disabling each other at the same moment both pass the check -> no active admin (recovery needs SQL). (b) With one active admin S and a disabled admin D, demoting D fails with "last active administrator" because the guard does not ignore an already-disabled target.

## Evidence
```csharp
var admins = await userManager.GetUsersInRoleAsync(Roles.Admin);
return admins.Count(a => !a.IsDisabled) <= 1;
```

## How to reproduce
(b) Create admin D, disable D, then change D's role to Analyst -> error.

## Impact
Lock-out of administration (rare); cannot clean up roles (common).

## How to fix
1. In `IsLastActiveAdminAsync`: `if (user.IsDisabled) return false;` (or count active admins excluding the target).
2. Serialize admin-state changes (static SemaphoreSlim or serializable transaction) and re-check after the update.

## Tests to add (definition of done)
Disabled admin can be demoted while another admin is active; two concurrent disable calls leave >= 1 active admin.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/14-last-admin-guard-bugs.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
