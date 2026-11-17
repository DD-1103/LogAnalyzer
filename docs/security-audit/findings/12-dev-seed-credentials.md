# 12 · Known seed passwords are committed; a fresh Production install gets no admin

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Configuration / authentication |
| **CWE** | CWE-798 Hard-coded credentials / CWE-1188 Insecure default |
| **Status** | Fixed (branch `security-fixes`): no passwords in files, MustChangePassword for seeded/admin-set passwords, analyst seeded only in Development |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/appsettings.Development.json:2-9`
- `src/LogAnalyzer.Web/Data/DbSeeder.cs:43-71`
- `CLAUDE.md section 2 (repeats the admin password)`
- `src/LogAnalyzer.Web/LogAnalyzer.Web.csproj (appsettings.Development.json is published)`

## What is wrong
`admin@loganalyzer.local` / `Admin#…` (redacted) and the analyst password are in git and documented. Any DB first created in Development keeps these accounts; nothing forces a password change. In Production no SeedAdmin exists, so a new database has no admin at all.

## Evidence
`"SeedAdmin": { "Email": "admin@loganalyzer.local", "Password": "…" }`

## How to reproduce
Log in with the documented credentials on any instance whose DB was seeded in Development (e.g. a demo laptop reachable on the LAN).

## Impact
Full admin access if the dev DB or a Development instance is exposed or the repo becomes public.

## How to fix
1. Move seed passwords to user-secrets (`dotnet user-secrets set "SeedAdmin:Password" ...`); remove them from appsettings.Development.json and CLAUDE.md.
2. `<Content Update="appsettings.Development.json" CopyToPublishDirectory="Never" />`.
3. Add `MustChangePassword` for seeded/reset accounts + a filter that redirects to Change password.
4. Document `SeedAdmin__Email`/`SeedAdmin__Password` env vars for the first Production admin; seed the analyst only in Development.
5. Change the demo password before the jury presentation.

## Tests to add (definition of done)
Startup test in Production with no SeedAdmin logs a clear warning; seeded user is redirected to Change password.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/12-dev-seed-credentials.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
