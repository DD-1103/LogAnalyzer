# 22 · Floating NuGet versions and no lock file (non-reproducible builds)

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Dependencies |
| **CWE** | CWE-1104 Use of unmaintained/unpinned components |
| **Status** | Fixed (branch `security-fixes`): exact versions, `Directory.Build.props` with lock files (packages.lock.json committed), locked mode in CI; no vulnerable packages. MaxMind 6 / QuestPDF 2026 upgrades left for a separate, tested change |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/LogAnalyzer.Web.csproj:13-27 (10.0.*, 5.*, 2025.*)`

## What is wrong
Every restore can pull a different version; the thesis build is not reproducible and a broken/compromised release would be picked up silently. Outdated: MaxMind.GeoIP2 5.4.1 (6.1.0 available), QuestPDF 2025.12.4 (2026.9.2). Stay on 10.0.x (LTS) for Microsoft packages.

## Evidence
`Version="10.0.*"`, `Version="5.*"`, `Version="2025.*"`; no packages.lock.json.

## How to reproduce
n/a

## Impact
Unreproducible results; supply-chain risk.

## How to fix
Pin exact versions, set `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`, commit the lock files; run `dotnet list package --vulnerable` regularly. Check the QuestPDF Community licence terms if used at a government agency.

## Tests to add (definition of done)
`dotnet restore --locked-mode` succeeds.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/22-floating-package-versions.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
