# 28 · No switch for automatic third-party lookups and no data retention limit

| | |
|---|---|
| **Severity** | Info |
| **Kind** | Hardening (privacy) |
| **Area** | Threat intel / privacy |
| **CWE** | CWE-359 |
| **Status** | Fixed (branch `security-fixes`): `Enrichment:AutoLookup` (default off), `DataRetentionWorker` deletes answers after 90 days and orphaned rows; verified live |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs (RunForLogFileAsync, EnrichAsync)`
- `IpReputations / IpInfos tables (never purged)`

## What is wrong
When keys are set, attacker IPs of every file are sent automatically; reputation and GeoIP rows are kept forever, even after the log file is deleted.

## Evidence
-

## How to reproduce
-

## Impact
GDPR / ethics-chapter question.

## How to fix
`Enrichment:AutoLookup` flag (default off or ask per upload); purge job for rows older than 90 days or orphaned; describe in the thesis which data goes to which vendor.

## Tests to add (definition of done)
AutoLookup=false -> no provider called by the worker.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/28-privacy-retention-and-auto-sharing.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
