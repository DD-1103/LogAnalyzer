# 24 · Threat-intel lookup canonicalises the IP but events and alerts store the raw text

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Broken |
| **Area** | Parsing / threat intel |
| **CWE** | - |
| **Status** | Fixed (branch `security-fixes`): parser and lookup page store/use `IpAddressPolicy.Canonical` (lower-case compressed IPv6, mapped IPv4 as IPv4) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/ThreatIntelController.cs:100-105, 199-211`
- `src/LogAnalyzer.Web/Services/LogParser.cs (ClientIp stored raw)`

## What is wrong
`2001:DB8:0:0::1` in a log is stored as written; the lookup page converts it to `2001:db8::1`, then finds 0 alerts/events and creates a second cache row.

## Evidence
`address = parsed.ToString();` then `a.SourceIp == address`.

## How to reproduce
Upload a log with an upper-case/expanded IPv6 address and open its IP lookup from the alert.

## Impact
Wrong counts; duplicate lookups waste quota.

## How to fix
Canonicalise `ClientIp` in the parser when `IPAddress.TryParse` succeeds (keep the raw value otherwise). Combine with private-ip-leak-to-threat-intel.

## Tests to add (definition of done)
Parser stores the canonical IPv6 form.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/24-ip-normalisation-mismatch.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
