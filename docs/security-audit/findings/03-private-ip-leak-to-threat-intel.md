# 03 · IsPublic treats IPv4-mapped and special-use addresses as public, so internal IPs are sent to AbuseIPDB, GreyNoise and VirusTotal

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Vulnerability (privacy) |
| **Area** | Threat intel / privacy |
| **CWE** | CWE-359 Exposure of private information / CWE-184 Incomplete list of disallowed inputs |
| **Status** | Fixed (branch `security-fixes`): `IpAddressPolicy` (mapped IPv6 → IPv4, special/documentation/CGNAT/6to4 ranges blocked, IPv6 only 2000::/3), canonical address sent; verified live |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/IpEnrichment.cs:146-166 (IsPublic)`
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs:99, 438, 479 (callers)`
- `src/LogAnalyzer.Web/Services/ThreatIntel.cs:190, 251, 316 (raw string put in the provider URL)`
- `src/LogAnalyzer.Web/Controllers/ThreatIntelController.cs:101`
- `src/LogAnalyzer.Web/Views/Shared/_ReputationCard.cshtml:84`

## What is wrong
The IPv6 branch only checks link-local, site-local, multicast and fc00::/7. IPv4-mapped IPv6 (`::ffff:10.0.0.5`, how dual-stack nginx/Node/Kestrel log IPv4 clients), `::`, CGNAT 100.64.0.0/10 and other special ranges are reported as public. This breaks the thesis' ethics claim *private IPs never leave the machine*.

## Evidence
Live: `/ThreatIntel/Lookup?ip=10.0.0.5` -> private (correct); `::ffff:10.0.0.5`, `100.64.1.1`, `::` -> treated as public ("Open on AbuseIPDB" shown). Probe also true for `::ffff:192.168.1.5`, `::127.0.0.1`, `192.0.0.1`, `198.18.0.1`, `192.0.2.1`, `2001:db8::1`, `64:ff9b::a00:1`, `2002:a00:1::1`.

## How to reproduce
Upload a log from a dual-stack server containing `::ffff:192.168.1.50` as attacker, configure an API key -> the worker sends the internal address to all three vendors. Or POST /ThreatIntel/Refresh with ip=::ffff:10.0.0.5.

## Impact
Internal addressing/topology and potentially personal data leaves the organisation to US third parties automatically; contradicts the documented privacy guarantee; wastes API quota.

## How to fix
1. Parse once and canonicalise: `if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();` and drop `ScopeId`.
2. IPv4: also block 100.64/10, 192.0.0/24, 192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24, 255.255.255.255 (keep existing 0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 224+/4).
3. IPv6: allow only 2000::/3 and within it block 2001:db8::/32, 2001::/23, 2002::/16 and 64:ff9b::/96 (or check the embedded IPv4), plus ::, ::1.
4. Add `TryGetPublic(string raw, out string canonical)` and send the canonical string to providers.

## Tests to add (definition of done)
Extend `IsPublicTests` with every address above (false) and `8.8.8.8`, `::ffff:8.8.8.8`, `2001:4860:4860::8888` (true). Provider test: request URI contains the canonical form.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/03-private-ip-leak-to-threat-intel.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
