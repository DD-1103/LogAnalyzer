# 26 · CDN scripts without Subresource Integrity; signed-in pages may be cached

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Frontend / headers |
| **CWE** | CWE-829 Inclusion of functionality from untrusted control sphere / CWE-525 |
| **Status** | Fixed (branch `security-fixes`): libraries self-hosted in wwwroot/lib, CSP self only, no-store for signed-in pages |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Views/Shared/_Layout.cshtml (Bootstrap, Bootstrap Icons from cdn.jsdelivr.net)`
- `src/LogAnalyzer.Web/Views/Home/Index.cshtml (Leaflet, Chart.js)`
- `src/LogAnalyzer.Web/Services/SecurityHeaders.cs`

## What is wrong
Third-party scripts/styles have no `integrity`/`crossorigin` attributes and the CSP trusts the whole jsDelivr host. Authenticated HTML has no `Cache-Control: no-store`, so alert/evidence pages can stay in the browser cache.

## Evidence
`<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>`

## How to reproduce
n/a (supply-chain / shared-computer scenario)

## Impact
A compromised CDN file runs on every page; cached sensitive pages on shared machines.

## How to fix
Self-host the four libraries in `wwwroot/lib` (also makes the demo work offline!) and remove jsDelivr from the CSP - or add SRI hashes + `crossorigin="anonymous"`. Add `Cache-Control: no-store` for authenticated responses in SecurityHeadersMiddleware.

## Tests to add (definition of done)
Header test: authenticated response has no-store; layout contains no external script without integrity.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/26-browser-hardening.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
