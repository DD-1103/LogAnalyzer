# 10 · PDF report runs one query per alert; a log with many fake IPs creates unlimited alerts

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Will break |
| **Area** | Reports / detection |
| **CWE** | CWE-770 / CWE-400 |
| **Status** | Fixed (branch `security-fixes`): one CROSS APPLY query for samples, PDF lists top 200 alerts, max 1,000 alerts per rule (rest merged, evidence kept), streamed CSV. IP field not validated on purpose (hostnames in logs) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/ReportService.cs:25-53 (all alerts + N+1 evidence query)`
- `src/LogAnalyzer.Web/Services/LogParser.cs:30 (`(?<ip>\S+)`, any token accepted as IP)`
- `src/LogAnalyzer.Web/Controllers/AlertsController.cs:114-156 (CSV built in memory)`

## What is wrong
One alert per (rule, IP string) and the IP field is not validated, so a crafted (or X-Forwarded-For based) log with 200k distinct "IPs" yields 200k alerts. The PDF then runs 200k sequential queries and renders all of them in one request; the CSV is built entirely in memory.

## Evidence
```csharp
foreach (var alert in alerts)
    samples[alert.Id] = await db.AlertEvidence...Take(3).ToListAsync(ct);
```

## How to reproduce
Upload 200k lines like `10.0.<i>.<j> - - [...] "GET /?q=' or 1=1-- HTTP/1.1" 200 1`, then download the PDF report.

## Impact
Request timeouts / huge memory use; unusable report for real internet-facing logs.

## How to fix
1. Fetch the 3 samples per alert in one query (ROW_NUMBER partitioned by AlertId, or EF 10 GroupBy+Take).
2. Render at most the top 200 alerts in detail + "N more alerts not shown".
3. Validate the IP with `IPAddress.TryParse` (store invalid ones flagged or grouped) and cap alerts per rule per file.
4. Stream the CSV to the response.

## Tests to add (definition of done)
ReportService with 1,000 alerts issues <= 3 queries (EF command interceptor) and produces a PDF.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/10-report-and-alert-fanout.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
