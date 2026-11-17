# 05 · Uploads are unbounded after decompression: gzip bombs, endless lines and >2^31 lines

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Vulnerability (resource exhaustion) |
| **Area** | Upload / ingestion |
| **CWE** | CWE-409 Highly compressed data / CWE-770 Allocation without limits / CWE-190 Integer overflow |
| **Status** | Confirmed (code + measured compression ratio) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/LogFilesController.cs:37-41 (any signed-in user, 500 MB compressed)`
- `src/LogAnalyzer.Web/Services/LogProcessing.cs:117-172 (GZipStream without limit, ReadLineAsync without max length, int counters)`

## What is wrong
The 500 MB limit applies to the compressed upload. Decompressed size, number of lines, line length and event count are not limited. `ReadLineAsync` builds a whole line before it is cut to 8000 chars. Counters are `int`.

## Evidence
Measured: 1 GiB of repeated sqlmap lines gzips to 3.5 MB (295:1) = 10.1M events from a 3.5 MB upload; 500 MB would be ~1.4 billion rows. A 500 MB file without newline = one ~1 GB string (out-of-memory risk). `int total, parsed, failed, lineNumber` wrap above 2^31 lines.

## How to reproduce
Create `bomb.log.gz` (gzip -9 of a few GB of one repeated log line) and upload it as an Analyst.

## Impact
Fills the SQL Server data and log disks, blocks the worker for hours, can crash the process; corrupt line numbers.

## How to fix
1. Wrap the decompression stream in a counting stream that throws after a configurable limit (e.g. 2 GB or 20x the compressed size).
2. Add `MaxLines`/`MaxEvents` (e.g. 5M) -> mark the file Failed with a clear message.
3. Read lines with a bounded reader (e.g. 16 KB); discard the rest of an over-long line and count it as failed.
4. (Optional) per-user quota / one file in progress per user.

## Tests to add (definition of done)
- Counting stream throws at the limit.
- Worker: gz expanding beyond the cap -> Status Failed, row count <= cap.
- Stream with a 10 MB line followed by a valid line -> failed=1, parsed=1, bounded memory.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/05-upload-expansion-and-unbounded-input.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
