# 20 · Evaluate loads a 100 MB labels file and all line numbers into memory inside the request

| | |
|---|---|
| **Severity** | Low |
| **Kind** | Hardening |
| **Area** | Evaluation |
| **CWE** | CWE-770 |
| **Status** | Fixed (branch `security-fixes`): labels max 64 chars, line numbers 1..TotalLines, 256-char line reader, upload limit 20 MB |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Controllers/LogFilesController.cs:163-190 (100 MB limit, any user)`
- `src/LogAnalyzer.Web/Services/EvaluationService.cs (ParseLabels, EvaluateAsync)`

## What is wrong
Labels are unbounded strings; all evidence and event line numbers are materialised per request; several parallel requests multiply the memory.

## Evidence
`labels[n] = parts[1].Trim().Trim('"');` then `.Select(e => e.LineNumber).ToListAsync(ct)).ToHashSet()`.

## How to reproduce
Upload a 100 MB labels CSV with one huge label; repeat in parallel on a 1M-event file.

## Impact
Memory spikes / slow app for everyone.

## How to fix
Cap label length (64) and count (<= TotalLines); lower the limit to ~20 MB; optionally compute the confusion matrix in SQL.

## Tests to add (definition of done)
ParseLabels ignores labels > 64 chars and stops at the maximum count.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/20-evaluate-memory.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
