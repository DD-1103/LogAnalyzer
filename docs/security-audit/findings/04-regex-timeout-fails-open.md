# 04 · A rule regex that times out counts as "no match" - attackers can hide payloads; weak rules can stall the worker

| | |
|---|---|
| **Severity** | Medium |
| **Kind** | Vulnerability (detection evasion) |
| **Area** | Detection engine |
| **CWE** | CWE-1333 Inefficient regular expression / CWE-636 Not failing securely |
| **Status** | Confirmed (experiment); the 6 default rules are NOT affected (worst 0.25 ms/event) |
| **Found** | 2026-11-17 audit, branch `ui-liquid-glass` |

## Where
- `src/LogAnalyzer.Web/Services/DetectionCore.cs:61 (250 ms timeout), 144-154 (SafeMatch)`
- `src/LogAnalyzer.Web/Services/RuleManagement.cs:15-23 (ReDoS probes), 47-73 (CheckBacktracking)`

## What is wrong
`SafeMatch` returns false on `RegexMatchTimeoutException`, silently. The validator's probe inputs miss common exponential patterns, e.g. `(?i)<(\w+\s*)+on\w+\s*=` passes validation. An attacker who puts a backtracking-trigger prefix before the real payload makes that rule time out -> no alert. Each such event also costs 250 ms per weak rule.

## Evidence
Rule `(?i)<(\w+\s*)+on\w+\s*=` is accepted. URL `/search?x=<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!&q=<svg onload=alert(1)>` -> timeout after 248 ms -> not detected, while `/search?q=<svg onload=alert(1)>` is detected.

## How to reproduce
1. As admin create the signature rule above.
2. Upload a log line with the prefixed payload.
3. No alert for it; the plain payload alerts.

## Impact
Silent false negatives (undermines RQ1 results); 1M crafted lines x 250 ms = hours of a blocked worker.

## How to fix
1. Make `SafeMatch` tri-state; count timeouts per rule; never treat a timeout as a silent miss - flag the event/file ("rule X timed out on N events") or create a low-severity alert.
2. Compile admin rules with `RegexOptions.NonBacktracking` (linear time; .NET 7+). It does not support backreferences/lookarounds - have the validator say so and fall back only when needed.
3. Circuit breaker: after ~50 timeouts skip the rule for the rest of the file and log a warning.
4. Add probes: `"<" + new string('a', 40) + "!"`, `string.Concat(Enumerable.Repeat("a ", 5000)) + "!"`, `new string('<', 30000)`.

## Tests to add (definition of done)
- Validator rejects (or compiles NonBacktracking) `(?i)<(\w+\s*)+on\w+\s*=`.
- DetectionCore: evasive prefix + payload is either matched or flagged as timed out, never silently missed.
- `dotnet build` with 0 warnings and `dotnet test` green.
- Re-check in the browser (both themes) where the change is visible.

## Ask Claude to fix it
Paste this in Claude Code (from the repo root):

```
Fix docs/security-audit/findings/04-regex-timeout-fails-open.md: implement the fix and the tests described there, keep the project conventions in CLAUDE.md, build, run the tests, verify in the browser if visible, then update the Status line of this file to "Fixed (<commit>)" and commit on a new branch.
```
