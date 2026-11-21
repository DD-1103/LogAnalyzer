using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Services;

public sealed record Metrics(string Name, int TP, int FP, int FN, int TN)
{
    public double Precision => TP + FP == 0 ? 0 : (double)TP / (TP + FP);
    public double Recall => TP + FN == 0 ? 0 : (double)TP / (TP + FN);
    public double F1 => Precision + Recall == 0 ? 0 : 2 * Precision * Recall / (Precision + Recall);
    public double Accuracy => TP + FP + FN + TN == 0 ? 0 : (double)(TP + TN) / (TP + FP + FN + TN);
    public double FalsePositiveRate => FP + TN == 0 ? 0 : (double)FP / (FP + TN);
}

public sealed class EvaluationResult
{
    public required Metrics Overall { get; init; }
    public required List<Metrics> PerAttackType { get; init; }

    /// <summary>RQ2: rules only vs. anomaly detection only vs. both together.</summary>
    public required List<Metrics> Comparison { get; init; }
    public int LabelledLines { get; init; }
    public int IgnoredLines { get; init; }

    /// <summary>Lines labelled as an attack that the parser could not read (no event, so no rule could see them).</summary>
    public int UnparsedMalicious { get; init; }
    public int UnparsedNormal { get; init; }

    /// <summary>
    /// End-to-end view: unparsed attack lines count as missed (FN), unparsed normal lines as correctly ignored (TN).
    /// <see cref="Overall"/> only covers lines that became events.
    /// </summary>
    public required Metrics EndToEnd { get; init; }
}

/// <summary>
/// Compares detection results with a ground-truth labels file (CSV: line,label).
/// Label "normal" = benign; "malformed" lines are ignored (they are not events);
/// any other label = malicious. Evaluation is done per log line.
/// </summary>
public sealed class EvaluationService(AppDbContext db)
{
    // Label names used in the labels file -> attack type of the rule that should catch them.
    public static readonly Dictionary<string, AttackType> LabelMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sqli"] = AttackType.SqlInjection,
        ["xss"] = AttackType.Xss,
        ["traversal"] = AttackType.PathTraversal,
        ["bruteforce"] = AttackType.BruteForce,
        ["direnum"] = AttackType.DirectoryEnumeration,
        ["scanner"] = AttackType.Scanner,
        // Firewall logs (loganalyzer-tools generate-firewall)
        ["portscan"] = AttackType.PortScan,
        ["sweep"] = AttackType.NetworkSweep,
        ["intrusion"] = AttackType.Intrusion,
        ["flood"] = AttackType.BlockedTraffic,
        ["c2"] = AttackType.SuspiciousOutbound,
        ["authfail"] = AttackType.AuthenticationFailure
    };

    /// <summary>Longer labels are ignored (real labels are short words like "sqli").</summary>
    public const int MaxLabelLength = 64;

    /// <summary>
    /// Reads "line,label" rows. Labels longer than <see cref="MaxLabelLength"/>, line numbers outside 1..maxLine and
    /// anything after <paramref name="maxLine"/> labels are ignored, so a crafted file cannot use much memory.
    /// </summary>
    public static Dictionary<int, string> ParseLabels(Stream csv, int maxLine = int.MaxValue)
    {
        var labels = new Dictionary<int, string>();
        using var reader = new BoundedLineReader(new StreamReader(csv), 256);
        while (reader.ReadLineAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult() is { } read)
        {
            if (read.TooLong)
                continue;
            var parts = read.Text.Split(',', 2);
            if (parts.Length != 2 || !int.TryParse(parts[0].Trim(), out var n) || n < 1 || n > maxLine)
                continue;
            var label = parts[1].Trim().Trim('"');
            if (label.Length is 0 or > MaxLabelLength)
                continue;
            labels[n] = label;
            if (labels.Count >= maxLine)
                break;
        }
        return labels;
    }

    public async Task<EvaluationResult> EvaluateAsync(int logFileId, Dictionary<int, string> labels, CancellationToken ct)
    {
        // Line number -> attack types of the alerts that flagged it, split by detector family
        var evidence = await db.AlertEvidence.AsNoTracking()
            .Where(e => e.Alert!.LogFileId == logFileId)
            .Select(e => new { e.LogEvent!.LineNumber, e.Alert!.AttackType, IsAnomaly = e.Alert.Rule!.Kind == RuleKind.Anomaly })
            .ToListAsync(ct);
        var flagged = evidence
            .GroupBy(x => x.LineNumber)
            .ToDictionary(g => g.Key, g => g.Select(x => x.AttackType).ToHashSet());
        var byRules = evidence.Where(x => !x.IsAnomaly).Select(x => x.LineNumber).ToHashSet();
        var byAnomaly = evidence.Where(x => x.IsAnomaly).Select(x => x.LineNumber).ToHashSet();
        var eventLines = (await db.LogEvents.AsNoTracking()
                .Where(e => e.LogFileId == logFileId)
                .Select(e => e.LineNumber)
                .ToListAsync(ct))
            .ToHashSet();

        return Compute(labels, eventLines, flagged, byRules, byAnomaly);
    }

    /// <summary>The metric computation itself (pure, unit-tested).</summary>
    public static EvaluationResult Compute(Dictionary<int, string> labels, HashSet<int> eventLines,
        Dictionary<int, HashSet<AttackType>> flagged, HashSet<int> byRules, HashSet<int> byAnomaly)
    {
        var comparison = new[] { new int[4], new int[4], new int[4] }; // rules, anomaly, both
        int tp = 0, fp = 0, fn = 0, tn = 0, ignored = 0, unparsedMalicious = 0, unparsedNormal = 0;
        var perType = LabelMap.Values.Distinct().ToDictionary(t => t, _ => new int[4]); // TP, FP, FN, TN

        foreach (var (lineNo, label) in labels)
        {
            if (label.Equals("malformed", StringComparison.OrdinalIgnoreCase))
            {
                ignored++;
                continue;
            }
            var isMalicious = !label.Equals("normal", StringComparison.OrdinalIgnoreCase);
            if (!eventLines.Contains(lineNo))
            {
                // Not an event (parse failure or line outside the file): invisible to every detector.
                ignored++;
                if (isMalicious) unparsedMalicious++;
                else unparsedNormal++;
                continue;
            }

            var types = flagged.GetValueOrDefault(lineNo);
            var isFlagged = types is { Count: > 0 };

            if (isMalicious && isFlagged) tp++;
            else if (!isMalicious && isFlagged) fp++;
            else if (isMalicious) fn++;
            else tn++;

            Count(comparison[0], isMalicious, byRules.Contains(lineNo));
            Count(comparison[1], isMalicious, byAnomaly.Contains(lineNo));
            Count(comparison[2], isMalicious, byRules.Contains(lineNo) || byAnomaly.Contains(lineNo));

            LabelMap.TryGetValue(label, out var trueType);
            foreach (var (type, c) in perType)
            {
                var actual = isMalicious && LabelMap.ContainsKey(label) && trueType == type;
                var predicted = types?.Contains(type) == true;
                if (actual && predicted) c[0]++;
                else if (!actual && predicted) c[1]++;
                else if (actual) c[2]++;
                else c[3]++;
            }
        }

        return new EvaluationResult
        {
            Overall = new Metrics("All attacks", tp, fp, fn, tn),
            PerAttackType = perType
                .Select(p => new Metrics(p.Key.ToString(), p.Value[0], p.Value[1], p.Value[2], p.Value[3]))
                .ToList(),
            Comparison =
            [
                new Metrics("Rules only (signature + threshold)", comparison[0][0], comparison[0][1], comparison[0][2], comparison[0][3]),
                new Metrics("Anomaly detection only (Isolation Forest)", comparison[1][0], comparison[1][1], comparison[1][2], comparison[1][3]),
                new Metrics("Rules + anomaly detection", comparison[2][0], comparison[2][1], comparison[2][2], comparison[2][3])
            ],
            LabelledLines = labels.Count - ignored,
            IgnoredLines = ignored,
            UnparsedMalicious = unparsedMalicious,
            UnparsedNormal = unparsedNormal,
            EndToEnd = new Metrics("End to end (unparsed attacks count as missed)", tp, fp, fn + unparsedMalicious, tn + unparsedNormal)
        };
    }

    // c = TP, FP, FN, TN
    private static void Count(int[] c, bool actual, bool predicted)
    {
        if (actual && predicted) c[0]++;
        else if (!actual && predicted) c[1]++;
        else if (actual) c[2]++;
        else c[3]++;
    }
}
