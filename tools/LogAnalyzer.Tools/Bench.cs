using System.Diagnostics;
using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tools;

/// <summary>
/// CPU-only benchmark for RQ3: parse a file and run the default rules + Isolation Forest in memory.
/// Compare with the timings the web app stores per log file (which also include the SQL Server import).
/// </summary>
public static class Bench
{
    public static Task<int> RunAsync(Args a)
    {
        var path = a.Required("log");
        var repeat = Math.Max(1, a.Int("repeat", 1));
        var labelsPath = a.Optional("labels");
        var parser = new CombinedLogParser();

        var rules = DbSeeder.DefaultRules().ToList();
        for (var i = 0; i < rules.Count; i++)
            rules[i].Id = i + 1;
        var compiled = rules.Select(r => DetectionCore.TryCompile(r, out _)!).ToList();
        var anomalyRule = new DetectionRule { Id = 99, Name = "Isolation Forest", Kind = RuleKind.Anomaly, Threshold = 20, ScoreThreshold = 0.62 };

        Console.WriteLine($"File: {path} ({new FileInfo(path).Length / 1024.0 / 1024.0:0.0} MB), {Environment.ProcessorCount} logical CPUs, .NET {Environment.Version}");
        for (var run = 1; run <= repeat; run++)
        {
            var events = new List<DetectionEvent>();
            long lines = 0, failed = 0;

            var sw = Stopwatch.StartNew();
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                lines++;
                if (parser.TryParse(line, out var p) && p is not null)
                    events.Add(new DetectionEvent(lines, p.ClientIp, p.Timestamp, p.Method, p.Url, p.StatusCode, p.UserAgent, p.Referrer, p.ResponseSize));
                else
                    failed++;
            }
            var parseMs = sw.Elapsed.TotalMilliseconds;

            sw.Restart();
            events.Sort((x, y) => x.Timestamp.CompareTo(y.Timestamp));
            var core = new DetectionCore(compiled);
            var features = new IpFeatureAccumulator();
            foreach (var e in events)
            {
                core.Process(e);
                features.Add(e);
            }
            var rulesMs = sw.Elapsed.TotalMilliseconds;

            sw.Restart();
            var anomalies = new AnomalyDetector().Detect(anomalyRule, features);
            var mlMs = sw.Elapsed.TotalMilliseconds;

            var total = parseMs + rulesMs + mlMs;
            Console.WriteLine($"Run {run}: {lines:N0} lines ({failed:N0} unparsed), {features.Profiles.Count:N0} IPs");
            Console.WriteLine($"  parse        {parseMs,10:N0} ms  {lines / (parseMs / 1000):N0} lines/s");
            Console.WriteLine($"  rules        {rulesMs,10:N0} ms  {core.Hits.Count:N0} alerts");
            Console.WriteLine($"  isolation    {mlMs,10:N0} ms  {anomalies.Count:N0} anomalous IPs");
            Console.WriteLine($"  total        {total,10:N0} ms  {lines / (total / 1000):N0} lines/s");

            if (labelsPath is not null && run == 1)
                PrintAccuracy(labelsPath, core.Hits, anomalies, rules);
        }
        return Task.FromResult(0);
    }

    /// <summary>Per-line precision / recall like the web app's Evaluation page (event id = line number here).</summary>
    private static void PrintAccuracy(string labelsPath, IReadOnlyCollection<RuleHit> ruleHits,
        List<DetectionFinding> anomalies, List<DetectionRule> rules)
    {
        var labels = EvaluationService.ParseLabels(File.OpenRead(labelsPath));
        var byRules = ruleHits.SelectMany(h => h.EventIds).Select(id => (int)id).ToHashSet();
        var byMl = anomalies.SelectMany(f => f.Hit.EventIds).Select(id => (int)id).ToHashSet();

        Console.WriteLine();
        Console.WriteLine($"  {"detector",-28}{"TP",9}{"FP",9}{"FN",9}{"precision",11}{"recall",9}{"F1",8}{"FPR",8}");
        Row("rules only", byRules.Contains);
        Row("isolation forest only", byMl.Contains);
        Row("rules + isolation forest", n => byRules.Contains(n) || byMl.Contains(n));

        Console.WriteLine();
        Console.WriteLine("  recall per label (rules only):");
        foreach (var g in labels.Where(l => l.Value is not "normal" and not "malformed").GroupBy(l => l.Value).OrderBy(g => g.Key))
        {
            var hit = g.Count(l => byRules.Contains(l.Key));
            Console.WriteLine($"    {g.Key,-12}{hit,8:N0} / {g.Count(),-8:N0}{100.0 * hit / g.Count(),7:0.0}%");
        }

        void Row(string name, Func<int, bool> flagged)
        {
            int tp = 0, fp = 0, fn = 0, tn = 0;
            foreach (var (line, label) in labels)
            {
                if (label == "malformed") continue;
                var bad = label != "normal";
                var f = flagged(line);
                if (bad && f) tp++; else if (!bad && f) fp++; else if (bad) fn++; else tn++;
            }
            var m = new Metrics(name, tp, fp, fn, tn);
            Console.WriteLine($"  {name,-28}{tp,9:N0}{fp,9:N0}{fn,9:N0}{m.Precision,11:P1}{m.Recall,9:P1}{m.F1,8:P1}{m.FalsePositiveRate,8:P2}");
        }
    }
}
