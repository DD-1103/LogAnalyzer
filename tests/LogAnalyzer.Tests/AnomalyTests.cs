using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tests;

public class IsolationForestTests
{
    private static List<double[]> Cluster(int n, int seed)
    {
        var rng = new Random(seed);
        return Enumerable.Range(0, n).Select(_ => new[] { rng.NextDouble(), rng.NextDouble(), rng.NextDouble() }).ToList();
    }

    [Fact]
    public void Outlier_scores_higher_than_normal_points()
    {
        var data = Cluster(300, 1);
        var outlier = new[] { 8.0, 9.0, 7.5 };
        data.Add(outlier);

        var forest = IsolationForest.Fit(data, trees: 100, sampleSize: 256, seed: 42);
        var normalScores = data.Take(300).Select(forest.Score).ToList();

        Assert.True(forest.Score(outlier) > 0.65, $"outlier score {forest.Score(outlier)}");
        Assert.True(forest.Score(outlier) > normalScores.Max());
        Assert.InRange(normalScores.Average(), 0.35, 0.55);
    }

    [Fact]
    public void Same_seed_gives_same_scores()
    {
        var data = Cluster(200, 2);
        var a = IsolationForest.Fit(data, seed: 7);
        var b = IsolationForest.Fit(data, seed: 7);
        Assert.All(data, x => Assert.Equal(a.Score(x), b.Score(x)));
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    [InlineData(256, 10.244770920116851)]
    public void Average_path_length_matches_the_paper(int n, double expected) =>
        Assert.Equal(expected, IsolationForest.AveragePathLength(n), 6);
}

public class AnomalyDetectorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Flags_an_aggressive_scanner_among_normal_users()
    {
        var acc = new IpFeatureAccumulator();
        var rng = new Random(3);
        long id = 0;

        // 40 normal users: ~30 page views over an hour, rare 404s, normal URLs.
        for (var u = 0; u < 40; u++)
            for (var i = 0; i < 30; i++)
                acc.Add(new DetectionEvent(++id, $"20.0.0.{u}", T0.AddSeconds(i * 120 + rng.Next(60)), "GET",
                    $"/products/{rng.Next(1, 300)}", rng.NextDouble() < 0.02 ? 404 : 200, "Mozilla/5.0", null));

        // One scanner: 500 requests in 2 minutes, mostly 404, unique paths, odd characters.
        for (var i = 0; i < 500; i++)
            acc.Add(new DetectionEvent(++id, "66.66.66.66", T0.AddMilliseconds(i * 240), "GET",
                $"/admin{i}.php?x='<{i}>", i % 20 == 0 ? 200 : 404, null, null));

        var rule = new DetectionRule { Id = 1, Kind = RuleKind.Anomaly, Threshold = 20, ScoreThreshold = 0.62 };
        var findings = new AnomalyDetector().Detect(rule, acc);

        var scanner = Assert.Single(findings, f => f.Hit.Ip == "66.66.66.66");
        Assert.Equal(500, scanner.Hit.EventIds.Count);
        Assert.False(string.IsNullOrWhiteSpace(scanner.Explanation));
        Assert.True(findings.Count <= 3, $"too many normal users flagged: {findings.Count}");
    }

    [Fact]
    public void Needs_enough_clients_to_learn_normal_behaviour()
    {
        var acc = new IpFeatureAccumulator();
        for (var i = 0; i < 100; i++)
            acc.Add(new DetectionEvent(i, $"1.1.1.{i % 3}", T0.AddSeconds(i), "GET", "/", 200, "x", null));
        var rule = new DetectionRule { Id = 1, Kind = RuleKind.Anomaly, Threshold = 10, ScoreThreshold = 0.5 };
        Assert.Empty(new AnomalyDetector().Detect(rule, acc));
    }
}
