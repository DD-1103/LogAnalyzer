using System.Globalization;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Isolation Forest (Liu, Ting &amp; Zhou, 2008). Anomalies are "few and different", so random axis-parallel
/// splits isolate them in fewer steps than normal points. Score s(x) = 2^(-E[h(x)] / c(psi)):
/// close to 1 = anomaly, around 0.5 or below = normal. Implemented here (no external ML service)
/// with a fixed random seed so evaluation results are reproducible.
/// </summary>
public sealed class IsolationForest
{
    private const double EulerGamma = 0.5772156649015329;

    private sealed class Node
    {
        public int Feature = -1;
        public double Split;
        public Node? Left;
        public Node? Right;
        public int Size;          // number of training points that ended in this leaf
        public bool IsLeaf => Left is null;
    }

    private readonly List<Node> _trees;
    private readonly int _sampleSize;

    private IsolationForest(List<Node> trees, int sampleSize)
    {
        _trees = trees;
        _sampleSize = sampleSize;
    }

    public int TreeCount => _trees.Count;

    public static IsolationForest Fit(IReadOnlyList<double[]> data, int trees = 100, int sampleSize = 256, int seed = 42)
    {
        if (data.Count == 0)
            throw new ArgumentException("No training data.", nameof(data));

        var rng = new Random(seed);
        var psi = Math.Min(sampleSize, data.Count);
        var heightLimit = (int)Math.Ceiling(Math.Log2(Math.Max(psi, 2)));
        var list = new List<Node>(trees);

        for (var t = 0; t < trees; t++)
        {
            // Sub-sample without replacement (partial Fisher-Yates).
            var idx = Enumerable.Range(0, data.Count).ToArray();
            for (var i = 0; i < psi; i++)
            {
                var j = rng.Next(i, idx.Length);
                (idx[i], idx[j]) = (idx[j], idx[i]);
            }
            var sample = new double[psi][];
            for (var i = 0; i < psi; i++)
                sample[i] = data[idx[i]];

            list.Add(Build(sample, 0, heightLimit, rng));
        }
        return new IsolationForest(list, psi);
    }

    private static Node Build(double[][] points, int depth, int heightLimit, Random rng)
    {
        if (depth >= heightLimit || points.Length <= 1)
            return new Node { Size = points.Length };

        // Only split on features that still vary inside this node.
        var dims = points[0].Length;
        var candidates = new List<(int Feature, double Min, double Max)>();
        for (var f = 0; f < dims; f++)
        {
            double min = double.MaxValue, max = double.MinValue;
            foreach (var p in points)
            {
                if (p[f] < min) min = p[f];
                if (p[f] > max) max = p[f];
            }
            if (max > min)
                candidates.Add((f, min, max));
        }
        if (candidates.Count == 0)
            return new Node { Size = points.Length };

        var (feature, lo, hi) = candidates[rng.Next(candidates.Count)];
        var split = lo + rng.NextDouble() * (hi - lo);
        var left = points.Where(p => p[feature] < split).ToArray();
        var right = points.Where(p => p[feature] >= split).ToArray();

        return new Node
        {
            Feature = feature,
            Split = split,
            Left = Build(left, depth + 1, heightLimit, rng),
            Right = Build(right, depth + 1, heightLimit, rng)
        };
    }

    /// <summary>Anomaly score in (0, 1].</summary>
    public double Score(double[] x)
    {
        var total = 0.0;
        foreach (var tree in _trees)
            total += PathLength(tree, x, 0);
        var mean = total / _trees.Count;
        var c = AveragePathLength(_sampleSize);
        return c <= 0 ? 0.5 : Math.Pow(2, -mean / c);
    }

    private static double PathLength(Node node, double[] x, int depth)
    {
        while (!node.IsLeaf)
        {
            node = x[node.Feature] < node.Split ? node.Left! : node.Right!;
            depth++;
        }
        return depth + AveragePathLength(node.Size);
    }

    /// <summary>c(n): average path length of an unsuccessful search in a binary search tree of n points.</summary>
    public static double AveragePathLength(int n) => n switch
    {
        <= 1 => 0,
        2 => 1,
        _ => 2 * (Math.Log(n - 1) + EulerGamma) - 2.0 * (n - 1) / n
    };
}

/// <summary>Behaviour of one client IP within a log file, collected while detection streams the events.</summary>
public sealed class IpProfile(string ip)
{
    private const int MaxTrackedPaths = 5_000;
    private const int MaxTrackedAgents = 100;

    public string Ip { get; } = ip;
    public int Count { get; private set; }
    public DateTimeOffset First { get; private set; } = DateTimeOffset.MaxValue;
    public DateTimeOffset Last { get; private set; } = DateTimeOffset.MinValue;
    public int ClientErrors { get; private set; }
    public int ServerErrors { get; private set; }
    public int Posts { get; private set; }
    public int WithQuery { get; private set; }
    public int SpecialChars { get; private set; }
    public int MissingAgent { get; private set; }
    public long UrlLengthSum { get; private set; }
    public HashSet<string> Paths { get; } = [];
    public HashSet<string> Agents { get; } = [];
    public List<long> EventIds { get; } = [];

    // Characters that are rare in normal URLs but common in injection payloads.
    private static readonly char[] Suspicious = ['\'', '"', '<', '>', ';', '(', ')', '{', '}', '|', '`', '\\'];

    public void Add(DetectionEvent e)
    {
        Count++;
        EventIds.Add(e.Id);
        if (e.Timestamp < First) First = e.Timestamp;
        if (e.Timestamp > Last) Last = e.Timestamp;
        if (e.StatusCode is >= 400 and < 500) ClientErrors++;
        if (e.StatusCode >= 500) ServerErrors++;
        if (string.Equals(e.Method, "POST", StringComparison.OrdinalIgnoreCase)) Posts++;

        var decoded = UrlDecoder.Decode(e.Url);
        UrlLengthSum += e.Url.Length;
        var q = e.Url.IndexOf('?');
        if (q >= 0) WithQuery++;
        if (decoded.IndexOfAny(Suspicious) >= 0 || decoded.Contains("..", StringComparison.Ordinal)) SpecialChars++;

        if (Paths.Count < MaxTrackedPaths)
            Paths.Add(q >= 0 ? e.Url[..q] : e.Url);
        if (string.IsNullOrEmpty(e.UserAgent)) MissingAgent++;
        else if (Agents.Count < MaxTrackedAgents) Agents.Add(e.UserAgent);
    }

    public double Minutes => Math.Max(1.0, (Last - First).TotalMinutes);
}

/// <summary>Builds the per-IP feature vectors used by the Isolation Forest.</summary>
public sealed class IpFeatureAccumulator
{
    private readonly Dictionary<string, IpProfile> _profiles = [];

    public static readonly string[] FeatureNames =
    [
        "requests (log)",
        "requests per minute (log)",
        "4xx error ratio",
        "5xx error ratio",
        "unique path ratio",
        "average URL length (log)",
        "POST ratio",
        "suspicious-character ratio",
        "missing user-agent ratio",
        "distinct user agents (log)",
        "query-string ratio"
    ];

    public IReadOnlyCollection<IpProfile> Profiles => _profiles.Values;

    public void Add(DetectionEvent e)
    {
        if (!_profiles.TryGetValue(e.ClientIp, out var p))
            _profiles[e.ClientIp] = p = new IpProfile(e.ClientIp);
        p.Add(e);
    }

    public static double[] Features(IpProfile p)
    {
        double n = p.Count;
        return
        [
            Math.Log(1 + n),
            Math.Log(1 + n / p.Minutes),
            p.ClientErrors / n,
            p.ServerErrors / n,
            p.Paths.Count / n,
            Math.Log(1 + p.UrlLengthSum / n),
            p.Posts / n,
            p.SpecialChars / n,
            p.MissingAgent / n,
            Math.Log(1 + p.Agents.Count),
            p.WithQuery / n
        ];
    }

    /// <summary>Human-readable values for the explanation (not log-scaled).</summary>
    public static double[] RawValues(IpProfile p)
    {
        double n = p.Count;
        return
        [
            n,
            n / p.Minutes,
            p.ClientErrors / n,
            p.ServerErrors / n,
            p.Paths.Count / n,
            p.UrlLengthSum / n,
            p.Posts / n,
            p.SpecialChars / n,
            p.MissingAgent / n,
            p.Agents.Count,
            p.WithQuery / n
        ];
    }
}

/// <summary>A rule hit plus, for anomaly rules, the Isolation Forest score (NaN for signature/threshold rules) and explanation.</summary>
public sealed record DetectionFinding(RuleHit Hit, double Score, string Explanation);

/// <summary>Applies an Anomaly rule: trains an Isolation Forest on the IPs of one log file and flags outliers.</summary>
public sealed class AnomalyDetector
{
    public const int Seed = 42;
    public const int Trees = 100;
    public const int MinimumIps = 8;   // fewer clients than this: no meaningful "normal" to learn

    public List<DetectionFinding> Detect(DetectionRule rule, IpFeatureAccumulator features)
    {
        var minRequests = Math.Max(1, rule.Threshold ?? 20);
        var threshold = rule.ScoreThreshold ?? 0.62;
        var profiles = features.Profiles.Where(p => p.Count >= minRequests).ToList();
        if (profiles.Count < MinimumIps)
            return [];

        var vectors = profiles.Select(IpFeatureAccumulator.Features).ToList();
        var forest = IsolationForest.Fit(vectors, Trees, 256, Seed);
        var raw = profiles.Select(IpFeatureAccumulator.RawValues).ToList();
        var medians = Enumerable.Range(0, IpFeatureAccumulator.FeatureNames.Length)
            .Select(f => Median(vectors.Select(v => v[f])))
            .ToArray();
        var rawMedians = Enumerable.Range(0, IpFeatureAccumulator.FeatureNames.Length)
            .Select(f => Median(raw.Select(v => v[f])))
            .ToArray();
        var spread = Enumerable.Range(0, IpFeatureAccumulator.FeatureNames.Length)
            .Select(f => Mad(vectors.Select(v => v[f]), medians[f]))
            .ToArray();

        var findings = new List<DetectionFinding>();
        for (var i = 0; i < profiles.Count; i++)
        {
            var score = forest.Score(vectors[i]);
            if (score < threshold)
                continue;

            var p = profiles[i];
            var hit = new RuleHit(rule.Id, p.Ip);
            hit.AddMany(p.EventIds, p.First, p.Last);
            findings.Add(new DetectionFinding(hit, score, Explain(vectors[i], raw[i], medians, rawMedians, spread)));
        }
        return findings;
    }

    // The three features furthest from the population median (robust z-score) explain the alert.
    private static string Explain(double[] v, double[] raw, double[] medians, double[] rawMedians, double[] spread)
    {
        var top = Enumerable.Range(0, v.Length)
            .Select(f => (Feature: f, Z: Math.Abs(v[f] - medians[f]) / (spread[f] > 1e-9 ? spread[f] : 1e-3)))
            .Where(x => x.Z > 1)
            .OrderByDescending(x => x.Z)
            .Take(3)
            .Select(x =>
            {
                var name = IpFeatureAccumulator.FeatureNames[x.Feature].Replace(" (log)", "");
                return $"{name} {Fmt(raw[x.Feature])} (typical {Fmt(rawMedians[x.Feature])})";
            });
        var text = string.Join("; ", top);
        return string.IsNullOrEmpty(text) ? "Unusual combination of behaviour features" : text;
    }

    private static string Fmt(double d) =>
        d >= 100 ? d.ToString("N0", CultureInfo.InvariantCulture)
        : d >= 10 ? d.ToString("0.#", CultureInfo.InvariantCulture)
        : d.ToString("0.##", CultureInfo.InvariantCulture);

    private static double Median(IEnumerable<double> values)
    {
        var a = values.OrderBy(x => x).ToArray();
        if (a.Length == 0) return 0;
        return a.Length % 2 == 1 ? a[a.Length / 2] : (a[a.Length / 2 - 1] + a[a.Length / 2]) / 2;
    }

    // Median absolute deviation, scaled to be comparable with a standard deviation.
    private static double Mad(IEnumerable<double> values, double median) =>
        1.4826 * Median(values.Select(x => Math.Abs(x - median)));
}
