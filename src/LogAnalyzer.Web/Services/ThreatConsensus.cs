using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>LogAnalyzer's own verdict on an indicator, combined from every provider that answered.</summary>
public enum ConsensusVerdict
{
    /// <summary>No provider has answered (none configured, all failed, or not looked up yet).</summary>
    NoData,
    /// <summary>Providers answered, but none flags it and none vouches for it.</summary>
    NoThreatFound,
    /// <summary>At least one provider knows it as legitimate (e.g. a search-engine crawler) and none flags it.</summary>
    Benign,
    Suspicious,
    Malicious
}

public sealed record ThreatConsensusResult(
    ConsensusVerdict Verdict,
    int Score,
    int Malicious,
    int Suspicious,
    int Benign,
    int NoDetection,
    int Failed,
    int Answered,
    string Explanation)
{
    public string Label => Verdict switch
    {
        ConsensusVerdict.Malicious => "Malicious",
        ConsensusVerdict.Suspicious => "Suspicious",
        ConsensusVerdict.Benign => "Benign",
        ConsensusVerdict.NoThreatFound => "No threat found",
        _ => "No data"
    };
}

/// <summary>
/// Combines the providers' normalised verdicts into one verdict and a 0-100 score (pure, unit-tested, explainable):
/// <list type="bullet">
/// <item>Only real answers count (Malicious, Suspicious, Benign, Unknown, NotFound); errors and skipped lookups do not.</item>
/// <item>Score = 100 × (malicious + ½ suspicious − ½ benign) / answers, clamped to 0-100.</item>
/// <item>Malicious when two or more providers say malicious, or one does and the score is at least 40
///   (e.g. one of two answering providers).</item>
/// <item>Suspicious when any provider says malicious or suspicious and the score is above 0; Benign when providers
///   vouch for it and outweigh any weak findings (score 0); No threat found when providers answered without findings;
///   No data when nobody answered.</item>
/// </list>
/// Each provider has one vote: vendors differ in coverage, so agreement between independent sources is what counts.
/// </summary>
public static class ThreatConsensus
{
    public const int MaliciousScoreThreshold = 40;

    public static ThreatConsensusResult Compute(IEnumerable<IpReputation> answers)
    {
        var list = answers.ToList();
        int m = 0, s = 0, b = 0, none = 0, failed = 0;
        foreach (var a in list)
        {
            switch (a.Verdict)
            {
                case ThreatVerdict.Malicious: m++; break;
                case ThreatVerdict.Suspicious: s++; break;
                case ThreatVerdict.Benign: b++; break;
                case ThreatVerdict.Unknown or ThreatVerdict.NotFound: none++; break;
                case ThreatVerdict.Error: failed++; break;
            }
        }
        var answered = m + s + b + none;
        if (answered == 0)
            return new ThreatConsensusResult(ConsensusVerdict.NoData, 0, 0, 0, 0, 0, failed, 0,
                failed > 0 ? $"{failed} provider(s) could not be reached; no verdict yet." : "No provider has answered yet.");

        var raw = 100.0 * (m + 0.5 * s - 0.5 * b) / answered;
        var score = (int)Math.Round(Math.Clamp(raw, 0, 100), MidpointRounding.AwayFromZero);
        // Benign votes can cancel weak signals: when they bring the score to 0 (e.g. 8.8.8.8: one engine of 92 flags it,
        // AbuseIPDB whitelists it) the result is Benign, never "Suspicious with score 0".
        var verdict = m >= 2 || (m >= 1 && score >= MaliciousScoreThreshold) ? ConsensusVerdict.Malicious
            : m + s > 0 && score > 0 ? ConsensusVerdict.Suspicious
            : b > 0 ? ConsensusVerdict.Benign
            : ConsensusVerdict.NoThreatFound;

        var parts = new List<string>();
        if (m > 0) parts.Add($"{m} malicious");
        if (s > 0) parts.Add($"{s} suspicious");
        if (b > 0) parts.Add($"{b} benign");
        if (none > 0) parts.Add($"{none} without findings");
        var explanation = $"{answered} provider(s) answered: {string.Join(", ", parts)}."
                          + (m + s > 0 && b > 0 ? " Mixed signals: benign answers outweigh or soften the findings." : "")
                          + (failed > 0 ? $" {failed} could not be reached." : "");
        return new ThreatConsensusResult(verdict, score, m, s, b, none, failed, answered, explanation);
    }
}
