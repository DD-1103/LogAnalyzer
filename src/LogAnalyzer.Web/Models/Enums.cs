namespace LogAnalyzer.Web.Models;

public enum LogFileStatus
{
    Pending = 0,
    Processing = 1,
    Completed = 2,
    Failed = 3,
    Analyzing = 4,
    Deleting = 5
}

public enum AttackType
{
    BruteForce = 0,
    SqlInjection = 1,
    Xss = 2,
    PathTraversal = 3,
    Scanner = 4,
    DirectoryEnumeration = 5,
    Anomaly = 6
}

public enum Severity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

/// <summary>
/// Signature = regex match on a single event. Threshold = N matching events from one IP within a time window.
/// Anomaly = Isolation Forest over per-IP behaviour features (no fixed pattern).
/// </summary>
public enum RuleKind
{
    Signature = 0,
    Threshold = 1,
    Anomaly = 2
}

/// <summary>Which field of a log event a signature rule inspects.</summary>
public enum RuleField
{
    Url = 0,
    UserAgent = 1,
    Referrer = 2
}

/// <summary>Verdict a SOC 2 analyst gives on an escalated alert.</summary>
public enum EscalationVerdict
{
    /// <summary>Confirmed attack (true positive).</summary>
    Malicious = 1,
    /// <summary>Not an attack: the rule fired on legitimate traffic.</summary>
    FalsePositive = 2,
    /// <summary>Not decided yet: keep the alert open and watch the source.</summary>
    KeepMonitoring = 3,
    /// <summary>Real activity, but expected or harmless (e.g. an authorised scanner).</summary>
    Benign = 4
}

/// <summary>What an analyst can look up at the threat-intel providers.</summary>
public enum IndicatorType
{
    Ip,
    Domain,
    Hash
}

/// <summary>SOC tier of an analyst: SOC 1 triages and escalates, SOC 2 investigates and closes (see SocPermissions).</summary>
public enum AnalystTier
{
    Soc1 = 1,
    Soc2 = 2
}

public enum AlertStatus
{
    New = 0,
    Investigating = 1,
    FalsePositive = 2,
    Closed = 3
}

/// <summary>Normalised verdict of a threat-intelligence provider about an IP address.</summary>
public enum ThreatVerdict
{
    Unknown = 0,
    Benign = 1,
    Suspicious = 2,
    Malicious = 3,
    NotFound = 4,   // the provider has no data about this IP
    Error = 5,      // lookup failed (bad key, quota, network) - retried on the next run
    Skipped = 6     // not configured, or a private address that is never sent out
}
