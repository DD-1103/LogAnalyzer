namespace LogAnalyzer.Web.Models;

public enum LogFileStatus
{
    Pending = 0,
    Processing = 1,
    Completed = 2,
    Failed = 3,
    Analyzing = 4
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

/// <summary>Signature = regex match on a single event. Threshold = N matching events from one IP within a time window.</summary>
public enum RuleKind
{
    Signature = 0,
    Threshold = 1
}

/// <summary>Which field of a log event a signature rule inspects.</summary>
public enum RuleField
{
    Url = 0,
    UserAgent = 1,
    Referrer = 2
}

public enum AlertStatus
{
    New = 0,
    Investigating = 1,
    FalsePositive = 2,
    Closed = 3
}
