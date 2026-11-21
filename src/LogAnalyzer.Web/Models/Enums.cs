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
    Anomaly = 6,
    // Firewall / network attacks (firewall logs, since 2026-11-21)
    /// <summary>One source probes many ports of a host (vertical scan).</summary>
    PortScan = 7,
    /// <summary>One source probes the same service on many hosts (horizontal sweep).</summary>
    NetworkSweep = 8,
    /// <summary>The firewall's own IPS / anti-malware / botnet engine reported an attack.</summary>
    Intrusion = 9,
    /// <summary>Many blocked connections from one source (flooding, persistent probing).</summary>
    BlockedTraffic = 10,
    /// <summary>Internal host talking to typical backdoor / C2 / mining ports, or blocked outbound traffic.</summary>
    SuspiciousOutbound = 11,
    /// <summary>Failed VPN / administrator logins on the firewall itself.</summary>
    AuthenticationFailure = 12
}

/// <summary>What kind of log a file contains; rules only run on files of their kind.</summary>
public enum LogSource
{
    /// <summary>Apache / Nginx access log (Common / Combined Log Format).</summary>
    WebAccess = 0,
    /// <summary>Firewall / network device log (FortiGate, Palo Alto, Cisco ASA, ...).</summary>
    Firewall = 1
}

/// <summary>Normalised decision of a firewall about a connection or event.</summary>
public enum FirewallAction
{
    /// <summary>No decision in the log line (e.g. an informational or system event).</summary>
    Unknown = 0,
    Allow = 1,
    /// <summary>Blocked by policy (vendor words: deny, block, discard).</summary>
    Deny = 2,
    /// <summary>Silently dropped.</summary>
    Drop = 3,
    /// <summary>Refused with a reset / ICMP unreachable.</summary>
    Reject = 4,
    /// <summary>Detected but not blocked (IPS in monitor mode, "alert", "detect", "pass" with a threat).</summary>
    Alert = 5
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
    Anomaly = 2,
    /// <summary>
    /// Firewall: N or more DIFFERENT values of <see cref="DetectionRule.Field"/> (destination ports = port scan,
    /// destination IPs = network sweep) from one source inside the time window, after the action/port filters.
    /// </summary>
    DistinctCount = 3
}

/// <summary>Which field of a log event a signature rule inspects.</summary>
public enum RuleField
{
    Url = 0,
    UserAgent = 1,
    Referrer = 2,
    // Firewall fields
    /// <summary>The event's message / summary text (LogEvent.Url holds it for firewall events).</summary>
    Message = 3,
    /// <summary>IPS / antivirus / botnet signature name reported by the firewall.</summary>
    ThreatName = 4,
    /// <summary>Name or id of the firewall policy / ACL that matched.</summary>
    RuleName = 5,
    /// <summary>Vendor event type, e.g. traffic, threat, auth, vpn, system.</summary>
    EventType = 6,
    DestinationPort = 7,
    DestinationIp = 8
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
