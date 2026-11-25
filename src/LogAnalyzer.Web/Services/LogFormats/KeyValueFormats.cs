using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.FirewallFields;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Base of the key=value / structured firewall parsers: one reusable <see cref="KeyValueLine"/> per file, and a
/// catch-all so a parser bug turns into a Failed line instead of an exception.
/// </summary>
public abstract class FirewallLineParser(LogParseContext context) : ILineParser
{
    public const int MaxLineLength = 16 * 1024;

    protected LogParseContext Context { get; } = context;
    protected KeyValueLine Kv { get; } = new();

    public ParseOutcome Parse(string line, out ParsedLine? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength)
            return ParseOutcome.Failed;
        try
        {
            return ParseLine(line, out result);
        }
        catch (Exception)
        {
            result = null;
            return ParseOutcome.Failed;
        }
    }

    /// <summary>The parser without the length limit and the catch-all (fuzz tests: it must not throw on its own either).</summary>
    public ParseOutcome ParseUnguarded(string line, out ParsedLine? result) => ParseLine(line, out result);

    protected abstract ParseOutcome ParseLine(string line, out ParsedLine? result);

    private const int MaxLeadingWords = 4;

    /// <summary>
    /// Reads the pairs of a vendor record. False when the text was written by another program (sshd, nginx, ...) or
    /// has prose in front of the first pair: log text is attacker-controlled, so "Failed password for invalid user
    /// type=traffic devid=x srcip=10.0.0.1 ..." must not become a firewall event.
    /// </summary>
    protected bool ReadRecord(SyslogEnvelope envelope, string? text = null, KvMode mode = KvMode.Spaces)
    {
        if (envelope.FromOtherProgram || StructuredRecord.IsCefOrLeef(envelope))
            return false;
        KeyValueReader.Read(text ?? envelope.Message, Kv, mode);
        return Kv.Count > 0 && Kv.LeadingWords <= MaxLeadingWords;
    }

    /// <summary>An HTTP request without a firewall decision (JSON / logfmt web server logs): not a firewall event.</summary>
    protected bool LooksLikeWebRequest() =>
        Has("method", "http_method", "request_method", "requestmethod", "http.request.method", "request.method", "verb", "http.method")
        && Has("uri", "url", "path", "request", "request_uri", "status", "status_code", "url.original", "url.path",
            "http.response.status_code", "request.uri", "response", "http.url");

    private bool Has(params ReadOnlySpan<string> keys)
    {
        foreach (var k in keys)
            if (Kv.Has(k))
                return true;
        return false;
    }

    /// <summary>Vendor time from the usual fields, else the syslog envelope.</summary>
    protected DateTimeOffset? TimeOf(SyslogEnvelope envelope) => FirewallTime.FromFields(Kv, Context) ?? envelope.Timestamp;

    protected DateTimeOffset? ParseTime(string? value, string? zone = null) =>
        FirewallTime.TryParse(value, Context, out var ts, zone) ? ts : null;
}

/// <summary>
/// Fortinet FortiGate / FortiOS: <c>date=2026-11-21 time=10:00:00 devname="fw01" devid="FGT60F..." logid="0000000013"
/// type="traffic" subtype="forward" srcip=... dstip=... action="deny" policyid=0 ...</c>. Reference: Fortinet
/// "FortiOS Log Message Reference" (docs.fortinet.com). type=utm = IPS / antivirus / web filter / application control /
/// anomaly; type=event = system, VPN and user events (login failures).
/// </summary>
public sealed class FortiGateFormat : ILogFormat
{
    public string Id => "fortigate";
    public string DisplayName => "Fortinet FortiGate";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("type=", StringComparison.Ordinal)
                || !(line.Contains("logid=", StringComparison.Ordinal) || line.Contains("devid=", StringComparison.Ordinal)))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            var type = ReadRecord(envelope) ? Kv.Get("type")?.ToLowerInvariant() : null;
            if (type is null || !(Kv.Has("logid") || Kv.Has("devid")))
                return ParseOutcome.Failed;

            var subtype = Kv.Get("subtype")?.ToLowerInvariant();
            var time = TimeOf(envelope);
            var device = Kv.Get("devname") ?? Kv.Get("devid") ?? envelope.Host;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = Transport(Kv.Get("proto")) ?? TransportOf(Kv);
            var rule = Kv.Get("policyname") ?? Kv.Get("policyid");
            var bytes = Bytes(Kv.Get("sentbyte"), Kv.Get("rcvdbyte"));
            var actionWord = Kv.Get("action");
            var msg = Kv.Get("msg");
            var logdesc = Kv.Get("logdesc");

            switch (type)
            {
                case "traffic":
                    return Build(out result, time, Action(actionWord), src, dst, transport, "traffic", msg, rule, null, device, bytes);

                case "utm" or "ips" or "virus" or "webfilter" or "app-ctrl" or "anomaly" or "attack" or "dlp" or "waf" or "dns":
                {
                    var action = Action(actionWord);
                    var kind = type == "utm" ? subtype : type;
                    // Web filter = which page was opened or blocked; application control / DNS logs of allowed traffic
                    // only name the application or the query. Neither is an attack (or every page view would be a threat).
                    if (kind == "webfilter")
                        return Build(out result, time, action, src, dst, transport, "url", msg ?? Kv.Get("url") ?? Kv.Get("hostname"),
                            rule, null, device, bytes);
                    if (kind is "app-ctrl" or "dns" && action == FirewallAction.Allow)
                        return Build(out result, time, action, src, dst, transport, "traffic", msg ?? Kv.Get("app"), rule, null, device, bytes);
                    var threat = Kv.Get("attack") ?? Kv.Get("virus") ?? Kv.Get("app") ?? Kv.Get("catdesc") ?? msg ?? subtype;
                    if (action is FirewallAction.Allow or FirewallAction.Unknown)
                        action = FirewallAction.Alert;   // passthrough / pass / monitored / detected: seen, not stopped
                    return Build(out result, time, action, src, dst, transport, "threat", msg ?? logdesc, rule, threat, device, bytes);
                }

                case "event":
                {
                    var status = Kv.Get("status");
                    var ui = Kv.Get("ui");
                    if (src.Ip is null)
                    {
                        var ip = Ip(Kv.Get("remip")) ?? IpInParentheses(ui);
                        if (ip is not null)
                            src = new Endpoint(ip, Port(Kv.Get("remport")), null);
                    }
                    if (src.Port is null && src.Ip is not null && src.Ip == Ip(Kv.Get("remip")))
                        src = src with { Port = Port(Kv.Get("remport")) };
                    if (dst.Ip is null && Ip(Kv.Get("locip")) is { } local)
                        dst = new Endpoint(local, Port(Kv.Get("locport")), null);

                    var text = msg ?? logdesc;
                    if (subtype == "user" || LooksLikeAuth(logdesc) || LooksLikeAuth(actionWord))
                    {
                        var failed = LooksLikeFailure(status) || LooksLikeFailure(actionWord) || LooksLikeFailure(logdesc);
                        return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth",
                            text, rule, null, device, bytes);
                    }
                    if (subtype == "vpn")
                    {
                        var action = LooksLikeFailure(actionWord) || LooksLikeFailure(status) ? FirewallAction.Deny
                            : ContainsIgnoreCase(actionWord, "up") || ContainsIgnoreCase(status, "success") ? FirewallAction.Allow
                            : FirewallAction.Unknown;
                        return Build(out result, time, action, src, dst, transport, "vpn", text, rule, null, device, bytes);
                    }
                    // System events (config changes, HA, performance) normally carry no addresses -> Skipped.
                    return Build(out result, time, TryAction(actionWord) ?? FirewallAction.Unknown, src, dst, transport,
                        subtype ?? "event", text, rule, null, device, bytes);
                }

                default:
                    return Build(out result, time, Action(actionWord), src, dst, transport, type, msg ?? logdesc, rule, null, device, bytes);
            }
        }
    }
}

/// <summary>
/// Sophos Firewall (SFOS / XG): <c>device="SFW" date=2026-11-21 time=10:00:00 timezone="CET" device_name="XG330"
/// log_id=010101600001 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny" ...
/// src_ip=... dst_ip=... protocol="TCP" src_port=... dst_port=...</c> and the SFOS v19+ variant (timestamp=,
/// log_subtype="Allowed"). Reference: Sophos "Sophos Firewall log file details" / "Log viewer" documentation.
/// </summary>
public sealed class SophosFormat : ILogFormat
{
    public string Id => "sophos";
    public string DisplayName => "Sophos Firewall (SFOS / XG)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("log_type=", StringComparison.Ordinal) && !line.Contains("log_component=", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            if (!ReadRecord(envelope))
                return ParseOutcome.Failed;
            var logType = Kv.Get("log_type");
            var component = Kv.Get("log_component");
            if ((logType is null && component is null)
                || !(Kv.Has("log_id") || Kv.Has("device_name") || Kv.Has("messageid") || Kv.Has("log_subtype")))
                return ParseOutcome.Failed;

            var subtype = Kv.Get("log_subtype");
            var status = Kv.Get("status");
            var time = TimeOf(envelope);
            var device = Kv.Get("device_name") ?? Kv.Get("device_serial_id") ?? Kv.Get("device_id") ?? envelope.Host;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var rule = Kv.Get("fw_rule_name") ?? Kv.Get("fw_rule_id") ?? Kv.Get(KvField.Rule);
            var bytes = Bytes(Kv.Get(KvField.SentBytes), Kv.Get(KvField.ReceivedBytes));
            var message = Kv.Get("message") ?? Kv.Get("log_message");
            var type = logType?.ToLowerInvariant() ?? "";

            if (type == "firewall")
            {
                var action = TryAction(status) ?? TryAction(subtype) ?? Action(Kv.Get("action"));
                return Build(out result, time, action, src, dst, transport, "traffic", message, rule, null, device, bytes);
            }
            if (type is "idp" or "ips" or "anti-virus" or "antivirus" or "atp" or "advanced threat protection" or "sandstorm"
                or "zero day protection" or "anti-spam" or "waf")
            {
                var threat = Kv.Get("signature_msg") ?? Kv.Get("threatname") ?? Kv.Get("virus") ?? Kv.Get("malware")
                             ?? Kv.Get(KvField.Threat) ?? Kv.Get("signature_id") ?? message;
                var action = TryAction(Kv.Get("action")) ?? TryAction(subtype) ?? TryAction(status) ?? FirewallAction.Alert;
                if (action == FirewallAction.Allow)
                    action = FirewallAction.Alert;
                return Build(out result, time, action, src, dst, transport, "threat", message, rule, threat, device, bytes);
            }
            if (type == "event")
            {
                var text = $"{component} {subtype} {message}";
                if (LooksLikeAuth(text) || ContainsIgnoreCase(component, "admin") || ContainsIgnoreCase(component, "vpn"))
                {
                    if (status is null && message is null)
                        return Build(out result, time, FirewallAction.Unknown, src, dst, transport, "event", null, rule, null, device, bytes);
                    var failed = LooksLikeFailure(status) || LooksLikeFailure(subtype) || LooksLikeFailure(message);
                    var who = Kv.Get("user_name") ?? Kv.Get(KvField.User);
                    message ??= $"{component} login {(failed ? "failed" : "succeeded")}{(who is null ? "" : " for " + who)}";
                    return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport,
                        "auth", message, rule, null, device, bytes);
                }
                return Build(out result, time, FirewallAction.Unknown, src, dst, transport, "event", message, rule, null, device, bytes);
            }
            var other = TryAction(status) ?? TryAction(subtype) ?? Action(Kv.Get("action"));
            var otherType = type switch { "" => "event", "content filtering" => "url", _ => type };
            return Build(out result, time, other, src, dst, transport, otherType, message, rule, null, device, bytes);
        }
    }
}

/// <summary>
/// SonicWall (SonicOS): <c>id=firewall sn=0017C5... time="2026-11-21 10:00:00 UTC" fw=198.51.100.1 pri=1 c=32 m=36
/// msg="TCP packet dropped" n=1234 src=203.0.113.5:51234:X1 dst=10.0.0.5:22:X0 proto=tcp/ssh fw_action="drop"</c>.
/// Reference: SonicWall "SonicOS Log Events Reference Guide". The message id (m=) classifies the event.
/// </summary>
public sealed class SonicWallFormat : ILogFormat
{
    public string Id => "sonicwall";
    public string DisplayName => "SonicWall";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    // Message ids checked against the "SonicOS 6.5.4 Log Events Reference Guide": 97 web site hit, 98 / 537 connection
    // opened / closed, 526 web request allowed, 597 / 598 ICMP allowed, 602 DNS allowed, 1235 packet allowed;
    // 36-41, 173-175, 522-534, 652, 1253, 1254, 1257 dropped; 82 / 83 / 177 port scan, 608 / 609 IPS, 789 / 790 IDP,
    // 793 application firewall, 794 / 795 anti-spyware, 809 gateway anti-virus, 1154 / 1155 application control;
    // 29 / 199 administrator login allowed, 30 / 35 / 200 denied, 31 user login allowed, 32 / 33 denied, 237 / 238 VPN / WAN
    // administrator login allowed. 1080 (SSL VPN login) is not legible in that guide: decided by the message text.
    private static readonly HashSet<int> Opened = [97, 98, 526, 537, 597, 598, 602, 1235];
    private static readonly HashSet<int> Dropped = [36, 37, 38, 41, 173, 174, 175, 522, 524, 533, 534, 652, 1253, 1254, 1257];
    private static readonly HashSet<int> Intrusion = [82, 83, 177, 608, 609, 789, 790, 793, 794, 795, 809, 1154, 1155];
    private static readonly HashSet<int> Login = [29, 30, 31, 32, 33, 35, 199, 200, 237, 238, 1080];
    private static readonly HashSet<int> LoginDenied = [30, 32, 33, 35, 200];

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("sn=", StringComparison.Ordinal) || !line.Contains("m=", StringComparison.Ordinal)
                || !line.Contains("id=", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            var m = ReadRecord(envelope) ? Port(Kv.Get("m")) : null;
            if (!Kv.Has("id") || !Kv.Has("sn") || m is null)
                return ParseOutcome.Failed;

            var msg = Kv.Get("msg");
            var fwAction = Kv.Get("fw_action");
            var time = ParseTime(Kv.Get("time")) ?? envelope.Timestamp;
            var device = envelope.Host ?? Kv.Get("sn");
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var rule = Kv.Get(KvField.Rule);
            var bytes = Bytes(Kv.Get("sent"), Kv.Get("rcvd"));

            if (Intrusion.Contains(m.Value) || StartsWithAny(msg, "IPS ", "IDP ", "Gateway Anti-Virus", "Anti-Spyware", "Botnet"))
            {
                var colon = msg?.IndexOf(": ", StringComparison.Ordinal) ?? -1;
                var threat = colon > 0 ? msg![(colon + 2)..] : msg;
                var action = TryAction(fwAction)
                             ?? (m is 609 or 790 or 794 or 1155 || ContainsIgnoreCase(msg, "prevention") || ContainsIgnoreCase(msg, "blocked")
                                 ? FirewallAction.Deny : FirewallAction.Alert);
                if (action == FirewallAction.Allow)
                    action = FirewallAction.Alert;
                return Build(out result, time, action, src, dst, transport, "threat", msg, rule, threat, device, bytes);
            }
            if (Login.Contains(m.Value) || LooksLikeAuth(msg))
            {
                var failed = LooksLikeFailure(msg) || LoginDenied.Contains(m.Value);
                return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth",
                    msg, rule, null, device, bytes);
            }

            var traffic = TryAction(fwAction) switch
            {
                { } a => a,
                null when Dropped.Contains(m.Value) || ContainsIgnoreCase(msg, "dropped") => FirewallAction.Drop,
                null when ContainsIgnoreCase(msg, "denied") || ContainsIgnoreCase(msg, "blocked") => FirewallAction.Deny,
                null when Opened.Contains(m.Value) || ContainsIgnoreCase(msg, "opened") || ContainsIgnoreCase(msg, "closed")
                          || ContainsIgnoreCase(msg, "allowed") => FirewallAction.Allow,
                _ => FirewallAction.Unknown
            };
            return Build(out result, time, traffic, src, dst, transport, "traffic", msg, rule, null, device, bytes);
        }

        private static bool StartsWithAny(string? text, params ReadOnlySpan<string> prefixes)
        {
            if (text is null)
                return false;
            foreach (var p in prefixes)
                if (text.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }
    }
}

/// <summary>
/// Stormshield Network Security (SNS): <c>id=firewall time="2026-11-21 10:00:00" fw="SN310" tz=+0000 startime="..."
/// pri=5 ruleid=4 ipproto=tcp proto=ssh src=... srcport=... dst=... dstport=22 action=block logtype="filter"</c>;
/// logtype="alarm" = IPS alarm (msg, classification). Reference: Stormshield "Description of audit logs" (documentation.stormshield.eu).
/// </summary>
public sealed class StormshieldFormat : ILogFormat
{
    public string Id => "stormshield";
    public string DisplayName => "Stormshield SNS";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("id=firewall", StringComparison.Ordinal)
                || !(line.Contains("logtype=", StringComparison.Ordinal) || line.Contains("startime=", StringComparison.Ordinal)))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            if (!ReadRecord(envelope) || !string.Equals(Kv.Get("id"), "firewall", StringComparison.OrdinalIgnoreCase)
                || !(Kv.Has("logtype") || Kv.Has("startime")) || (Kv.Has("sn") && Kv.Has("m")))
                return ParseOutcome.Failed;

            var zone = Kv.Get("tz");
            var time = ParseTime(Kv.Get("time"), zone) ?? ParseTime(Kv.Get("startime"), zone) ?? envelope.Timestamp;
            var device = Kv.Get("fw") ?? envelope.Host;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = Transport(Kv.Get("ipproto")) ?? TransportOf(Kv);
            var rule = Kv.Get("rulename") ?? Kv.Get("ruleid");
            var bytes = Bytes(Kv.Get("sent"), Kv.Get("rcvd"));
            var msg = Kv.Get("msg");
            var actionWord = Kv.Get("action");
            var logType = Kv.Get("logtype")?.ToLowerInvariant() ?? "filter";

            switch (logType)
            {
                case "alarm":
                {
                    var threat = msg ?? Kv.Get("classification") ?? Kv.Get("alarmid");
                    var action = TryAction(actionWord) ?? FirewallAction.Alert;
                    if (action == FirewallAction.Allow)
                        action = FirewallAction.Alert;   // "pass": the alarm did not block
                    return Build(out result, time, action, src, dst, transport, "threat", msg, rule, threat, device, bytes);
                }
                case "auth" or "server" or "xvpn" or "vpn" or "sslvpn":
                {
                    var error = Kv.Get("error");
                    var failed = (error is not null && error != "0") || LooksLikeFailure(msg);
                    var type = logType == "vpn" && !LooksLikeAuth(msg) && error is null ? "vpn" : "auth";
                    return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, type,
                        msg, rule, null, device, bytes);
                }
                case "filter" or "connection" or "plugin":
                {
                    var action = TryAction(actionWord) ?? (logType == "connection" ? FirewallAction.Allow : FirewallAction.Unknown);
                    return Build(out result, time, action, src, dst, transport, "traffic", msg, rule, null, device, bytes);
                }
                default:
                    return Build(out result, time, TryAction(actionWord) ?? FirewallAction.Unknown, src, dst, transport, logType,
                        msg, rule, null, device, bytes);
            }
        }
    }
}

/// <summary>
/// Zyxel USG / ATP / USG FLEX (ZLD): <c>&lt;134&gt;Nov 21 10:00:00 usg60 src="203.0.113.5:51234" dst="10.0.0.5:22"
/// msg="Match default rule, DROP" note="ACCESS BLOCK" user="unknown" devID="..." cat="Security Policy" protoID=6 proto="ssh"</c>.
/// No own date: the syslog time stamp is used. Reference: Zyxel "ZLD Log Reference Guide" (USG / ATP series).
/// </summary>
public sealed class ZyxelFormat : ILogFormat
{
    public string Id => "zyxel";
    public string DisplayName => "Zyxel USG / ATP";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    /// <summary>"ACCESS BLOCK" / "ACCESS FORWARD" (note field, ZYnote in Zyxel's CEF output) to an action.</summary>
    internal static FirewallAction? NoteAction(string? note)
    {
        if (note is null)
            return null;
        if (ContainsIgnoreCase(note, "block") || ContainsIgnoreCase(note, "deny"))
            return FirewallAction.Deny;
        if (ContainsIgnoreCase(note, "drop"))
            return FirewallAction.Drop;
        if (ContainsIgnoreCase(note, "reject") || ContainsIgnoreCase(note, "reset"))
            return FirewallAction.Reject;
        if (ContainsIgnoreCase(note, "forward") || ContainsIgnoreCase(note, "allow") || ContainsIgnoreCase(note, "accept")
            || ContainsIgnoreCase(note, "permit"))
            return FirewallAction.Allow;
        return null;
    }

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("devID=", StringComparison.Ordinal) || !line.Contains("cat=", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            if (!ReadRecord(envelope) || !Kv.Has("devID") || !Kv.Has("cat"))
                return ParseOutcome.Failed;

            var time = envelope.Timestamp ?? FirewallTime.FromFields(Kv, Context);
            var device = envelope.Host ?? Kv.Get("devID");
            var src = Unspecified(FirewallFields.Source(Kv));
            var dst = Unspecified(Destination(Kv));
            var transport = Transport(Kv.Get("protoID")) ?? TransportOf(Kv);
            var msg = Kv.Get("msg");
            var note = Kv.Get("note");
            var category = Kv.Get("cat")?.ToLowerInvariant() ?? "";

            if (category is "idp" or "ips" or "anti-virus" or "anti-malware" or "av" or "botnet filter" or "adp"
                or "ip reputation" or "sandboxing" or "anti-spam" or "threat intelligence")
            {
                var action = ActionAfterLabel(msg) ?? NoteAction(note) ?? FirewallAction.Alert;
                if (action == FirewallAction.Allow)
                    action = FirewallAction.Alert;
                return Build(out result, time, action, src, dst, transport, "threat", msg, null, Signature(msg), device);
            }
            if (category is "user" or "account" or "auth" or "authentication" || LooksLikeAuth(msg))
            {
                if (!LooksLikeAuth(msg))
                    return Build(out result, time, FirewallAction.Unknown, src, dst, transport, "event", msg, null, null, device);
                var failed = LooksLikeFailure(msg);
                return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth", msg,
                    null, null, device);
            }
            if (category is "security policy" or "firewall" or "access control" or "policy control" or "policy route")
            {
                var action = LastWordAction(msg) ?? NoteAction(note) ?? FirewallAction.Unknown;
                return Build(out result, time, action, src, dst, transport, "traffic", msg, RuleOf(msg), null, device);
            }
            // System, interface, DHCP, ... (usually src="0.0.0.0") -> Skipped
            return Build(out result, time, NoteAction(note) ?? FirewallAction.Unknown, src, dst, transport, category, msg, null, null, device);
        }

        private static Endpoint Unspecified(Endpoint e) => e.Ip is "0.0.0.0" or "::" ? default : e;

        /// <summary>"Match default rule, DROP" / "priority:3, from WAN to LAN, service SSH, ACCEPT" -> the last word.</summary>
        private static FirewallAction? LastWordAction(string? msg)
        {
            if (msg is null)
                return null;
            var t = msg.TrimEnd(' ', '.', ',');
            var cut = Math.Max(t.LastIndexOf(','), t.LastIndexOf(' '));
            return TryAction(cut >= 0 ? t[(cut + 1)..] : t);
        }

        /// <summary>"... Action: Drop, Severity: High" -> Drop.</summary>
        private static FirewallAction? ActionAfterLabel(string? msg)
        {
            var i = msg?.IndexOf("Action:", StringComparison.OrdinalIgnoreCase) ?? -1;
            if (i < 0)
                return null;
            var rest = msg![(i + 7)..].TrimStart();
            var end = rest.IndexOfAny([',', ' ', '.', ';']);
            return TryAction(end < 0 ? rest : rest[..end]);
        }

        /// <summary>"from WAN to LAN, [type=Signature] 1051001 WEB-ATTACKS SQL Injection Action: Drop, Severity: High" -> the name.</summary>
        private static string? Signature(string? msg)
        {
            if (msg is null)
                return null;
            var s = msg;
            var bracket = s.IndexOf("] ", StringComparison.Ordinal);
            if (bracket >= 0)
                s = s[(bracket + 2)..];
            var action = s.IndexOf("Action:", StringComparison.OrdinalIgnoreCase);
            if (action > 0)
                s = s[..action];
            return s.Trim().TrimEnd(',', '.').Trim();
        }

        private static string? RuleOf(string? msg)
        {
            if (msg is null)
                return null;
            if (ContainsIgnoreCase(msg, "default rule"))
                return "default";
            var i = msg.IndexOf("priority:", StringComparison.OrdinalIgnoreCase);
            if (i < 0)
                return null;
            var digits = new string(msg.AsSpan(i + 9).TrimStart().ToArray().TakeWhile(char.IsAsciiDigit).ToArray());
            return digits.Length == 0 ? null : "priority " + digits;
        }
    }
}

/// <summary>
/// Any other firewall that logs key=value pairs (Barracuda, Hillstone, Forcepoint, Untangle, ...): needs a source IP
/// and a destination IP (or a source IP and an action word) under one of the <see cref="KvAliases"/> names, and a time
/// stamp (date/time, timestamp-like keys or the syslog envelope). Lowest specificity, so a vendor format always wins.
/// </summary>
public sealed class GenericKeyValueFormat : ILogFormat
{
    public string Id => "keyvalue";
    public string DisplayName => "Generic key=value firewall log";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 10;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 16 || CountChar(line, '=', 3) < 3)
                return ParseOutcome.Failed;
            // (Decided by the structure, never by words anywhere in the line: a URL could contain them and hide the event.)
            var envelope = SyslogEnvelope.Parse(line, Context);
            var message = envelope.Message;
            var commas = CountChar(message, ',', int.MaxValue);
            var equals = CountChar(message, '=', int.MaxValue);
            var mode = commas >= 2 && commas + 1 >= equals - 1 && message.Contains(", ", StringComparison.Ordinal) ? KvMode.Comma : KvMode.Spaces;
            // Commas inside a value (a user name, a message) can make the guess wrong: then the other mode is tried.
            if (!TryRead(envelope, message, mode) && !TryRead(envelope, message, mode == KvMode.Comma ? KvMode.Spaces : KvMode.Comma))
                return ParseOutcome.Failed;

            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var action = ActionOf(Kv);
            var time = TimeOf(envelope);
            if (time is null)
                return ParseOutcome.Failed;
            var threat = Kv.Get(KvField.Threat);
            var device = envelope.Host ?? Kv.Get(KvField.Device);
            var message2 = Kv.Get(KvField.Message);
            var hint = Kv.Get("event") ?? Kv.Get("type") ?? Kv.Get("subtype") ?? Kv.Get(KvField.Category);
            if (threat is null && (LooksLikeAuth(hint) || LooksLikeAuth(message2)))
            {
                var failed = LooksLikeFailure(hint) || LooksLikeFailure(message2) || LooksLikeFailure(Kv.Get("result") ?? Kv.Get("status"))
                             || action is FirewallAction.Deny or FirewallAction.Drop or FirewallAction.Reject;
                return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, TransportOf(Kv), "auth",
                    message2, Kv.Get(KvField.Rule), null, device);
            }
            var finalAction = action ?? FirewallAction.Unknown;
            if (threat is not null && finalAction is FirewallAction.Unknown or FirewallAction.Allow)
                finalAction = FirewallAction.Alert;
            return Build(out result, time, finalAction, src, dst, TransportOf(Kv), threat is null ? "traffic" : "threat",
                message2, Kv.Get(KvField.Rule), threat, device,
                Bytes(Kv.Get(KvField.SentBytes), Kv.Get(KvField.ReceivedBytes), Kv.Get(KvField.TotalBytes)));
        }

        /// <summary>A source address and a destination address or action; with both, free text in between does not matter.</summary>
        private bool TryRead(SyslogEnvelope envelope, string message, KvMode mode)
        {
            if (!ReadRecord(envelope, message, mode) || Kv.Count < 3 || FirewallFields.Source(Kv).Ip is null)
                return false;
            var hasDestination = Destination(Kv).Ip is not null;
            var hasAction = ActionOf(Kv) is not null;
            return (hasDestination || hasAction)
                   && (Kv.BareTokens <= Kv.Count || (hasDestination && hasAction))
                   && (hasAction || !LooksLikeWebRequest());
        }

        private static int CountChar(string s, char c, int stopAt)
        {
            var n = 0;
            for (var i = s.IndexOf(c); i >= 0 && n < stopAt; i = s.IndexOf(c, i + 1))
                n++;
            return n;
        }
    }
}
