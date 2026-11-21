using System.Globalization;
using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.FirewallFields;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Check Point (Log Exporter): RFC 5424 syslog whose structured data holds the fields
/// <c>[action:"Drop"; ifdir:"inbound"; origin:"198.51.100.1"; product:"VPN-1 &amp; FireWall-1"; proto:"6"; rule_name:"Cleanup rule";
/// s_port:"51234"; service:"22"; src:"203.0.113.5"; dst:"10.0.0.5"; time:"1763719200"]</c> (the element can also be
/// the whole message), and the plain key=value export (<c>time=... action=Drop orig=... product=... src=... dst=...</c>).
/// Reference: Check Point "Log Exporter" (sk122323) and "Log Exporter fields" documentation.
/// </summary>
public sealed class CheckPointFormat : ILogFormat
{
    public string Id => "checkpoint";
    public string DisplayName => "Check Point (Log Exporter)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("product", StringComparison.Ordinal)
                || !(line.Contains("origin", StringComparison.Ordinal) || line.Contains("loguid", StringComparison.Ordinal)
                     || line.Contains("orig=", StringComparison.Ordinal)))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            var text = envelope.StructuredData is null ? envelope.Message : envelope.StructuredData + " " + envelope.Message;
            KeyValueReader.Read(text, Kv);
            var product = Kv.Get("product");
            if (product is null || !(Kv.Has("origin") || Kv.Has("orig") || Kv.Has("loguid") || Kv.Has("originsicname")))
                return ParseOutcome.Failed;

            var time = CheckPointTime(Kv.Get("time")) ?? envelope.Timestamp;
            var device = envelope.Host ?? Kv.Get("origin_sic_name") ?? Kv.Get("orig") ?? Kv.Get("origin");
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            if (dst.Ip is not null && Port(Kv.Get("service")) is { } servicePort)
                dst = dst with { Port = servicePort };
            var transport = TransportOf(Kv);
            var rule = Kv.Get("rule_name") ?? Kv.Get("rule") ?? Kv.Get("rule_uid");
            var actionWord = Kv.Get("action");
            var bytes = Bytes(Kv.Get("client_outbound_bytes") ?? Kv.Get("sent_bytes"), Kv.Get("client_inbound_bytes") ?? Kv.Get("received_bytes"));
            var message = Kv.Get("msg") ?? Kv.Get("message_info");

            if (IsThreatProduct(product))
            {
                var threat = Kv.Get("protection_name") ?? Kv.Get("attack") ?? Kv.Get("malware_family") ?? Kv.Get("malware_action")
                             ?? Kv.Get("attack_info") ?? Kv.Get("protection_type");
                var action = TryAction(actionWord) ?? FirewallAction.Alert;
                if (action == FirewallAction.Allow)
                    action = FirewallAction.Alert;
                return Build(out result, time, action, src, dst, transport, "threat", message, rule, threat, device, bytes);
            }

            var authStatus = Kv.Get("auth_status");
            if (authStatus is not null || LooksLikeAuth(actionWord)
                || ((ContainsIgnoreCase(product, "Mobile Access") || ContainsIgnoreCase(product, "SmartConsole")
                     || ContainsIgnoreCase(product, "Identity")) && LooksLikeAuth(message)))
            {
                var failed = LooksLikeFailure(authStatus) || LooksLikeFailure(actionWord) || LooksLikeFailure(message);
                var user = Kv.Get("user") ?? Kv.Get("src_user_name");
                message ??= $"{authStatus ?? actionWord ?? "Log In"} ({product}){(user is null ? "" : " user " + user)}";
                return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth",
                    message, rule, null, device, bytes);
            }

            var eventType = ContainsIgnoreCase(product, "VPN") && !ContainsIgnoreCase(product, "FireWall") ? "vpn" : "traffic";
            return Build(out result, time, Action(actionWord), src, dst, transport, eventType, message, rule, null, device, bytes);
        }

        private static bool IsThreatProduct(string product) =>
            ContainsIgnoreCase(product, "SmartDefense") || ContainsIgnoreCase(product, "IPS") || ContainsIgnoreCase(product, "Anti-Bot")
            || ContainsIgnoreCase(product, "Anti Bot") || ContainsIgnoreCase(product, "Threat") || ContainsIgnoreCase(product, "Anti-Virus")
            || ContainsIgnoreCase(product, "Anti Virus") || ContainsIgnoreCase(product, "Anti-Malware") || ContainsIgnoreCase(product, "Zero Phishing");

        /// <summary>Epoch / ISO (Log Exporter) or "21Nov2026 10:00:00" (older OPSEC LEA exports).</summary>
        private DateTimeOffset? CheckPointTime(string? value)
        {
            if (value is null)
                return null;
            if (ParseTime(value) is { } ts)
                return ts;
            return DateTime.TryParseExact(value.Trim(), ["dMMMyyyy H:mm:ss", "ddMMMyyyy H:mm:ss"], CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var local)
                ? new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), Context.DefaultOffset)
                : null;
        }
    }
}

/// <summary>
/// Huawei USG / HiSecEngine (VRP log header <c>%%01MODULE/severity/MNEMONIC(l):</c> + comma-separated pairs):
/// <c>%%01POLICY/6/POLICYDENY(l): vsys=public, protocol=6, source-ip=..., source-port=..., destination-ip=...,
/// destination-port=22, time=2026/11/21 10:00:00, ..., rule-name=deny-all.</c>, session logs
/// (<c>%%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=tcp,SourceIP=...</c>) and IPS logs
/// (<c>%%01IPS/4/DETECT(l): ... (SrcIp=..., DstIp=..., SignName=..., Action=Block)</c>).
/// Reference: Huawei "HUAWEI USG6000 / HiSecEngine Log Reference" (support.huawei.com).
/// </summary>
public sealed class HuaweiFormat : ILogFormat
{
    public string Id => "huawei";
    public string DisplayName => "Huawei USG / HiSecEngine";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly HashSet<string> ThreatModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "IPS", "AV", "ANTIVIRUS", "ATK", "ANTIATTACK", "ANTI-ATTACK", "BOTNET", "APT", "SANDBOX", "CDES", "SA_IPS", "URL", "WAF"
    };

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!line.Contains("%%", StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var envelope = SyslogEnvelope.Parse(line, Context);
            var message = envelope.Message;
            var start = message.IndexOf("%%", StringComparison.Ordinal);
            if (start < 0)
            {
                message = line;
                start = line.IndexOf("%%", StringComparison.Ordinal);
            }
            if (!TryHeader(message, start, out var module, out var mnemonic, out var bodyStart))
                return ParseOutcome.Failed;

            var body = message[bodyStart..].Trim();
            if (body.EndsWith('.'))
                body = body[..^1];
            KeyValueReader.Read(body, Kv, KvMode.Comma);

            var time = ParseTime(Kv.Get("time")) ?? envelope.Timestamp ?? FirewallTime.FromFields(Kv, Context);
            var device = envelope.Host;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var rule = Kv.Get(KvField.Rule);
            var bytes = Bytes(Kv.Get(KvField.SentBytes), Kv.Get(KvField.ReceivedBytes));
            var actionWord = Kv.Get("Action");
            var upper = mnemonic.ToUpperInvariant();

            if (ThreatModules.Contains(module))
            {
                var threat = Kv.Get("SignName") ?? Kv.Get(KvField.Threat) ?? Kv.Get("Event") ?? Kv.Get("AttackType")
                             ?? Kv.Get("VirusName") ?? Kv.Get("Category");
                var action = TryAction(actionWord) ?? FirewallAction.Alert;
                if (action == FirewallAction.Allow)
                    action = FirewallAction.Alert;
                return Build(out result, time, action, src, dst, transport, "threat", null, rule, threat, device, bytes);
            }
            if (upper.Contains("LOGIN") || upper.Contains("LOGON") || upper.Contains("AUTH"))
            {
                if (src.Ip is null && (Ip(Kv.Get("IPAddress")) ?? Ip(Kv.Get("UserIP")) ?? Ip(Kv.Get("Ip")) ?? Ip(Kv.Get("ClientIp"))) is { } ip)
                    src = new Endpoint(ip, null, null);
                var failed = upper.Contains("FAIL") || LooksLikeFailure(Kv.Get("Result")) || LooksLikeFailure(Kv.Get("FailedReason"));
                var user = Kv.Get("UserName") ?? Kv.Get("User");
                var summary = $"{module}/{mnemonic}{(user is null ? "" : " user " + user)}";
                return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth",
                    summary, rule, null, device, bytes);
            }

            var traffic = upper switch
            {
                _ when upper.Contains("DENY") || upper.Contains("BLOCK") => FirewallAction.Deny,
                _ when upper.Contains("PERMIT") || upper.StartsWith("SESSION", StringComparison.Ordinal) => FirewallAction.Allow,
                _ => TryAction(actionWord) ?? FirewallAction.Unknown
            };
            var eventType = module.Equals("POLICY", StringComparison.OrdinalIgnoreCase) || module.Equals("SECLOG", StringComparison.OrdinalIgnoreCase)
                            || module.Equals("SESSION", StringComparison.OrdinalIgnoreCase) ? "traffic" : module.ToLowerInvariant();
            return Build(out result, time, traffic, src, dst, transport, eventType, null, rule, null, device, bytes);
        }

        /// <summary>"%%01POLICY/6/POLICYDENY(l):" -> module, mnemonic and where the body starts.</summary>
        private static bool TryHeader(string s, int start, out string module, out string mnemonic, out int bodyStart)
        {
            module = mnemonic = string.Empty;
            bodyStart = 0;
            var i = start + 2;
            while (i < s.Length && char.IsAsciiDigit(s[i]))
                i++;
            var moduleStart = i;
            while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] is '_' or '-'))
                i++;
            if (i == moduleStart || i >= s.Length || s[i] != '/')
                return false;
            module = s[moduleStart..i];
            i++;
            var severityStart = i;
            while (i < s.Length && char.IsAsciiDigit(s[i]))
                i++;
            if (i == severityStart || i >= s.Length || s[i] != '/')
                return false;
            i++;
            var mnemonicStart = i;
            while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] is '_' or '-'))
                i++;
            if (i == mnemonicStart)
                return false;
            mnemonic = s[mnemonicStart..i];
            if (i < s.Length && s[i] == '(')
            {
                var close = s.IndexOf(')', i);
                if (close < 0 || close - i > 4)
                    return false;
                i = close + 1;
            }
            if (i >= s.Length || s[i] != ':')
                return false;
            bodyStart = i + 1;
            return true;
        }
    }
}

/// <summary>
/// Cisco Meraki MX (syslog "flows", "firewall", "ids-alerts", "security_event", "urls", "events"):
/// <c>1763719200.123456789 MX84 flows src=... dst=... protocol=tcp sport=... dport=22 pattern: deny all</c>,
/// <c>... ids-alerts signature=1:2001219:20 priority=1 ... src=ip:port dst=ip:port message: ET SCAN ...</c>.
/// Reference: Cisco Meraki "Syslog Event Types and Log Samples" (documentation.meraki.com).
/// </summary>
public sealed class MerakiFormat : ILogFormat
{
    public string Id => "meraki";
    public string DisplayName => "Cisco Meraki MX";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly HashSet<string> Types = new(StringComparer.Ordinal)
    {
        "flows", "firewall", "vpn_firewall", "cellular_firewall", "bridge_anyconnect_client_vpn_firewall", "l7_firewall",
        "ids-alerts", "security_event", "urls", "events", "airmarshal_events", "port_forwarding"
    };

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!TryHead(line, out var epoch, out var host, out var type, out var rest))
            {
                // A collector may have put its own syslog header in front ("Nov 21 10:00:00 192.0.2.10 1 1763...").
                if (line.Length > 0 && char.IsAsciiDigit(line[0]))
                    return ParseOutcome.Failed;
                var envelope = SyslogEnvelope.Parse(line, Context);
                if (ReferenceEquals(envelope.Message, line) || !TryHead(envelope.Message, out epoch, out host, out type, out rest))
                    return ParseOutcome.Failed;
            }

            // Free text after the pairs: "pattern: deny all", "message: ET SCAN ...", "request: GET http://..."
            var tail = (string?)null;
            var kvText = rest;
            foreach (var marker in (ReadOnlySpan<string>)["pattern:", "message:", "request:"])
            {
                var i = rest.IndexOf(marker, StringComparison.Ordinal);
                if (i >= 0 && (i == 0 || rest[i - 1] == ' '))
                {
                    kvText = rest[..i];
                    tail = rest[(i + marker.Length)..].Trim();
                    break;
                }
            }
            KeyValueReader.Read(kvText, Kv);
            var time = epoch;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var firstWord = FirstWord(kvText);

            switch (type)
            {
                case "ids-alerts":
                case "security_event" when firstWord is "ids_alerted" or "ids-alerted":
                {
                    var action = TryAction(Kv.Get("decision")) ?? TryAction(Kv.Get("action")) ?? FirewallAction.Alert;
                    if (action == FirewallAction.Allow)
                        action = FirewallAction.Alert;
                    return Build(out result, time, action, src, dst, transport, "threat", null, Kv.Get("signature"), tail, host);
                }
                case "security_event":
                {
                    var threat = Kv.Get("name") ?? Kv.Get("disposition") ?? firstWord;
                    var action = TryAction(Kv.Get("action")) ?? FirewallAction.Alert;
                    if (action == FirewallAction.Allow)
                        action = FirewallAction.Alert;
                    return Build(out result, time, action, src, dst, transport, "threat", tail, null, threat, host);
                }
                case "urls":
                    return Build(out result, time, FirewallAction.Allow, src, dst, transport, "url",
                        tail is null ? null : "request: " + tail, null, null, host);
                case "events" or "airmarshal_events":
                {
                    var text = rest;
                    if (!LooksLikeAuth(text))
                        return Build(out result, time, FirewallAction.Unknown, src, dst, transport, "event", null, null, null, host);
                    if (src.Ip is null && IpAfter(text, " from ") is { } from)
                        src = new Endpoint(from, null, null);
                    var failed = LooksLikeFailure(text);
                    return Build(out result, time, failed ? FirewallAction.Deny : FirewallAction.Allow, src, dst, transport, "auth",
                        text.Length > 300 ? text[..300] : text, null, null, host);
                }
                default:
                {
                    // flows / firewall / vpn_firewall / ...: "pattern: allow all", newer firmware also "flows deny src=..."
                    var action = TryAction(FirstWord(tail)) ?? TryAction(firstWord) ?? FirewallAction.Unknown;
                    return Build(out result, time, action, src, dst, transport, "traffic", null, tail, null, host);
                }
            }
        }

        /// <summary>"[&lt;134&gt;][1 ]EPOCH HOST TYPE rest".</summary>
        private static bool TryHead(string s, out DateTimeOffset time, out string host, out string type, out string rest)
        {
            time = default;
            host = type = rest = string.Empty;
            var i = 0;
            if (s.StartsWith('<'))
            {
                var close = s.IndexOf('>');
                if (close is < 2 or > 4)
                    return false;
                i = close + 1;
            }
            if (s.Length > i + 2 && s[i] == '1' && s[i + 1] == ' ')
                i += 2;
            var epoch = NextToken(s, ref i);
            if (epoch.Length < 10 || !char.IsAsciiDigit(epoch[0]) || !FirewallTime.TryEpoch(epoch.ToString(), out time))
                return false;
            var h = NextToken(s, ref i);
            var t = NextToken(s, ref i);
            if (h.Length == 0 || t.Length == 0 || !Types.Contains(t.ToString()))
                return false;
            host = h.ToString();
            type = t.ToString();
            rest = i < s.Length ? s[i..].Trim() : string.Empty;
            return true;
        }

        private static ReadOnlySpan<char> NextToken(string s, ref int i)
        {
            while (i < s.Length && s[i] == ' ')
                i++;
            var start = i;
            while (i < s.Length && s[i] != ' ')
                i++;
            return s.AsSpan(start, i - start);
        }

        private static string? FirstWord(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return null;
            var t = text.TrimStart();
            var end = t.IndexOf(' ');
            var word = end < 0 ? t : t[..end];
            return word.Contains('=') ? null : word;
        }

        private static string? IpAfter(string text, string marker)
        {
            var i = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0)
                return null;
            var rest = text[(i + marker.Length)..].TrimStart();
            var end = rest.IndexOfAny([' ', ',', ';', ')']);
            return Ip((end < 0 ? rest : rest[..end]).Trim('\''));
        }
    }
}
