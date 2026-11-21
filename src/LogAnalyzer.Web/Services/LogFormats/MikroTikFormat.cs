using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// MikroTik RouterOS remote syslog: firewall rules with action=log (optionally with a log prefix)
/// <c>firewall,info DROP-WAN input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.5:51234->10.0.0.5:22, len 60</c>
/// (IPv6 as <c>[2001:db8::5]:51234->[2001:db8::1]:22</c>, ICMP without ports) and the login messages of the
/// "system" topic. The action comes from the prefix words (drop / reject / block / deny / accept), without a prefix it
/// is Unknown and the chain is the rule name. Other RouterOS topic lines are skipped.
/// </summary>
public sealed class MikroTikFormat : ILogFormat
{
    public string Id => "mikrotik";
    public string DisplayName => "MikroTik RouterOS";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly HashSet<string> Topics = new(StringComparer.Ordinal)
    {
        "system", "firewall", "dhcp", "interface", "wireless", "ppp", "pppoe", "l2tp", "pptp", "sstp", "ovpn", "ipsec",
        "script", "account", "info", "warning", "error", "critical", "debug", "dns", "bridge", "caps", "health", "hotspot",
        "route", "ospf", "bgp", "web-proxy", "certificate", "radius", "ntp", "e-mail", "async", "lte", "wireguard"
    };

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            var firewall = line.Contains(": in:", StringComparison.Ordinal);
            if (!firewall && !line.Contains(',', StringComparison.Ordinal))
                return ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);
            var msg = env.Message;

            if (firewall)
            {
                // "router1 input: in:ether1 ..." - the syslog parser takes the chain for a tag; put it back
                if (!msg.Contains(": in:", StringComparison.Ordinal) && env.AppName is { } chainTag && msg.StartsWith("in:", StringComparison.Ordinal))
                    msg = chainTag + ": " + msg;
                return Firewall(env, msg, out result);
            }

            // "system,error,critical login failure for user admin from 203.0.113.9 via ssh"
            var space = msg.IndexOf(' ');
            if (space <= 0 || !IsTopicList(msg[..space]) || env.Timestamp is null)
                return ParseOutcome.Failed;
            var topics = msg[..space];
            var text = msg[(space + 1)..].Trim();
            if (!topics.StartsWith("system", StringComparison.Ordinal) && !topics.Contains("account", StringComparison.Ordinal))
                return ParseOutcome.Skipped;
            FirewallAction action;
            if (text.StartsWith("login failure for user ", StringComparison.Ordinal))
                action = FirewallAction.Deny;
            else if (text.StartsWith("user ", StringComparison.Ordinal) && text.Contains(" logged in from ", StringComparison.Ordinal))
                action = FirewallAction.Allow;
            else
                return ParseOutcome.Skipped;
            var ip = WordAfter(text, " from ");
            if (!IsIp(ip))
                return ParseOutcome.Skipped;
            result = ParsedLine.Network(ip, env.Timestamp.Value, action, Short(text), null, null, null, null, "auth", null, null, env.Host);
            return ParseOutcome.Parsed;
        }

        private static ParseOutcome Firewall(SyslogEnvelope env, string msg, out ParsedLine? result)
        {
            result = null;
            var idx = msg.IndexOf(": in:", StringComparison.Ordinal);
            if (idx < 0)
                return ParseOutcome.Failed;
            var head = Tokens(msg[..idx]);
            if (head.Length == 0)
                return ParseOutcome.Failed;
            var first = 0;
            if (head[0].Contains(',') || head[0] == "firewall")
            {
                if (!IsTopicList(head[0]))
                    return ParseOutcome.Failed;
                first = 1;
            }
            if (head.Length <= first)
                return ParseOutcome.Failed;
            var chain = head[^1];
            var prefix = head.Length - 1 > first ? string.Join(' ', head[first..^1]) : null;

            var body = msg[(idx + 2)..];
            var inIf = WordAfter(body, "in:")?.TrimEnd(',');
            var pi = body.IndexOf("proto ", StringComparison.Ordinal);
            if (pi < 0)
                return ParseOutcome.Failed;
            var i = pi + 6;
            var protoEnd = i;
            while (protoEnd < body.Length && body[protoEnd] is not (' ' or ','))
                protoEnd++;
            var protoWord = body[i..protoEnd];
            i = protoEnd;
            string? detail = null;
            while (i < body.Length && body[i] == ' ')
                i++;
            if (i < body.Length && body[i] == '(')
            {
                var close = body.IndexOf(')', i);
                if (close < 0)
                    return ParseOutcome.Failed;
                detail = body[(i + 1)..close];
                i = close + 1;
            }
            if (i >= body.Length || body[i] != ',')
                return ParseOutcome.Failed;
            i++;
            while (i < body.Length && body[i] == ' ')
                i++;
            var addrEnd = body.IndexOf(',', i);
            var addresses = addrEnd < 0 ? body[i..] : body[i..addrEnd];
            var arrow = addresses.IndexOf("->", StringComparison.Ordinal);
            if (arrow <= 0 || !TryEndpoint(addresses[..arrow], out var src, out var sport) || !TryEndpoint(addresses[(arrow + 2)..], out var dst, out var dport))
                return ParseOutcome.Failed;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;

            var proto = Transport(protoWord);
            if (proto is not ("tcp" or "udp" or "sctp"))
            {
                sport = null;
                dport = null;
            }
            var len = WordAfter(body, ", len ")?.TrimEnd(',');
            var action = ActionFromPrefix(prefix);
            var message = $"{prefix ?? chain} {chain}: {proto} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          (detail is null ? "" : $" ({detail})") + (inIf is null ? "" : $" in {inIf}");
            result = ParsedLine.Network(src, ts, action, Short(message), dst, sport, dport, proto, "traffic", prefix ?? chain, null,
                env.Host, len is null ? null : Long(len));
            return ParseOutcome.Parsed;
        }

        private static bool IsTopicList(string token)
        {
            var parts = token.Split(',');
            return parts.Length >= 1 && Topics.Contains(parts[0]) && parts.All(p => p.Length > 0 && p.All(c => c is >= 'a' and <= 'z' or '-' or >= '0' and <= '9'));
        }

        private static FirewallAction ActionFromPrefix(string? prefix)
        {
            if (prefix is null)
                return FirewallAction.Unknown;
            var u = prefix.ToUpperInvariant();
            if (u.Contains("REJECT")) return FirewallAction.Reject;
            if (u.Contains("DROP")) return FirewallAction.Drop;
            if (u.Contains("BLOCK") || u.Contains("DENY")) return FirewallAction.Deny;
            if (u.Contains("ACCEPT") || u.Contains("ALLOW") || u.Contains("PERMIT")) return FirewallAction.Allow;
            return FirewallAction.Unknown;
        }

        /// <summary>"203.0.113.5:51234", "203.0.113.5", "[2001:db8::5]:51234", "2001:db8::5".</summary>
        private static bool TryEndpoint(string text, out string ip, out int? port)
        {
            ip = string.Empty;
            port = null;
            var v = text.Trim();
            if (v.StartsWith('['))
            {
                var close = v.IndexOf(']');
                if (close < 0)
                    return false;
                ip = v[1..close];
                if (close + 2 < v.Length && v[close + 1] == ':')
                    port = Port(v[(close + 2)..]);
                return IsIp(ip);
            }
            if (IsIp(v))
            {
                ip = v;
                return true;
            }
            var colon = v.LastIndexOf(':');
            if (colon <= 0 || v.IndexOf(':') != colon)
                return false;
            ip = v[..colon];
            port = Port(v[(colon + 1)..]);
            return IsIp(ip);
        }

        private static string? WordAfter(string s, string marker)
        {
            var i = s.IndexOf(marker, StringComparison.Ordinal);
            if (i < 0)
                return null;
            var start = i + marker.Length;
            var end = s.IndexOf(' ', start);
            var w = end < 0 ? s[start..] : s[start..end];
            return w.Length == 0 ? null : w;
        }
    }
}
