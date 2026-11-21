using System.Globalization;
using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.PositionalFormatHelpers;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// Juniper SRX / Junos OS security logs ("Junos OS System Log Messages Reference"): RT_FLOW_SESSION_CREATE / CLOSE /
/// DENY in text mode ("session denied 203.0.113.5/51234->10.0.0.5/22 0x0 junos-ssh 6(0) default-deny(global) ...") or
/// structured-data mode (RFC 5424 "[junos@2636... source-address="..." ...]"), RT_IDP attack logs, RT_SCREEN
/// (port scan, flood, spoofing) and SSHD_LOGIN_FAILED. Other lines with a Junos tag (RT_, UI_, SNMP_, ...) are skipped.
/// </summary>
public sealed class JuniperSrxFormat : ILogFormat
{
    public string Id => "juniper-srx";
    public string DisplayName => "Juniper SRX (Junos)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 100;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly string[] JunosTagPrefixes =
        ["RT_", "UI_", "SNMP_", "SSHD_", "CHASSISD_", "KMD_", "JSRPD_", "PFE_", "LICENSE_", "MIB2D_", "IDP_", "AV_", "WEBFILTER_", "APPTRACK_", "LOGIN_"];

    private sealed class Parser(LogParseContext context) : ILineParser
    {
        public ParseOutcome Parse(string line, out ParsedLine? result)
        {
            result = null;
            if (line.Length < 20 || !LooksJunos(line))
                return ParseOutcome.Failed;
            var env = SyslogEnvelope.Parse(line, context);

            if (line.Contains("RT_FLOW_SESSION_", StringComparison.Ordinal))
                return Flow(line, env, out result);
            if (line.Contains("IDP_ATTACK_LOG_EVENT", StringComparison.Ordinal))
                return Idp(env, out result);
            if (line.Contains("RT_SCREEN_", StringComparison.Ordinal))
                return Screen(env, out result);
            if (line.Contains("Login failed for user", StringComparison.Ordinal))
                return LoginFailed(env, out result);
            return HasJunosTag(env) ? ParseOutcome.Skipped : ParseOutcome.Failed;
        }

        private static bool LooksJunos(string line)
        {
            foreach (var p in JunosTagPrefixes)
                if (line.Contains(p, StringComparison.Ordinal))
                    return true;
            return line.Contains("junos@", StringComparison.Ordinal);
        }

        /// <summary>The syslog tag or the first word of the message is a Junos event tag ("UI_CMDLINE_READ_LINE:").</summary>
        private static bool HasJunosTag(SyslogEnvelope env)
        {
            static bool IsTag(string? t) => t is not null && t.Length > 3 && JunosTagPrefixes.Any(p => t.StartsWith(p, StringComparison.Ordinal))
                                            && t.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_');
            if (IsTag(env.AppName))
                return true;
            var colon = env.Message.IndexOf(':');
            if (colon > 0 && IsTag(env.Message[..colon]))
                return true;
            // RFC 5424 "RT_FLOW - RT_FLOW_SESSION_..." / structured data from Junos
            return env.StructuredData?.Contains("junos@", StringComparison.Ordinal) == true;
        }

        // ---------- RT_FLOW ----------
        private ParseOutcome Flow(string line, SyslogEnvelope env, out ParsedLine? result)
        {
            result = null;
            var kind = line.Contains("RT_FLOW_SESSION_DENY", StringComparison.Ordinal) ? "deny"
                : line.Contains("RT_FLOW_SESSION_CREATE", StringComparison.Ordinal) ? "create"
                : line.Contains("RT_FLOW_SESSION_CLOSE", StringComparison.Ordinal) ? "close" : null;
            if (kind is null)
                return HasJunosTag(env) ? ParseOutcome.Skipped : ParseOutcome.Failed;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;

            string? src, dst, service, policy, srcZone, dstZone, reason;
            int? sport, dport;
            string? proto;
            long? bytes = null;

            if (env.StructuredData is { } sd && sd.Contains("source-address=", StringComparison.Ordinal))
            {
                src = QuotedValue(sd, "source-address");
                dst = QuotedValue(sd, "destination-address");
                sport = Port(QuotedValue(sd, "source-port"));
                dport = Port(QuotedValue(sd, "destination-port"));
                service = QuotedValue(sd, "service-name");
                proto = Transport(QuotedValue(sd, "protocol-id"));
                policy = QuotedValue(sd, "policy-name");
                srcZone = QuotedValue(sd, "source-zone-name");
                dstZone = QuotedValue(sd, "destination-zone-name");
                reason = QuotedValue(sd, "reason");
                var bc = Long(QuotedValue(sd, "bytes-from-client"));
                var bs = Long(QuotedValue(sd, "bytes-from-server"));
                if (bc is not null || bs is not null)
                    bytes = (bc ?? 0) + (bs ?? 0);
            }
            else
            {
                var marker = kind switch { "deny" => "session denied ", "create" => "session created ", _ => "session closed " };
                var at = env.Message.IndexOf(marker, StringComparison.Ordinal);
                if (at < 0)
                    return ParseOutcome.Failed;
                var body = env.Message[(at + marker.Length)..];
                reason = null;
                if (kind == "close")
                {
                    // "TCP FIN: 203.0.113.5/51234->..." - the close reason comes first
                    var colon = body.IndexOf(": ", StringComparison.Ordinal);
                    if (colon < 0 || colon > 60)
                        return ParseOutcome.Failed;
                    reason = body[..colon];
                    body = body[(colon + 2)..];
                }
                var t = Tokens(body);
                if (t.Length < 4 || !TrySplitFlow(t[0], out src, out sport, out dst, out dport))
                    return ParseOutcome.Failed;
                var i = t[1].StartsWith("0x", StringComparison.Ordinal) ? 2 : 1;   // connection tag (Junos 12.3X48+)
                service = Na(t[i]);
                srcZone = dstZone = policy = null;
                proto = null;
                if (kind == "deny")
                {
                    // ... protocol-id(icmp-type) policy-name(rule) source-zone destination-zone ... reason
                    proto = Transport(Paren(At(t, i + 1)));
                    policy = Paren(At(t, i + 2));
                    srcZone = At(t, i + 3);
                    dstZone = At(t, i + 4);
                    var pd = body.LastIndexOf(" policy ", StringComparison.Ordinal);
                    reason = pd > 0 ? body[(pd + 1)..].Trim() : null;
                }
                else
                {
                    // ... service nat-src->nat-dst [tag] [nat rule types / names] protocol-id policy src-zone dst-zone session-id
                    for (var k = i + 1; k < Math.Min(t.Length, i + 12); k++)
                    {
                        if (t[k].Length is >= 1 and <= 3 && t[k].All(char.IsDigit) && k + 3 < t.Length)
                        {
                            proto = Transport(t[k]);
                            policy = t[k + 1];
                            srcZone = t[k + 2];
                            dstZone = t[k + 3];
                            if (kind == "close")
                            {
                                // session-id, packets-from-client(bytes), packets-from-server(bytes)
                                var bc = ParenNumber(At(t, k + 5));
                                var bs = ParenNumber(At(t, k + 6));
                                if (bc is not null || bs is not null)
                                    bytes = (bc ?? 0) + (bs ?? 0);
                            }
                            break;
                        }
                    }
                }
            }

            if (!IsIp(src) || !IsIp(dst))
                return ParseOutcome.Failed;
            var action = kind == "deny"
                ? reason?.Contains("reject", StringComparison.OrdinalIgnoreCase) == true ? FirewallAction.Reject : FirewallAction.Deny
                : FirewallAction.Allow;
            if (proto is not ("tcp" or "udp" or "sctp"))
            {
                sport = null;
                dport = null;
            }
            var verb = kind switch { "deny" => "session denied", "create" => "session created", _ => "session closed" };
            var message = $"{verb}: {service ?? proto ?? "?"} {Endpoint(src, sport)} -> {Endpoint(dst, dport)}" +
                          $" ({srcZone ?? "?"} -> {dstZone ?? "?"}), policy {policy ?? "?"}" +
                          (reason is null ? "" : $", {reason}");
            result = ParsedLine.Network(src, ts, action, Short(message), dst, sport, dport, proto, "traffic", policy, null, env.Host, bytes);
            return ParseOutcome.Parsed;
        }

        // ---------- RT_IDP ----------
        // IDP: at 1795255200, SIG Attack log <a/p->b/p> for TCP protocol and service HTTP application NONE by rule 1 of
        // rulebase IPS in policy Recommended. attack: id=1234, repeat=0, action=DROP, threat-severity=HIGH, name=HTTP:SQL:INJ:GENERIC, ...
        private ParseOutcome Idp(SyslogEnvelope env, out ParsedLine? result)
        {
            result = null;
            var msg = env.Message;
            string? src, dst, name, actionWord, severity, policy, protoText;
            int? sport, dport;
            DateTimeOffset? vendorTime = null;
            if (env.StructuredData is { } sd && sd.Contains("source-address=", StringComparison.Ordinal))
            {
                src = QuotedValue(sd, "source-address");
                dst = QuotedValue(sd, "destination-address");
                sport = Port(QuotedValue(sd, "source-port"));
                dport = Port(QuotedValue(sd, "destination-port"));
                name = QuotedValue(sd, "attack-name");
                actionWord = QuotedValue(sd, "action");
                severity = QuotedValue(sd, "threat-severity");
                policy = QuotedValue(sd, "policy-name");
                protoText = QuotedValue(sd, "protocol-name");
                if (Long(QuotedValue(sd, "epoch-time")) is { } e && LogTime.TryParse(e.ToString(CultureInfo.InvariantCulture), context, out var et))
                    vendorTime = et;
            }
            else
            {
                var lt = msg.IndexOf('<');
                // the closing '>' is not the one of "->"
                var gt = lt;
                do
                    gt = gt < 0 ? -1 : msg.IndexOf('>', gt + 1);
                while (gt > 0 && msg[gt - 1] == '-');
                if (gt < 0 || !TrySplitFlow(msg[(lt + 1)..gt], out src, out sport, out dst, out dport))
                    return ParseOutcome.Failed;
                name = Value(msg, "name=");
                actionWord = Value(msg, "action=");
                severity = Value(msg, "threat-severity=");
                policy = Between(msg, " in policy ", ".");
                protoText = Between(msg, "> for ", " protocol");
                var at = Between(msg, " at ", ",");
                if (at is not null && at.All(char.IsDigit) && LogTime.TryParse(at, context, out var et))
                    vendorTime = et;
            }
            if (!IsIp(src))
                return ParseOutcome.Failed;
            var ts = vendorTime ?? env.Timestamp;
            if (ts is null)
                return ParseOutcome.Failed;
            var action = actionWord?.ToUpperInvariant() switch
            {
                "DROP" or "DROP_PACKET" or "DROP_CONNECTION" => FirewallAction.Drop,
                "CLOSE" or "CLOSE_CLIENT" or "CLOSE_SERVER" or "CLOSE_CLIENT_AND_SERVER" => FirewallAction.Reject,
                _ => FirewallAction.Alert   // NONE, IGNORE, RECOMMENDED = detected only
            };
            var proto = Transport(protoText);
            var message = $"IDP attack {name ?? "?"}" + (severity is null ? "" : $" [{severity}]") +
                          $" {Endpoint(src, sport)} -> {Endpoint(dst, dport)}, action {actionWord ?? "?"}";
            result = ParsedLine.Network(src, ts.Value, action, Short(message), IsIp(dst) ? dst : null, sport, dport, proto, "threat",
                policy, name, env.Host);
            return ParseOutcome.Parsed;
        }

        // ---------- RT_SCREEN ----------
        // RT_SCREEN_TCP: TCP port scan! source: 203.0.113.5:51234, destination: 10.0.0.5:22, zone name: untrust, interface name: ge-0/0/0.0, action: drop
        private ParseOutcome Screen(SyslogEnvelope env, out ParsedLine? result)
        {
            result = null;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            string? attack, srcText, dstText, zone, actionWord, protoId = null;
            if (env.StructuredData is { } sd && sd.Contains("source-address=", StringComparison.Ordinal))
            {
                attack = QuotedValue(sd, "attack-name");
                srcText = QuotedValue(sd, "source-address");
                var sp = QuotedValue(sd, "source-port");
                if (sp is not null && srcText is not null && !srcText.Contains(':')) srcText += ":" + sp;
                dstText = QuotedValue(sd, "destination-address");
                var dp = QuotedValue(sd, "destination-port");
                if (dp is not null && dstText is not null && !dstText.Contains(':')) dstText += ":" + dp;
                zone = QuotedValue(sd, "source-zone-name");
                actionWord = QuotedValue(sd, "action");
                protoId = QuotedValue(sd, "protocol-id");
            }
            else
            {
                var msg = env.Message;
                var tag = msg.IndexOf("RT_SCREEN_", StringComparison.Ordinal);
                if (tag >= 0)
                {
                    var colon = msg.IndexOf(": ", tag, StringComparison.Ordinal);
                    msg = colon < 0 ? msg : msg[(colon + 2)..];
                }
                var bang = msg.IndexOf('!');
                if (bang <= 0)
                    return ParseOutcome.Failed;
                attack = msg[..bang].Trim();
                srcText = Between(msg, "source: ", ",");
                dstText = Between(msg, "destination: ", ",");
                zone = Between(msg, "zone name: ", ",");
                actionWord = Between(msg, "action: ", ",");
                protoId = Between(msg, "protocol-id: ", ",");
            }
            if (!TrySplitColonPort(srcText, out var src, out var sport))
                return ParseOutcome.Failed;
            TrySplitColonPort(dstText, out var dst, out var dport);
            var upper = attack?.ToUpperInvariant() ?? "";
            var proto = upper.StartsWith("TCP") || upper.Contains("SYN") ? "tcp"
                : upper.StartsWith("UDP") ? "udp"
                : upper.StartsWith("ICMP") || upper.Contains("PING") ? "icmp"
                : Transport(protoId);
            if (proto is not ("tcp" or "udp"))
            {
                sport = null;
                dport = null;
            }
            var action = Action(actionWord);
            if (action == FirewallAction.Unknown)
                action = actionWord?.Contains("alarm", StringComparison.OrdinalIgnoreCase) == true ? FirewallAction.Alert : FirewallAction.Drop;
            var message = $"screen: {attack} {Endpoint(src, sport)} -> {Endpoint(string.IsNullOrEmpty(dst) ? null : dst, dport)}" +
                          (zone is null ? "" : $", zone {zone}") + $", action {actionWord ?? "?"}";
            result = ParsedLine.Network(src, ts, action, Short(message), IsIp(dst) ? dst : null, sport, dport, proto, "threat",
                zone is null ? null : "screen " + zone, attack, env.Host);
            return ParseOutcome.Parsed;
        }

        // ---------- sshd ----------
        // SSHD_LOGIN_FAILED: Login failed for user 'root' from host '203.0.113.9'
        private static ParseOutcome LoginFailed(SyslogEnvelope env, out ParsedLine? result)
        {
            result = null;
            if (env.Timestamp is not { } ts)
                return ParseOutcome.Failed;
            var msg = env.Message;
            var host = Between(msg, "from host ", " ")?.Trim('\'', '"', '.');
            if (!IsIp(host))
                return HasJunosTag(env) ? ParseOutcome.Skipped : ParseOutcome.Failed;
            var tag = msg.IndexOf("Login failed", StringComparison.Ordinal);
            result = ParsedLine.Network(host, ts, FirewallAction.Deny, Short(msg[tag..]), null, null, null, null, "auth", null, null, env.Host);
            return ParseOutcome.Parsed;
        }

        // ---------- helpers ----------
        /// <summary>"203.0.113.5/51234->10.0.0.5/22" (IPv6 too, the port follows the last '/').</summary>
        private static bool TrySplitFlow(string text, out string? src, out int? sport, out string? dst, out int? dport)
        {
            src = dst = null;
            sport = dport = null;
            var arrow = text.IndexOf("->", StringComparison.Ordinal);
            if (arrow <= 0)
                return false;
            if (!TrySplitSlash(text[..arrow], out var s, out sport) || !TrySplitSlash(text[(arrow + 2)..], out var d, out dport))
                return false;
            src = s;
            dst = d;
            return true;
        }

        /// <summary>"203.0.113.5:51234" / "203.0.113.5" / "2001:db8::5" (IPv6 without port).</summary>
        private static bool TrySplitColonPort(string? text, out string ip, out int? port)
        {
            ip = string.Empty;
            port = null;
            if (string.IsNullOrWhiteSpace(text))
                return false;
            var v = text.Trim();
            if (IsIp(v))
            {
                ip = v;
                return true;
            }
            var colon = v.LastIndexOf(':');
            if (colon <= 0 || !IsIp(v[..colon].Trim('[', ']')))
                return false;
            ip = v[..colon].Trim('[', ']');
            port = Port(v[(colon + 1)..]);
            return true;
        }

        private static string? Na(string? v) => v is null or "N/A" or "None" or "UNKNOWN" ? null : v;

        /// <summary>"6(0)" -> "6", "default-deny(global)" -> "default-deny".</summary>
        private static string? Paren(string? v)
        {
            if (v is null)
                return null;
            var p = v.IndexOf('(');
            return Na(p > 0 ? v[..p] : v);
        }

        /// <summary>"5(320)" -> 320.</summary>
        private static long? ParenNumber(string? v)
        {
            if (v is null)
                return null;
            var p = v.IndexOf('(');
            return p >= 0 && v.EndsWith(')') ? Long(v[(p + 1)..^1]) : null;
        }

        private static string? Value(string msg, string key)
        {
            var i = msg.IndexOf(key, StringComparison.Ordinal);
            while (i > 0 && msg[i - 1] is not (' ' or ',') )
                i = msg.IndexOf(key, i + 1, StringComparison.Ordinal);
            if (i < 0)
                return null;
            var start = i + key.Length;
            var end = msg.IndexOf(',', start);
            var v = (end < 0 ? msg[start..] : msg[start..end]).Trim();
            return v.Length == 0 ? null : v;
        }

        private static string? Between(string s, string start, string end)
        {
            var i = s.IndexOf(start, StringComparison.Ordinal);
            if (i < 0)
                return null;
            i += start.Length;
            var j = s.IndexOf(end, i, StringComparison.Ordinal);
            var v = (j < 0 ? s[i..] : s[i..j]).Trim();
            return v.Length == 0 ? null : v;
        }
    }
}
