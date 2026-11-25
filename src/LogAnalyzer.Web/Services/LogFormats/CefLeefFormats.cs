using System.Globalization;
using System.Text;
using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.FirewallFields;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>Shared CEF / LEEF logic: event type, action and the start of the record inside an optional syslog wrapper.</summary>
internal static class StructuredRecord
{
    /// <summary>Finds "CEF:" / "LEEF:" and the syslog envelope around it (time stamp and host fallback).</summary>
    public static bool TryLocate(string line, string marker, LogParseContext context, out string record, out SyslogEnvelope? envelope)
    {
        record = string.Empty;
        envelope = null;
        var index = line.IndexOf(marker, StringComparison.Ordinal);
        if (index < 0)
            return false;
        if (index == 0)
        {
            record = line;
            return true;
        }
        envelope = SyslogEnvelope.Parse(line, context);
        // The record must be the message itself, not text inside another program's message (a user name, a URL).
        var inner = envelope.Message.IndexOf(marker, StringComparison.Ordinal);
        if (!envelope.RecordStartsAt(inner))
            return false;
        record = envelope.Message[inner..];
        return true;
    }

    /// <summary>The message itself is a CEF / LEEF record (not merely a URL or user name that contains "CEF:").</summary>
    public static bool IsCefOrLeef(SyslogEnvelope envelope) =>
        envelope.RecordStartsAt(envelope.Message.IndexOf("CEF:", StringComparison.Ordinal))
        || envelope.RecordStartsAt(envelope.Message.IndexOf("LEEF:", StringComparison.Ordinal));

    /// <summary>"threat" (IPS / malware / ...), "auth" (logins) or "traffic".</summary>
    public static string EventType(string? category, string? name, string? threatName)
    {
        if (threatName is not null || IsThreatWord(category) || IsThreatWord(name))
            return "threat";
        if (LooksLikeAuth(category) || LooksLikeAuth(name))
            return "auth";
        return "traffic";
    }

    private static bool IsThreatWord(string? text) =>
        text is not null && (LooksLikeThreat(text) || ContainsIgnoreCase(text, "/ids") || ContainsIgnoreCase(text, "bot"));

    public static FirewallAction ActionFor(string eventType, FirewallAction? action, string? outcome, string? name)
    {
        if (eventType == "auth")
        {
            if (action is FirewallAction.Deny or FirewallAction.Drop or FirewallAction.Reject)
                return action.Value;
            var failed = LooksLikeFailure(outcome) || LooksLikeFailure(name);
            return failed ? FirewallAction.Deny : FirewallAction.Allow;
        }
        var a = action ?? TryAction(outcome) ?? FirewallAction.Unknown;
        if (eventType == "threat" && a is FirewallAction.Unknown or FirewallAction.Allow)
            a = FirewallAction.Alert;
        return a;
    }

    /// <summary>Header fields separated by unescaped "|"; returns the index after the last separator read.</summary>
    public static int SplitHeader(string s, int start, Span<int> pipes, out int found)
    {
        found = 0;
        var i = start;
        for (; i < s.Length && found < pipes.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length)
            {
                i++;
                continue;
            }
            if (s[i] == '|')
                pipes[found++] = i;
        }
        return i;
    }

    public static string HeaderField(string s, int from, int to)
    {
        var span = s.AsSpan(from, Math.Max(0, to - from));
        return span.IndexOf('\\') >= 0 ? KeyValueReader.Unescape(span).Trim() : span.Trim().ToString();
    }
}

/// <summary>
/// ArcSight Common Event Format: <c>CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|src=... dst=... spt=...
/// dpt=... proto=TCP act=deny rt=... cs1Label=Rule cs1=... dvchost=...</c>, optionally inside syslog.
/// Reference: Micro Focus / OpenText "ArcSight Common Event Format (CEF) Implementation Standard" v25+.
/// </summary>
public sealed class CefFormat : ILogFormat
{
    public string Id => "cef";
    public string DisplayName => "CEF (Common Event Format)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 50;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly string[] LabelKeys = ["cs1Label", "cs2Label", "cs3Label", "cs4Label", "cs5Label", "cs6Label"];
    private static readonly string[] ValueKeys = ["cs1", "cs2", "cs3", "cs4", "cs5", "cs6"];

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!StructuredRecord.TryLocate(line, "CEF:", Context, out var cef, out var envelope))
                return ParseOutcome.Failed;
            Span<int> pipes = stackalloc int[7];
            StructuredRecord.SplitHeader(cef, 4, pipes, out var found);
            if (found < 7)
                return ParseOutcome.Failed;
            var signatureId = StructuredRecord.HeaderField(cef, pipes[3] + 1, pipes[4]);
            var name = StructuredRecord.HeaderField(cef, pipes[4] + 1, pipes[5]);
            var product = StructuredRecord.HeaderField(cef, pipes[1] + 1, pipes[2]);
            KeyValueReader.Read(cef, Kv, KvMode.UntilNextKey, start: pipes[6] + 1);

            string? rule = null, threat = null;
            for (var i = 0; i < LabelKeys.Length; i++)
            {
                var label = Kv.Get(LabelKeys[i]);
                if (label is null || Kv.Get(ValueKeys[i]) is not { } value)
                    continue;
                var key = KvAliases.Normalise(label);
                if (key is "rule" or "rulename" or "policy" or "policyname" or "accessrule" or "acl" or "firewallrule" or "rulenumber")
                    rule ??= value;
                else if (key is "threat" or "threatname" or "signature" or "signaturename" or "attack" or "attackname" or "virus"
                         or "malware" or "ipssignature" or "threatid")
                    threat ??= value;
            }
            rule ??= Kv.Get(KvField.Rule);
            threat ??= Kv.Get(KvField.Threat);

            var zone = Kv.Get("dtz");
            var stamp = Kv.Get("rt") ?? Kv.Get("end") ?? Kv.Get("start") ?? Kv.Get("deviceReceiptTime");
            var time = ParseTime(stamp, zone) ?? envelope?.Timestamp;
            var category = Kv.Get("cat");
            var eventType = StructuredRecord.EventType(category, name, threat);
            if (eventType == "threat")
                threat ??= name.Length > 0 ? name : signatureId;
            // fw_action: SonicWall ArcSight format; ZYnote: Zyxel ("ACCESS BLOCK", the plain format's note field)
            var action = StructuredRecord.ActionFor(eventType, TryAction(Kv.Get("act")) ?? TryAction(Kv.Get("deviceAction"))
                ?? TryAction(Kv.Get("fw_action")) ?? ZyxelFormat.NoteAction(Kv.Get("ZYnote")), Kv.Get("outcome"), name);
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var device = Kv.Get("dvchost") ?? Kv.Get("deviceExternalId") ?? envelope?.Host ?? Kv.Get("dvc");
            var msg = Kv.Get("msg");
            var message = name.Length == 0 ? signatureId : name;
            if (msg is not null && !string.Equals(msg, message, StringComparison.Ordinal))
                message = message + ": " + msg;
            if (string.IsNullOrWhiteSpace(message))
                message = product;
            var bytes = Bytes(Kv.Get("out"), Kv.Get("in"));
            return Build(out result, time, action, src, dst, transport, eventType, message, rule, threat, device, bytes);
        }
    }
}

/// <summary>
/// IBM QRadar Log Event Extended Format: <c>LEEF:1.0|Vendor|Product|Version|EventID|k=v&lt;TAB&gt;k=v</c> and
/// <c>LEEF:2.0|Vendor|Product|Version|EventID|^|k=v^k=v</c> (delimiter as a character or hex "x5E"). Time from
/// devTime + devTimeFormat (Java date pattern) or the syslog header. Reference: IBM "Log Event Extended Format (LEEF)"
/// (QRadar DSM documentation).
/// </summary>
public sealed class LeefFormat : ILogFormat
{
    public string Id => "leef";
    public string DisplayName => "LEEF (IBM QRadar)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 50;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            if (!StructuredRecord.TryLocate(line, "LEEF:", Context, out var leef, out var envelope))
                return ParseOutcome.Failed;
            Span<int> pipes = stackalloc int[5];
            StructuredRecord.SplitHeader(leef, 5, pipes, out var found);
            if (found < 5)
                return ParseOutcome.Failed;
            var version = leef.AsSpan(5, pipes[0] - 5).Trim();
            var eventId = StructuredRecord.HeaderField(leef, pipes[3] + 1, pipes[4]);
            var extensionStart = pipes[4] + 1;
            var delimiter = '\t';

            if (version.StartsWith("2"))
            {
                var next = leef.IndexOf('|', extensionStart);
                if (next >= 0 && next - extensionStart <= 6 && leef.AsSpan(extensionStart, next - extensionStart).IndexOf('=') < 0)
                {
                    var spec = leef.AsSpan(extensionStart, next - extensionStart);
                    if (TryDelimiter(spec, out var d))
                        delimiter = d;
                    extensionStart = next + 1;
                }
            }

            // Tabs are often turned into spaces on the way; then read it like a CEF extension.
            if (delimiter == '\t' && leef.IndexOf('\t', extensionStart) < 0)
                KeyValueReader.Read(leef, Kv, KvMode.UntilNextKey, start: extensionStart);
            else
                KeyValueReader.Read(leef, Kv, KvMode.Delimiter, delimiter, extensionStart);

            var time = DevTime() ?? envelope?.Timestamp;
            var category = Kv.Get("cat");
            var threat = Kv.Get(KvField.Threat);
            var eventType = StructuredRecord.EventType(category, eventId, threat);
            if (eventType == "threat")
                threat ??= Kv.Get(KvField.Message) ?? eventId;
            var action = StructuredRecord.ActionFor(eventType, ActionOf(Kv), Kv.Get("outcome") ?? Kv.Get("result"), eventId + " " + Kv.Get(KvField.Message));
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var device = envelope?.Host ?? Kv.Get("devName") ?? Kv.Get(KvField.Device);
            var message = Kv.Get(KvField.Message) is { } msg ? $"{eventId}: {msg}" : eventId;
            var bytes = Bytes(Kv.Get(KvField.SentBytes), Kv.Get(KvField.ReceivedBytes), Kv.Get(KvField.TotalBytes));
            return Build(out result, time, action, src, dst, TransportOf(Kv), eventType, message, Kv.Get(KvField.Rule), threat,
                device, bytes);
        }

        private DateTimeOffset? DevTime()
        {
            var value = Kv.Get("devTime");
            if (value is null)
                return null;
            var format = Kv.Get("devTimeFormat");
            if (format is not null && JavaTime.TryParse(value, format, Context, out var ts))
                return ts;
            return ParseTime(value);
        }

        /// <summary>"^", "x5E", "0x5E" or "\t".</summary>
        private static bool TryDelimiter(ReadOnlySpan<char> spec, out char delimiter)
        {
            delimiter = '\t';
            if (spec.Length == 1)
            {
                delimiter = spec[0];
                return true;
            }
            if (spec.SequenceEqual("\\t"))
                return true;
            var hex = spec.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? spec[2..]
                : spec.StartsWith("x", StringComparison.OrdinalIgnoreCase) ? spec[1..] : ReadOnlySpan<char>.Empty;
            if (hex.Length is >= 1 and <= 4 && int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code) && code > 0)
            {
                delimiter = (char)code;
                return true;
            }
            return false;
        }
    }
}

/// <summary>Java SimpleDateFormat subset used by LEEF devTimeFormat (MMM dd yyyy HH:mm:ss, yyyy-MM-dd'T'HH:mm:ss.SSSZ, ...).</summary>
public static class JavaTime
{
    public static bool TryParse(string value, string javaFormat, LogParseContext context, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (javaFormat.Length > 64 || value.Length > 64)
            return false;
        var v = value.Trim();
        var f = javaFormat.Trim();

        // Zone letters (z, Z, X) are cut from pattern and value; the value's zone is read separately.
        TimeSpan? offset = null;
        var zoneAt = f.IndexOfAny(['z', 'Z', 'X']);
        if (zoneAt >= 0)
        {
            f = f[..zoneAt].TrimEnd();
            if (!SplitZone(ref v, out var zone))
                return false;
            offset = zone;
        }

        var net = new StringBuilder(f.Length + 8);
        foreach (var c in f)
        {
            net.Append(c switch
            {
                'S' => 'f',
                'a' => 't',
                'E' => 'd',
                _ => c
            });
        }
        var pattern = net.ToString().Replace("t", "tt", StringComparison.Ordinal);
        if (!DateTime.TryParseExact(v, pattern, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var local))
            return false;
        return LogTime.TryLocal(local, offset ?? context.DefaultOffset, out timestamp);
    }

    /// <summary>Cuts "Z", "+0100", "+01:00", " UTC" / " CET" from the end of the value.</summary>
    private static bool SplitZone(ref string value, out TimeSpan offset)
    {
        offset = TimeSpan.Zero;
        if (value.EndsWith('Z'))
        {
            value = value[..^1].TrimEnd();
            return true;
        }
        var space = value.LastIndexOf(' ');
        if (space > 0 && FirewallTime.TryOffset(value[(space + 1)..], out offset))
        {
            value = value[..space].TrimEnd();
            return true;
        }
        foreach (var length in (ReadOnlySpan<int>)[6, 5, 3])
        {
            if (value.Length > length && value[^length] is '+' or '-' && FirewallTime.TryOffset(value[^length..], out offset))
            {
                value = value[..^length];
                return true;
            }
        }
        return false;
    }
}
