using System.Text.Json;
using LogAnalyzer.Web.Models;
using static LogAnalyzer.Web.Services.LogFormats.FirewallFields;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>
/// One JSON object per line from cloud and next-generation firewalls. Fields are flattened to dotted paths and mapped
/// with <see cref="KvAliases"/> (full path first, then the last two segments, then the last segment), which covers
/// Elastic Common Schema (source.ip, destination.port, event.action, rule.name, @timestamp), AWS Network Firewall
/// (event.src_ip, event.alert.signature, event_timestamp), Azure Firewall (properties.SourceIp / legacy properties.msg),
/// Google Cloud firewall rules logging (jsonPayload.connection.*, jsonPayload.disposition) and OPNsense / pfSense JSON.
/// Only lines with a time stamp and an address (plus some sign of a firewall decision) are events, so other JSON logs
/// are not mistaken for firewall logs.
/// </summary>
public sealed class JsonFirewallFormat : ILogFormat
{
    public string Id => "json";
    public string DisplayName => "JSON lines (ECS / cloud firewalls)";
    public LogSource Source => LogSource.Firewall;
    public int Specificity => 50;
    public ILineParser CreateParser(LogParseContext context) => new Parser(context);

    private static readonly JsonDocumentOptions Options = new() { MaxDepth = 32, AllowTrailingCommas = false };

    private sealed class Parser(LogParseContext context) : FirewallLineParser(context)
    {
        protected override ParseOutcome ParseLine(string line, out ParsedLine? result)
        {
            result = null;
            var json = line.AsSpan().Trim();
            DateTimeOffset? envelopeTime = null;
            string? envelopeHost = null;
            if (json.Length == 0 || json[0] != '{')
            {
                // JSON inside syslog ("<134>Nov 21 10:00:00 fw01 app: {...}")
                if (json.IndexOf("{\"") < 0)
                    return ParseOutcome.Failed;
                var envelope = SyslogEnvelope.Parse(line, Context);
                json = envelope.Message.AsSpan().Trim();
                if (json.Length == 0 || json[0] != '{')
                    return ParseOutcome.Failed;
                envelopeTime = envelope.Timestamp;
                envelopeHost = envelope.Host;
            }
            if (json[^1] != '}')
                return ParseOutcome.Failed;

            var text = json.ToString();
            JsonDocument document;
            try
            {
                // through bytes: unpaired surrogates become U+FFFD instead of an exception
                document = JsonDocument.Parse(System.Text.Encoding.UTF8.GetBytes(text), Options);
            }
            catch (JsonException)
            {
                return ParseOutcome.Failed;
            }
            using (document)
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                    return ParseOutcome.Failed;
                Kv.Reset(text);
                Flatten(document.RootElement, null);
            }
            return Interpret(envelopeTime, envelopeHost, out result);
        }

        private void Flatten(JsonElement element, string? path)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        if (Kv.Count >= KeyValueLine.MaxPairs)
                            return;
                        var name = NameOf(property);
                        if (name is null || name.Length + (path?.Length ?? 0) >= MaxPathLength)
                            continue;
                        Flatten(property.Value, path is null ? name : path + "." + name);
                    }
                    break;
                case JsonValueKind.Array:
                    var scalars = new List<string>();
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                            Flatten(item, path);
                        else if (Scalar(item) is { } s)
                            scalars.Add(s);
                    }
                    if (scalars.Count > 0 && path is not null)
                        Add(path, string.Join(",", scalars));
                    break;
                default:
                    if (path is not null && Scalar(element) is { } value)
                        Add(path, value);
                    break;
            }
        }

        private const int MaxPathLength = 256;

        // "\ud800" without its partner is valid JSON text but no valid string: GetString / Name throw. One such value
        // (a user agent) must not make the whole event unreadable.
        private static string? NameOf(JsonProperty property)
        {
            try
            {
                return property.Name;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        private static string TextOf(JsonElement e)
        {
            try
            {
                return e.GetString() ?? "";
            }
            catch (InvalidOperationException)
            {
                return e.GetRawText().Trim('"');
            }
        }

        private static string? Scalar(JsonElement e) => e.ValueKind switch
        {
            JsonValueKind.String => TextOf(e),
            JsonValueKind.Number => e.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };

        private void Add(string path, string value)
        {
            var (field, priority) = ResolvePath(path);
            // A client chooses its HTTP headers: repeated paths and fields without a meaning must not use up the room
            // for the addresses that follow them.
            if ((field == KvField.None && Kv.Count >= KeyValueLine.MaxPairs / 2) || Kv.Has(path))
                return;
            Kv.AddResolved(path, value, field, priority);
        }

        /// <summary>
        /// Full dotted path, else the last two segments (+5), else the last segment (+10); one more per level, so
        /// "event.src_ip" wins over an HTTP header that a client named "src_ip" ("event.http.headers.src_ip").
        /// </summary>
        internal static (KvField Field, byte Priority) ResolvePath(string path)
        {
            var hit = KvAliases.Resolve(path);
            if (hit.Field != KvField.None)
                return hit;
            var last = path.LastIndexOf('.');
            if (last < 0)
                return hit;
            var depth = Math.Min(path.AsSpan().Count('.'), 64);
            var previous = last > 0 ? path.LastIndexOf('.', last - 1) : -1;
            if (previous >= 0)
            {
                hit = KvAliases.Resolve(path.AsSpan(previous + 1));
                if (hit.Field != KvField.None)
                    return (hit.Field, (byte)(hit.Priority + 5 + depth));
            }
            hit = KvAliases.Resolve(path.AsSpan(last + 1));
            return hit.Field != KvField.None ? (hit.Field, (byte)(hit.Priority + 10 + depth)) : hit;
        }

        private ParseOutcome Interpret(DateTimeOffset? envelopeTime, string? envelopeHost, out ParsedLine? result)
        {
            result = null;
            var src = FirewallFields.Source(Kv);
            var dst = Destination(Kv);
            var transport = TransportOf(Kv);
            var action = ActionOf(Kv);
            var message = Kv.Get(KvField.Message);
            var category = Kv.Get(KvField.Category);
            var eventKind = Kv.Get("event.event_type") ?? Kv.Get("event_type") ?? Kv.Get("event.kind") ?? Kv.Get("event.type");
            var threat = Kv.Get(KvField.Threat);
            var rule = Kv.Get("properties.Rule") ?? Kv.Get(KvField.Rule);

            // Azure Firewall legacy diagnostics: everything is in properties.msg
            if (src.Ip is null && dst.Ip is null && Kv.Get("properties.msg") is { } azure && AzureMessage.TryParse(azure, out var parsed))
            {
                src = parsed.Source;
                dst = parsed.Destination;
                transport ??= Transport(parsed.Protocol);
                action ??= TryAction(parsed.Action);
                rule ??= parsed.Rule;
                threat ??= parsed.Threat;
            }

            var isThreat = threat is not null || ContainsAny(category, "intrusion", "malware", "threat", "idps", "ids")
                           || string.Equals(eventKind, "alert", StringComparison.OrdinalIgnoreCase);
            var outcome = Kv.Get("event.outcome") ?? Kv.Get("outcome");
            var isAuth = !isThreat && (ContainsAny(category, "authentication") || LooksLikeAuth(Kv.Get("event.action")));

            string eventType;
            FirewallAction finalAction;
            if (isThreat)
            {
                eventType = "threat";
                threat ??= Kv.Get("properties.Description") ?? Kv.Get("rule.name") ?? message;
                finalAction = action is null or FirewallAction.Allow ? FirewallAction.Alert : action.Value;
            }
            else if (isAuth)
            {
                eventType = "auth";
                var failed = LooksLikeFailure(outcome) || action is FirewallAction.Deny or FirewallAction.Drop or FirewallAction.Reject
                             || LooksLikeFailure(Kv.Get("event.action"));
                finalAction = failed ? FirewallAction.Deny : FirewallAction.Allow;
            }
            else
            {
                eventType = "traffic";
                // AWS Network Firewall "netflow" records describe flows that were let through.
                finalAction = action ?? (string.Equals(eventKind, "netflow", StringComparison.OrdinalIgnoreCase)
                    ? FirewallAction.Allow : FirewallAction.Unknown);
            }

            // Guard against other JSON logs: an address alone is not a firewall event.
            var firewallLike = dst.Ip is not null || action is not null || dst.Port is not null || transport is not null || isThreat || isAuth;
            if ((src.Ip is null && dst.Ip is null) || !firewallLike)
                return ParseOutcome.Failed;
            if (action is null && !isThreat && !isAuth && LooksLikeWebRequest())
                return ParseOutcome.Failed;
            var time = FirewallTime.FromFields(Kv, Context) ?? envelopeTime;
            if (time is null)
                return ParseOutcome.Failed;
            var device = Kv.Get(KvField.Device) ?? envelopeHost;
            var bytes = Bytes(Kv.Get(KvField.SentBytes), Kv.Get(KvField.ReceivedBytes), Kv.Get(KvField.TotalBytes));
            return Build(out result, time, finalAction, src, dst, transport, eventType, message, rule, threat, device, bytes);
        }

        private static bool ContainsAny(string? text, params ReadOnlySpan<string> words)
        {
            if (text is null)
                return false;
            foreach (var w in words)
                if (text.Contains(w, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }
    }
}

/// <summary>
/// Azure Firewall legacy log text: "TCP request from 203.0.113.5:51234 to 10.0.0.5:22. Action: Deny. Rule Collection: c.
/// Rule: r" (network rules), "... Action: Alert. Signature: 2008983. IDS: name. Priority: 2. Classification: ..." (IDPS),
/// "... ThreatIntel: name" (threat intelligence).
/// </summary>
public static class AzureMessage
{
    public readonly record struct Result(Endpoint Source, Endpoint Destination, string? Protocol, string? Action, string? Rule, string? Threat);

    public static bool TryParse(string msg, out Result result)
    {
        result = default;
        var from = msg.IndexOf(" request from ", StringComparison.Ordinal);
        if (from <= 0)
            return false;
        var protocol = msg[..from].Split(' ', 2)[0];
        var rest = msg[(from + 14)..];
        var to = rest.IndexOf(" to ", StringComparison.Ordinal);
        if (to <= 0)
            return false;
        var source = SplitEndpoint(rest[..to]);
        rest = rest[(to + 4)..];
        var end = rest.IndexOf(". ", StringComparison.Ordinal);
        var destination = SplitEndpoint((end < 0 ? rest : rest[..end]).TrimEnd('.'));
        if (source.Ip is null && destination.Ip is null)
            return false;
        var rule = Field(msg, "Rule: ");
        var collection = Field(msg, "Rule Collection: ");
        var threat = Field(msg, "IDS: ") ?? Field(msg, "ThreatIntel: ");
        result = new Result(source, destination, protocol, Field(msg, "Action: "),
            rule ?? collection, threat);
        return true;
    }

    private static string? Field(string msg, string label)
    {
        var i = 0;
        while ((i = msg.IndexOf(label, i, StringComparison.Ordinal)) >= 0)
        {
            if (i == 0 || msg[i - 1] == ' ')
            {
                var start = i + label.Length;
                var end = msg.IndexOf(". ", start, StringComparison.Ordinal);
                var value = (end < 0 ? msg[start..] : msg[start..end]).Trim().TrimEnd('.');
                return value.Length == 0 ? null : value;
            }
            i += label.Length;
        }
        return null;
    }
}
