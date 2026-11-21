using System.Text;

namespace LogAnalyzer.Web.Services.LogFormats;

/// <summary>Normalised meaning of a key, shared by every key=value / structured firewall format (see <see cref="KvAliases"/>).</summary>
public enum KvField : byte
{
    None = 0,
    SourceIp,
    DestinationIp,
    SourcePort,
    DestinationPort,
    Protocol,
    Action,
    Date,
    Time,
    Timestamp,
    TimeZone,
    Device,
    Rule,
    Threat,
    Message,
    SentBytes,
    ReceivedBytes,
    TotalBytes,
    User,
    Category
}

/// <summary>How values are delimited.</summary>
public enum KvMode
{
    /// <summary><c>k=v k="v w" k='v' k:"v";</c> - an unquoted value ends at white space (FortiGate, Sophos, Check Point, ...).</summary>
    Spaces,
    /// <summary><c>k=v w, k=v</c> - an unquoted value ends at a comma and may contain spaces (Huawei).</summary>
    Comma,
    /// <summary>CEF extension: an unquoted value runs until the next " key=" and uses <c>\=</c> escapes.</summary>
    UntilNextKey,
    /// <summary>LEEF: pairs separated by one delimiter character, no quoting.</summary>
    Delimiter
}

/// <summary>
/// Key aliases of the firewall vendors mapped to one <see cref="KvField"/>. Keys are compared after normalisation:
/// ASCII lower case without "-", "_", ".", "@", "/" and spaces, so <c>src_ip</c>, <c>source-ip</c>, <c>SrcIp</c>
/// and <c>source.ip</c> are all "srcip"/"sourceip". A lower priority number wins when a line has several aliases.
/// </summary>
public static class KvAliases
{
    public const int MaxKeyLength = 64;

    private static readonly Dictionary<string, (KvField Field, byte Priority)> Map = Build();
    private static readonly Dictionary<string, (KvField Field, byte Priority)>.AlternateLookup<ReadOnlySpan<char>> SpanMap =
        Map.GetAlternateLookup<ReadOnlySpan<char>>();

    private static Dictionary<string, (KvField, byte)> Build()
    {
        var d = new Dictionary<string, (KvField, byte)>(StringComparer.Ordinal);
        void Add(KvField f, byte p, params string[] keys)
        {
            foreach (var k in keys)
                d.TryAdd(k, (f, p));
        }

        Add(KvField.SourceIp, 0, "srcip", "sourceip", "srcaddr", "srcaddress", "sourceaddress", "sourceaddr", "srcipaddr",
            "sourceipaddress", "ipsrc", "saddr", "clientip", "srcipv4", "srcipv6");
        Add(KvField.SourceIp, 1, "src", "sip", "source");
        Add(KvField.SourceIp, 3, "remip", "remoteip", "remoteaddress");
        Add(KvField.DestinationIp, 0, "dstip", "destinationip", "dstaddr", "dstaddress", "destinationaddress", "destinationaddr",
            "dstipaddr", "destinationipaddress", "ipdst", "daddr", "destip", "destaddr", "serverip", "dstipv4", "dstipv6");
        Add(KvField.DestinationIp, 1, "dst", "dip", "dest", "destination");
        Add(KvField.SourcePort, 0, "srcport", "sourceport", "spt", "sport", "srcpt", "clientport", "sourcetransportport");
        Add(KvField.DestinationPort, 0, "dstport", "destinationport", "dpt", "dport", "destport", "dstpt", "serverport",
            "destinationtransportport");
        Add(KvField.Protocol, 0, "ipproto", "protoid", "ipprotocol", "networktransport", "transportprotocol");
        Add(KvField.Protocol, 1, "protocol", "transport", "protoname");
        Add(KvField.Protocol, 2, "proto");
        Add(KvField.Action, 0, "fwaction", "disposition", "alertaction");
        Add(KvField.Action, 1, "action", "act", "deviceaction");
        Add(KvField.Action, 2, "eventaction", "utmaction", "decision");
        Add(KvField.Date, 0, "date");
        Add(KvField.Time, 0, "time");
        Add(KvField.Timestamp, 0, "timestamp", "rt", "devtime", "eventtime", "receipttime", "devicereceipttime",
            "eventtimestamp", "logtime", "timegenerated", "datetime", "eventdatetime");
        Add(KvField.Timestamp, 2, "starttime", "start", "end", "endtime");
        Add(KvField.TimeZone, 0, "tz", "timezone");
        Add(KvField.Device, 0, "devname", "devicename", "firewallname", "observername", "observerhostname");
        Add(KvField.Device, 1, "hostname", "dvchost", "devicehostname", "hostname");
        Add(KvField.Device, 2, "fw", "deviceexternalid", "firewall");
        Add(KvField.Device, 3, "device", "dvc", "observer");
        Add(KvField.Rule, 0, "rulename", "policyname", "fwrulename", "ruledetailsreference", "aclname");
        Add(KvField.Rule, 1, "rule", "policy", "acl");
        Add(KvField.Rule, 2, "ruleid", "policyid", "fwruleid");
        Add(KvField.Rule, 3, "label");
        Add(KvField.Threat, 0, "threatname", "signaturename", "attackname", "signname", "malwarename", "virusname",
            "protectionname", "alertsignature");
        Add(KvField.Threat, 1, "attack", "virus", "malware", "threat", "signature", "threatdescription");
        Add(KvField.Message, 0, "msg", "message");
        Add(KvField.Message, 1, "logdesc", "eventmessage");
        Add(KvField.Message, 2, "description", "desc");
        Add(KvField.Message, 3, "reason");
        Add(KvField.SentBytes, 0, "sentbyte", "sentbytes", "bytessent", "bytesout", "srcbytes", "outbytes", "sendbytes");
        Add(KvField.SentBytes, 0, "sourcebytes", "clientbytes");
        Add(KvField.SentBytes, 1, "sent");
        Add(KvField.ReceivedBytes, 0, "rcvdbyte", "rcvdbytes", "bytesreceived", "bytesrcvd", "recvbytes", "bytesin",
            "dstbytes", "inbytes", "rcvbytes");
        Add(KvField.ReceivedBytes, 0, "destinationbytes", "serverbytes");
        Add(KvField.ReceivedBytes, 1, "rcvd", "received");
        Add(KvField.TotalBytes, 0, "bytes", "totalbytes", "networkbytes");
        Add(KvField.User, 0, "user", "username", "usrname", "srcuser", "suser", "userid");
        Add(KvField.Category, 0, "cat", "category", "eventcategory");
        return d;
    }

    /// <summary>Writes the normalised key into <paramref name="dest"/>; returns its length (0 = too long or empty).</summary>
    public static int Normalise(ReadOnlySpan<char> key, Span<char> dest)
    {
        var n = 0;
        foreach (var c in key)
        {
            if (c is '-' or '_' or '.' or '@' or '/' or ' ')
                continue;
            if (n >= dest.Length)
                return 0;
            dest[n++] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
        }
        return n;
    }

    /// <summary>Normalised form of a key as a string (tests, JSON paths).</summary>
    public static string Normalise(string key)
    {
        Span<char> buffer = stackalloc char[MaxKeyLength];
        var n = Normalise(key.AsSpan(), buffer);
        return n == 0 ? string.Empty : new string(buffer[..n]);
    }

    public static (KvField Field, byte Priority) Resolve(ReadOnlySpan<char> key)
    {
        if (key.Length == 0 || key.Length > MaxKeyLength)
            return (KvField.None, (byte)255);
        Span<char> buffer = stackalloc char[MaxKeyLength];
        var n = Normalise(key, buffer);
        return n > 0 && SpanMap.TryGetValue(buffer[..n], out var hit) ? hit : (KvField.None, (byte)255);
    }
}

/// <summary>
/// The pairs of one line. Keys and values are kept as ranges of the source text; a value string is only created
/// when it is read (and cached), so scanning millions of lines allocates little. Reuse one instance per parser.
/// </summary>
public sealed class KeyValueLine
{
    public const int MaxPairs = 256;

    private struct Entry
    {
        public int KeyStart, KeyLength, ValueStart, ValueLength;
        public bool Escaped;
        public KvField Field;
        public byte Priority;
        public string? Cached;
        public string? KeyString;
    }

    private Entry[] _entries = new Entry[32];

    public string Text { get; private set; } = string.Empty;
    public int Count { get; private set; }

    /// <summary>Words that were not part of a pair (free text between the pairs).</summary>
    public int BareTokens { get; internal set; }

    internal void Reset(string text)
    {
        Text = text;
        for (var i = 0; i < Count; i++)
        {
            _entries[i].Cached = null;
            _entries[i].KeyString = null;
        }
        Count = 0;
        BareTokens = 0;
    }

    internal void Add(int keyStart, int keyLength, int valueStart, int valueLength, bool escaped)
    {
        if (Count >= MaxPairs)
            return;
        if (Count == _entries.Length)
            Array.Resize(ref _entries, Math.Min(MaxPairs, _entries.Length * 2));
        var (field, priority) = KvAliases.Resolve(Text.AsSpan(keyStart, keyLength));
        _entries[Count++] = new Entry
        {
            KeyStart = keyStart, KeyLength = keyLength, ValueStart = valueStart, ValueLength = valueLength,
            Escaped = escaped, Field = field, Priority = priority
        };
    }

    /// <summary>Adds a pair that does not come from <see cref="Text"/> (JSON fields), with its field already resolved.</summary>
    internal void AddResolved(string key, string value, KvField field, byte priority)
    {
        if (Count >= MaxPairs)
            return;
        if (Count == _entries.Length)
            Array.Resize(ref _entries, Math.Min(MaxPairs, _entries.Length * 2));
        _entries[Count++] = new Entry
        {
            KeyString = key, Cached = value, ValueLength = value.Length, Field = field, Priority = priority
        };
    }

    public ReadOnlySpan<char> Key(int index) =>
        _entries[index].KeyString ?? Text.AsSpan(_entries[index].KeyStart, _entries[index].KeyLength);
    public KvField FieldAt(int index) => _entries[index].Field;
    public byte PriorityAt(int index) => _entries[index].Priority;

    public string Value(int index)
    {
        ref var e = ref _entries[index];
        if (e.Cached is not null)
            return e.Cached;
        var raw = Text.AsSpan(e.ValueStart, e.ValueLength);
        e.Cached = e.Escaped ? KeyValueReader.Unescape(raw) : raw.Length == 0 ? string.Empty : new string(raw);
        return e.Cached;
    }

    public int IndexOf(string key)
    {
        for (var i = 0; i < Count; i++)
            if (Key(i).Equals(key, StringComparison.OrdinalIgnoreCase))
                return i;
        return -1;
    }

    public bool Has(string key) => IndexOf(key) >= 0;

    /// <summary>Value of the first pair with this exact key (case-insensitive); null when missing or empty.</summary>
    public string? Get(string key)
    {
        var i = IndexOf(key);
        if (i < 0)
            return null;
        var v = Value(i);
        return v.Length == 0 ? null : v;
    }

    /// <summary>First non-empty value of the given keys.</summary>
    public string? GetFirst(params ReadOnlySpan<string> keys)
    {
        foreach (var k in keys)
            if (Get(k) is { } v)
                return v;
        return null;
    }

    /// <summary>Best value of a normalised field (lowest alias priority, then first in the line); null when missing.</summary>
    public string? Get(KvField field)
    {
        var best = -1;
        var bestPriority = 256;
        for (var i = 0; i < Count; i++)
        {
            if (_entries[i].Field == field && _entries[i].Priority < bestPriority && _entries[i].ValueLength > 0)
            {
                best = i;
                bestPriority = _entries[i].Priority;
            }
        }
        return best < 0 ? null : NullIfEmpty(Value(best));
    }

    /// <summary>The first value of <paramref name="field"/> (in priority order) that <paramref name="map"/> accepts.</summary>
    public T? GetMapped<T>(KvField field, Func<string, T?> map) where T : struct
    {
        int p = -1, i = -1;
        while (NextCandidate(field, ref p, ref i))
            if (map(Value(i)) is { } hit)
                return hit;
        return null;
    }

    /// <summary>Next entry of <paramref name="field"/> after (<paramref name="priority"/>, <paramref name="index"/>) in (priority, position) order.</summary>
    private bool NextCandidate(KvField field, ref int priority, ref int index)
    {
        int bestP = int.MaxValue, bestI = -1;
        for (var j = 0; j < Count; j++)
        {
            ref var e = ref _entries[j];
            if (e.Field != field || e.ValueLength == 0)
                continue;
            if (e.Priority < priority || (e.Priority == priority && j <= index))
                continue;
            if (e.Priority < bestP)
            {
                bestP = e.Priority;
                bestI = j;
            }
        }
        if (bestI < 0)
            return false;
        priority = bestP;
        index = bestI;
        return true;
    }

    /// <summary>Like <see cref="GetMapped{T}"/> for reference results.</summary>
    public string? GetMappedString(KvField field, Func<string, string?> map)
    {
        int p = -1, i = -1;
        while (NextCandidate(field, ref p, ref i))
            if (map(Value(i)) is { } hit)
                return hit;
        return null;
    }

    private static string? NullIfEmpty(string v) => v.Length == 0 || v == "-" ? null : v;
}

/// <summary>
/// Hand-written scanner for key=value lines (no regular expressions, linear time): <c>k=v</c>, <c>k="quoted \" value"</c>,
/// <c>k='v'</c>, Check Point <c>[k:"v"; k:"v"]</c>, comma separated <c>k=v, k=v</c> (Huawei), CEF extensions and LEEF
/// delimiters. Words that are not pairs are counted as <see cref="KeyValueLine.BareTokens"/> and skipped.
/// </summary>
public static class KeyValueReader
{
    /// <summary>Reads <paramref name="text"/> (from <paramref name="start"/>) into <paramref name="into"/>; returns the pair count.</summary>
    public static int Read(string text, KeyValueLine into, KvMode mode = KvMode.Spaces, char delimiter = '\t', int start = 0)
    {
        into.Reset(text);
        if (string.IsNullOrEmpty(text))
            return 0;
        if (mode == KvMode.Delimiter)
            ReadDelimited(text, into, delimiter, start);
        else
            ReadPairs(text, into, mode, start);
        return into.Count;
    }

    private static bool IsSeparator(char c, KvMode mode) =>
        char.IsWhiteSpace(c) || c is ',' or ';' or '[' or ']' or '(' or ')' or '{' or '}' || (c == '|' && mode != KvMode.UntilNextKey);

    private static bool IsKeyStart(char c) => char.IsAsciiLetter(c) || c is '_' or '@';

    private static bool IsKeyChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or '@' or '/' or '[' or ']';

    private static void ReadPairs(string s, KeyValueLine into, KvMode mode, int i)
    {
        var n = s.Length;
        while (i < n)
        {
            var c = s[i];
            if (IsSeparator(c, mode))
            {
                i++;
                continue;
            }
            if (!IsKeyStart(c))
            {
                i = SkipBare(s, i, mode, into);
                continue;
            }

            var keyStart = i;
            while (i < n && IsKeyChar(s[i]) && !(s[i] is '[' or ']' && mode != KvMode.UntilNextKey))
                i++;
            var keyLength = i - keyStart;
            var checkPointStyle = i + 1 < n && s[i] == ':' && (s[i + 1] == '"' || (s[i + 1] == ' ' && i + 2 < n && s[i + 2] == '"'));
            if (keyLength == 0 || keyLength > KvAliases.MaxKeyLength || i >= n || (s[i] != '=' && !checkPointStyle))
            {
                i = SkipBare(s, keyStart, mode, into);
                continue;
            }
            i++;   // '=' or ':'
            if (checkPointStyle && s[i] == ' ')
                i++;

            int valueStart, valueLength;
            var escaped = false;
            if (i < n && (s[i] == '"' || (s[i] == '\'' && mode != KvMode.UntilNextKey)))
            {
                var quote = s[i];
                valueStart = ++i;
                while (i < n && s[i] != quote)
                {
                    if (s[i] == '\\' && i + 1 < n)
                    {
                        escaped = true;
                        i++;
                    }
                    i++;
                }
                valueLength = i - valueStart;
                if (i < n)
                    i++;   // closing quote
            }
            else
            {
                valueStart = i;
                switch (mode)
                {
                    case KvMode.Comma:
                        while (i < n && s[i] != ',')
                            i++;
                        valueLength = TrimEnd(s, valueStart, i - valueStart);
                        // "Action=Block)" at the end of a Huawei message
                        if (valueLength > 0 && s[valueStart + valueLength - 1] == ')'
                            && s.AsSpan(valueStart, valueLength).IndexOf('(') < 0)
                            valueLength--;
                        break;
                    case KvMode.UntilNextKey:
                        i = ScanCefValue(s, valueStart, out valueLength, out escaped);
                        break;
                    default:
                        // Unquoted values keep backslashes as they are (Windows paths, user DOMAIN\name).
                        while (i < n && !char.IsWhiteSpace(s[i]))
                            i++;
                        valueLength = i - valueStart;
                        // "k=v, k2=v2" / "k=v;" / "[k=v]"
                        while (valueLength > 0 && s[valueStart + valueLength - 1] is ',' or ';' or ']')
                            valueLength--;
                        break;
                }
            }
            into.Add(keyStart, keyLength, valueStart, valueLength, escaped);
        }
    }

    private static int TrimEnd(string s, int start, int length)
    {
        while (length > 0 && char.IsWhiteSpace(s[start + length - 1]))
            length--;
        return length;
    }

    /// <summary>Skips a word that is not a pair (up to the next white space; in comma mode also up to a comma).</summary>
    private static int SkipBare(string s, int i, KvMode mode, KeyValueLine into)
    {
        into.BareTokens++;
        var n = s.Length;
        if (s[i] is '"' or '\'')
        {
            // A quoted phrase that is not a value ("GET / HTTP/1.1"): skip it as one word.
            var quote = s[i++];
            while (i < n && s[i] != quote)
                i += s[i] == '\\' ? 2 : 1;
            return Math.Min(n, i + 1);
        }
        while (i < n && !char.IsWhiteSpace(s[i]) && !(mode == KvMode.Comma && s[i] == ','))
            i++;
        return i;
    }

    /// <summary>
    /// CEF: the value ends at the white space before the next unescaped "key=" ("msg=Port scan detected src=1.2.3.4").
    /// An "=" with no white space since the value started belongs to the value (URLs).
    /// </summary>
    private static int ScanCefValue(string s, int start, out int length, out bool escaped)
    {
        escaped = false;
        var n = s.Length;
        var lastWhitespace = -1;
        for (var i = start; i < n; i++)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < n)
            {
                escaped = true;
                i++;
                continue;
            }
            if (char.IsWhiteSpace(c))
            {
                lastWhitespace = i;
                continue;
            }
            if (c == '=' && lastWhitespace >= start)
            {
                var keyStart = lastWhitespace + 1;
                var valid = keyStart < i && IsKeyStart(s[keyStart]);
                for (var k = keyStart; valid && k < i; k++)
                    valid = IsKeyChar(s[k]);
                if (valid)
                {
                    length = TrimEnd(s, start, lastWhitespace - start);
                    return lastWhitespace;
                }
            }
        }
        length = TrimEnd(s, start, n - start);
        return n;
    }

    private static void ReadDelimited(string s, KeyValueLine into, char delimiter, int i)
    {
        var n = s.Length;
        while (i < n)
        {
            var end = s.IndexOf(delimiter, i);
            if (end < 0)
                end = n;
            var eq = s.IndexOf('=', i, end - i);
            if (eq > i)
            {
                var ks = i;
                var kl = eq - i;
                while (kl > 0 && char.IsWhiteSpace(s[ks])) { ks++; kl--; }
                while (kl > 0 && char.IsWhiteSpace(s[ks + kl - 1])) kl--;
                var vs = eq + 1;
                var vl = end - vs;
                var escaped = s.AsSpan(vs, vl).IndexOf('\\') >= 0;
                if (kl > 0 && kl <= KvAliases.MaxKeyLength)
                    into.Add(ks, kl, vs, TrimEnd(s, vs, vl), escaped);
            }
            else if (end > i)
            {
                into.BareTokens++;
            }
            i = end + 1;
        }
    }

    /// <summary>Removes backslash escapes (<c>\"</c>, <c>\\</c>, <c>\=</c>, <c>\|</c>); <c>\n</c>, <c>\r</c>, <c>\t</c> become spaces.</summary>
    public static string Unescape(ReadOnlySpan<char> raw)
    {
        var sb = new StringBuilder(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            var c = raw[i];
            if (c == '\\' && i + 1 < raw.Length)
            {
                var next = raw[++i];
                sb.Append(next is 'n' or 'r' or 't' ? ' ' : next);
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}
