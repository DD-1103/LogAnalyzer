using System.Globalization;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Destination-port filter of a firewall rule, parsed from text like "22, 23,3389,5900-5902".
/// Lookups are O(1) (a 65,536-bit set), so a rule with many ports costs the same as one with a single port.
/// </summary>
public sealed class PortSet
{
    /// <summary>Most ports / ranges one filter may list (keeps the text readable and the column small).</summary>
    public const int MaxEntries = 200;

    private readonly ulong[] _bits = new ulong[65536 / 64];
    private readonly List<string> _entries = [];

    private PortSet() { }

    /// <summary>The entries as written (trimmed), e.g. ["22", "5900-5902"].</summary>
    public IReadOnlyList<string> Entries => _entries;

    public bool Contains(int port) =>
        port is >= 0 and <= 65535 && (_bits[port >> 6] & (1UL << (port & 63))) != 0;

    /// <summary>An event without a destination port never matches a port filter.</summary>
    public bool Contains(int? port) => port is int p && Contains(p);

    /// <summary>Canonical text: entries joined by commas without spaces.</summary>
    public override string ToString() => string.Join(",", _entries);

    /// <summary>
    /// Parses a port filter. Blank text means "any port" (returns true with <paramref name="set"/> = null).
    /// Empty entries (e.g. a trailing comma) are ignored.
    /// </summary>
    public static bool TryParse(string? text, out PortSet? set, out string? error)
    {
        set = null;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var result = new PortSet();
        foreach (var raw in text.Split(','))
        {
            var entry = raw.Trim();
            if (entry.Length == 0)
                continue;
            if (result._entries.Count == MaxEntries)
            {
                error = $"Port filter: at most {MaxEntries} ports or ranges.";
                return false;
            }

            var dash = entry.IndexOf('-');
            int from, to;
            if (dash < 0)
            {
                if (!TryPort(entry, out from))
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a port (use numbers 0-65535 or ranges like 5900-5902).";
                    return false;
                }
                to = from;
                result._entries.Add(from.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                var a = entry[..dash].Trim();
                var b = entry[(dash + 1)..].Trim();
                if (!TryPort(a, out from) || !TryPort(b, out to))
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a port range (use numbers 0-65535, e.g. 5900-5902).";
                    return false;
                }
                if (from > to)
                {
                    error = $"Port filter: '{Shorten(entry)}' is not a valid range (the first port must not be larger than the second).";
                    return false;
                }
                result._entries.Add(from == to
                    ? from.ToString(CultureInfo.InvariantCulture)
                    : $"{from.ToString(CultureInfo.InvariantCulture)}-{to.ToString(CultureInfo.InvariantCulture)}");
            }

            for (var p = from; p <= to; p++)
                result._bits[p >> 6] |= 1UL << (p & 63);
        }

        if (result._entries.Count == 0)
            return true; // only separators: same as blank
        set = result;
        return true;
    }

    private static bool TryPort(string s, out int port) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port <= 65535;

    private static string Shorten(string s) => s.Length <= 40 ? s : s[..40] + "…";
}

/// <summary>Firewall-action filter of a rule, parsed from text like "Deny,Drop,Reject" (names are case-insensitive).</summary>
public sealed class ActionSet
{
    private readonly int _mask;

    private ActionSet(int mask, List<FirewallAction> actions)
    {
        _mask = mask;
        Actions = actions;
    }

    /// <summary>The actions in enum order, without duplicates.</summary>
    public IReadOnlyList<FirewallAction> Actions { get; }

    /// <summary>An event without an action counts as <see cref="FirewallAction.Unknown"/>.</summary>
    public bool Contains(FirewallAction? action) => (_mask & (1 << (int)(action ?? FirewallAction.Unknown))) != 0;

    /// <summary>Canonical text, e.g. "Deny,Drop,Reject".</summary>
    public override string ToString() => string.Join(",", Actions);

    /// <summary>All action names an admin may use.</summary>
    public static string AllowedNames => string.Join(", ", Enum.GetNames<FirewallAction>());

    /// <summary>Parses an action filter. Blank text means "any action" (returns true with <paramref name="set"/> = null).</summary>
    public static bool TryParse(string? text, out ActionSet? set, out string? error)
    {
        set = null;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var mask = 0;
        foreach (var raw in text.Split(','))
        {
            var token = raw.Trim();
            if (token.Length == 0)
                continue;
            // Names only: Enum.TryParse would also accept numbers ("2") and combinations.
            if (!token.All(char.IsAsciiLetter) || !Enum.TryParse<FirewallAction>(token, ignoreCase: true, out var action)
                || !Enum.IsDefined(action))
            {
                var shown = token.Length <= 40 ? token : token[..40] + "…";
                error = $"Action filter: '{shown}' is not a firewall action ({AllowedNames}).";
                return false;
            }
            mask |= 1 << (int)action;
        }

        if (mask == 0)
            return true;
        var actions = Enum.GetValues<FirewallAction>().Where(a => (mask & (1 << (int)a)) != 0).ToList();
        set = new ActionSet(mask, actions);
        return true;
    }
}
