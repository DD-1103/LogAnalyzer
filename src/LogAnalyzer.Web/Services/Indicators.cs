using System.Globalization;
using System.Text.RegularExpressions;
using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>A normalised indicator of compromise: lower-case, canonical IP form, punycode domain, lower-case hex hash.</summary>
public sealed record Indicator(IndicatorType Type, string Value)
{
    public static Indicator ForIp(string ip) => new(IndicatorType.Ip, ip);

    /// <summary>MD5, SHA-1 or SHA-256 for hashes; "IP address" / "Domain" otherwise.</summary>
    public string Label => Type switch
    {
        IndicatorType.Ip => "IP address",
        IndicatorType.Domain => "Domain",
        IndicatorType.Hash => Value.Length switch { 32 => "MD5 hash", 40 => "SHA-1 hash", _ => "SHA-256 hash" },
        _ => Type.ToString()
    };
}

/// <summary>
/// Turns what an analyst typed into an <see cref="Indicator"/> and decides whether it may be sent to external
/// services. Accepts defanged input (example[.]com, hxxps://...) and full URLs (the host is looked up).
/// </summary>
public static partial class IndicatorParser
{
    public const string Help = "Enter an IP address, a domain (example.com) or a file hash (MD5, SHA-1 or SHA-256).";

    // Names that only exist inside a network (RFC 6761 / 6762 / 8375 and common private suffixes).
    private static readonly string[] InternalSuffixes =
    [
        "local", "localhost", "internal", "intranet", "lan", "home", "home.arpa", "corp", "private",
        "localdomain", "test", "example", "invalid", "arpa"
    ];

    [GeneratedRegex("^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", RegexOptions.CultureInvariant)]
    private static partial Regex HashRegex();

    // Labels of letters, digits and inner hyphens; a top-level domain of letters (or punycode xn--).
    [GeneratedRegex(@"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    public static bool TryParse(string? raw, out Indicator indicator, out string error)
    {
        indicator = null!;
        error = Help;
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 2048)
            return false;

        var text = Refang(raw.Trim());

        // A pasted URL: look up its host.
        if (text.Contains("://", StringComparison.Ordinal)
            && Uri.TryCreate(text, UriKind.Absolute, out var uri)
            && uri.Scheme is "http" or "https" or "ftp")
            text = uri.IdnHost.Trim('[', ']');

        // IP address: full dotted quad for IPv4 ("1.2" would otherwise parse as 1.0.0.2), any valid IPv6.
        if ((text.Contains('.') || text.Contains(':')) && System.Net.IPAddress.TryParse(text, out var address)
            && (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || text.Count(c => c == '.') == 3))
        {
            indicator = Indicator.ForIp(IpAddressPolicy.Canonical(text));
            return true;
        }

        var lower = text.ToLowerInvariant();
        if (HashRegex().IsMatch(lower))
        {
            indicator = new Indicator(IndicatorType.Hash, lower);
            return true;
        }

        var domain = lower.TrimEnd('.');
        if (domain.StartsWith("*.", StringComparison.Ordinal))
            domain = domain[2..];
        try
        {
            domain = new IdnMapping().GetAscii(domain);
        }
        catch (ArgumentException)
        {
            return false;
        }
        if (DomainRegex().IsMatch(domain))
        {
            indicator = new Indicator(IndicatorType.Domain, domain);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Whether the indicator may leave the machine. Private/reserved IPs and internal host names never do
    /// (also the organisation's own domains listed in Enrichment:InternalDomains). Hashes are not personal data.
    /// </summary>
    public static bool MaySend(Indicator indicator, IEnumerable<string>? internalDomains, out string reason)
    {
        reason = string.Empty;
        switch (indicator.Type)
        {
            case IndicatorType.Ip when !IpAddressPolicy.IsPublic(indicator.Value):
                reason = "Private or reserved address - never sent to external services";
                return false;
            case IndicatorType.Domain when IsInternalDomain(indicator.Value, internalDomains):
                reason = "Internal host name - never sent to external services";
                return false;
            default:
                return true;
        }
    }

    public static bool IsInternalDomain(string domain, IEnumerable<string>? internalDomains)
    {
        bool Under(string suffix)
        {
            suffix = suffix.Trim().TrimStart('.').ToLowerInvariant();
            return suffix.Length > 0 && (domain == suffix || domain.EndsWith("." + suffix, StringComparison.Ordinal));
        }
        return InternalSuffixes.Any(Under) || (internalDomains?.Any(Under) ?? false);
    }

    /// <summary>Undoes common defanging: hxxp, [.], (.), {.}, [dot], [:] and [@].</summary>
    public static string Refang(string value) => value
        .Replace("hxxps", "https", StringComparison.OrdinalIgnoreCase)
        .Replace("hxxp", "http", StringComparison.OrdinalIgnoreCase)
        .Replace("[.]", ".").Replace("(.)", ".").Replace("{.}", ".")
        .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase)
        .Replace("[:]", ":").Replace("[://]", "://")
        .Replace("[@]", "@");
}
