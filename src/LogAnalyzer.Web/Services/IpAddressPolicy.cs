using System.Net;
using System.Net.Sockets;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Decides which client addresses may be sent to external services (threat-intel providers). Only globally routable
/// unicast addresses qualify; everything private, reserved, documentation, translation or tunnel-related stays on
/// this machine. IPv4-mapped IPv6 (<c>::ffff:10.0.0.5</c>, written by dual-stack servers) is judged as IPv4.
/// </summary>
public static class IpAddressPolicy
{
    private static readonly (IPAddress Network, int Prefix)[] BlockedV4 =
    [
        (IPAddress.Parse("0.0.0.0"), 8),        // "this network"
        (IPAddress.Parse("10.0.0.0"), 8),       // private
        (IPAddress.Parse("100.64.0.0"), 10),    // carrier-grade NAT
        (IPAddress.Parse("127.0.0.0"), 8),      // loopback
        (IPAddress.Parse("169.254.0.0"), 16),   // link-local
        (IPAddress.Parse("172.16.0.0"), 12),    // private
        (IPAddress.Parse("192.0.0.0"), 24),     // IETF protocol assignments
        (IPAddress.Parse("192.0.2.0"), 24),     // documentation TEST-NET-1
        (IPAddress.Parse("192.88.99.0"), 24),   // 6to4 relay anycast (deprecated)
        (IPAddress.Parse("192.168.0.0"), 16),   // private
        (IPAddress.Parse("198.18.0.0"), 15),    // benchmarking
        (IPAddress.Parse("198.51.100.0"), 24),  // documentation TEST-NET-2
        (IPAddress.Parse("203.0.113.0"), 24),   // documentation TEST-NET-3
        (IPAddress.Parse("224.0.0.0"), 3)       // multicast, reserved, broadcast (224.0.0.0 - 255.255.255.255)
    ];

    private static readonly (IPAddress Network, int Prefix)[] BlockedV6InsideGlobal =
    [
        (IPAddress.Parse("2001::"), 23),        // IETF special purpose (Teredo, benchmarking, ORCHID, ...)
        (IPAddress.Parse("2001:db8::"), 32),    // documentation
        (IPAddress.Parse("2002::"), 16),        // 6to4: embeds an IPv4 address (possibly private)
        (IPAddress.Parse("3fff::"), 20)         // documentation (RFC 9637)
    ];

    private static readonly (IPAddress Network, int Prefix) GlobalUnicastV6 = (IPAddress.Parse("2000::"), 3);

    /// <summary>
    /// Returns true and the canonical text form (what providers receive) when <paramref name="raw"/> is a public
    /// unicast address. Unparseable input, private and reserved addresses return false.
    /// </summary>
    public static bool TryGetPublic(string? raw, out string canonical)
    {
        canonical = string.Empty;
        if (string.IsNullOrWhiteSpace(raw) || !IPAddress.TryParse(raw.Trim(), out var address))
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (BlockedV4.Any(b => InRange(address, b.Network, b.Prefix)))
                return false;
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address.ScopeId = 0;
            if (!InRange(address, GlobalUnicastV6.Network, GlobalUnicastV6.Prefix)
                || BlockedV6InsideGlobal.Any(b => InRange(address, b.Network, b.Prefix)))
                return false;
        }
        else
        {
            return false;
        }

        canonical = address.ToString();
        return true;
    }

    public static bool IsPublic(string? ip) => TryGetPublic(ip, out _);

    /// <summary>
    /// Canonical text of an IP address as written in a log (lower-case, compressed IPv6; IPv4-mapped IPv6 as IPv4;
    /// no zone id). Anything that is not an IP address (e.g. a host name) is returned unchanged.
    /// </summary>
    public static string Canonical(string raw)
    {
        if (raw.Length is 0 or > 64 || !(raw.Contains('.') || raw.Contains(':')) || !IPAddress.TryParse(raw, out var address))
            return raw;
        // TryParse also reads "1.2" as 1.0.0.2: only full dotted quads count as IPv4.
        if (address.AddressFamily == AddressFamily.InterNetwork && raw.Count(c => c == '.') != 3)
            return raw;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            address.ScopeId = 0;
        return address.ToString();
    }

    private static bool InRange(IPAddress address, IPAddress network, int prefix)
    {
        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length)
            return false;
        var fullBytes = prefix / 8;
        for (var i = 0; i < fullBytes; i++)
            if (a[i] != n[i])
                return false;
        var rest = prefix % 8;
        if (rest == 0)
            return true;
        var mask = (byte)(0xFF << (8 - rest));
        return (a[fullBytes] & mask) == (n[fullBytes] & mask);
    }
}
