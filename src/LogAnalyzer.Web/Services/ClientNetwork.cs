using System.Net;
using System.Net.Sockets;

namespace LogAnalyzer.Web.Services;

/// <summary>Helpers for the client address of an HTTP request (rate limiting, audit).</summary>
public static class ClientNetwork
{
    /// <summary>
    /// Key for per-client rate limiting. IPv4-mapped IPv6 addresses count as their IPv4 address, and IPv6 clients
    /// are grouped by their /64 prefix (one end user usually owns a whole /64, so per-address limits are easy to dodge).
    /// </summary>
    public static string RateLimitKey(IPAddress? address)
    {
        if (address is null)
            return "unknown";
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return address.ToString();

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }
}
