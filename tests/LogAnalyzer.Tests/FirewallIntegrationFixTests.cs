using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

/// <summary>Fixes found when running generate-firewall output through the merged parsers (2026-11-22).</summary>
public class FirewallIntegrationFixTests
{
    private static readonly LogParseContext Ctx = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.Zero);

    private static ParsedLine Parse(string formatId, string line)
    {
        var parser = LogFormatRegistry.Find(formatId)!.CreateParser(Ctx);
        Assert.Equal(ParseOutcome.Parsed, parser.Parse(line, out var p));
        return p!;
    }

    [Fact]
    public void Asa_302020_inbound_icmp_is_allowed_from_the_foreign_host()
    {
        var p = Parse("cisco-asa", "Nov 21 2026 10:00:00 asa01 : %ASA-6-302020: Built inbound ICMP connection for faddr 203.0.113.5/0 gaddr 10.0.0.5/0 laddr 10.0.0.5/0 type 8 code 0");
        Assert.Equal("203.0.113.5", p.ClientIp);
        Assert.Equal("10.0.0.5", p.DestinationIp);
        Assert.Equal("icmp", p.Transport);
        Assert.Equal(FirewallAction.Allow, p.Action);
    }

    [Fact]
    public void Asa_302020_outbound_icmp_starts_at_the_local_host()
    {
        var p = Parse("cisco-asa", "Nov 21 2026 10:00:00 asa01 : %ASA-6-302020: Built outbound ICMP connection for faddr 198.51.100.7/0 gaddr 10.0.0.250/0 laddr 10.0.0.250/0 type 8 code 0");
        Assert.Equal("10.0.0.250", p.ClientIp);
        Assert.Equal("198.51.100.7", p.DestinationIp);
    }

    [Theory]
    [InlineData("Nov 21 10:00:00 gw01 sshd[2211]: Failed password for invalid user admin from 203.0.113.118 port 44456 ssh2", FirewallAction.Deny, "admin")]
    [InlineData("Nov 21 10:00:00 gw01 sshd[2211]: Failed password for root from 203.0.113.118 port 44456 ssh2", FirewallAction.Deny, "root")]
    [InlineData("Nov 21 10:00:00 gw01 sshd[2211]: Invalid user test from 203.0.113.118 port 44456", FirewallAction.Deny, "test")]
    [InlineData("Nov 21 10:00:00 gw01 sshd[2211]: Accepted publickey for ops from 203.0.113.118 port 44456 ssh2", FirewallAction.Allow, "ops")]
    public void Sshd_logins_in_a_gateway_syslog_are_auth_events(string line, FirewallAction action, string user)
    {
        var p = Parse("netfilter", line);
        Assert.Equal("203.0.113.118", p.ClientIp);
        Assert.Equal(action, p.Action);
        Assert.Equal("auth", p.EventType);
        Assert.Equal(22, p.DestinationPort);
        Assert.Contains(user, p.Url);
        Assert.Equal("gw01", p.Device);
    }

    [Fact]
    public void Other_sshd_lines_are_skipped_and_other_programs_fail()
    {
        var parser = LogFormatRegistry.Find("netfilter")!.CreateParser(Ctx);
        Assert.Equal(ParseOutcome.Skipped, parser.Parse("Nov 21 10:00:00 gw01 sshd[2211]: Connection closed by 203.0.113.118 port 44456 [preauth]", out _));
        Assert.Equal(ParseOutcome.Failed, parser.Parse("Nov 21 10:00:00 gw01 cron[99]: (root) CMD (run-parts /etc/cron.hourly) sshd", out _));
    }
}
