using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Tests;

public class SyslogEnvelopeTests
{
    private static readonly LogParseContext Ctx = new(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), TimeSpan.FromHours(1));

    [Fact]
    public void Rfc5424_reads_host_app_msgid_and_structured_data()
    {
        var env = SyslogEnvelope.Parse(
            "<14>1 2026-11-21T10:00:00Z srx01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 source-address=\"203.0.113.5\"] session denied", Ctx);
        Assert.Equal(14, env.Priority);
        Assert.Equal("srx01", env.Host);
        Assert.Equal("RT_FLOW", env.AppName);
        Assert.Equal("RT_FLOW_SESSION_DENY", env.MsgId);
        Assert.StartsWith("[junos@2636", env.StructuredData);
        Assert.Equal("session denied", env.Message);
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero), env.Timestamp);
    }

    [Fact]
    public void Rfc5424_without_msgid_gives_null()
    {
        var env = SyslogEnvelope.Parse("<134>1 2026-11-21T10:00:00Z fw01 app 1 - - hello", Ctx);
        Assert.Null(env.MsgId);
        Assert.Equal("hello", env.Message);
    }

    [Fact]
    public void Bsd_header_with_host_and_tag()
    {
        var env = SyslogEnvelope.Parse("<134>Nov 21 10:00:00 gw01 kernel: [UFW BLOCK] IN=eth0", Ctx);
        Assert.Equal("gw01", env.Host);
        Assert.Equal("kernel", env.AppName);
        Assert.Equal("[UFW BLOCK] IN=eth0", env.Message);
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.FromHours(1)), env.Timestamp);
    }

    [Fact]
    public void Cisco_priority_colon_and_utc_zone_word()
    {
        var env = SyslogEnvelope.Parse("<166>:Nov 21 10:00:00 UTC: %ASA-4-106023: Deny tcp src outside:203.0.113.5/51234", Ctx);
        Assert.Equal(166, env.Priority);
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero), env.Timestamp);
        Assert.StartsWith("%ASA-4-106023:", env.Message);
        Assert.Null(env.AppName);
    }

    [Fact]
    public void Cisco_year_timestamp_with_host()
    {
        var env = SyslogEnvelope.Parse("Nov 21 2026 10:00:00 asa01 : %ASA-6-302013: Built inbound TCP connection", Ctx);
        Assert.Equal("asa01", env.Host);
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.FromHours(1)), env.Timestamp);
        Assert.Contains("%ASA-6-302013", env.Message);
    }

    [Fact]
    public void Cef_after_host_is_not_a_tag()
    {
        var env = SyslogEnvelope.Parse("Nov 21 10:00:00 fw01 CEF:0|Vendor|Product|1|100|Name|5|src=203.0.113.5", Ctx);
        Assert.Equal("fw01", env.Host);
        Assert.StartsWith("CEF:0|", env.Message);
    }

    [Fact]
    public void Line_without_header_is_the_whole_message()
    {
        const string line = "date=2026-11-21 time=10:00:00 devname=\"fw01\"";
        var env = SyslogEnvelope.Parse(line, Ctx);
        Assert.Null(env.Timestamp);
        Assert.Equal(line, env.Message);
    }
}
