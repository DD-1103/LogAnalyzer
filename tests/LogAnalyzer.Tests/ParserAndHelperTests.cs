using LogAnalyzer.Web.Helpers;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tests;

public class CombinedLogParserTests
{
    private readonly CombinedLogParser _parser = new();

    [Fact]
    public void Parses_combined_format()
    {
        const string line = "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326 \"http://www.example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\"";

        Assert.True(_parser.TryParse(line, out var p));
        Assert.Equal("127.0.0.1", p!.ClientIp);
        Assert.Equal(new DateTimeOffset(2000, 10, 10, 13, 55, 36, TimeSpan.FromHours(-7)), p.Timestamp);
        Assert.Equal("GET", p.Method);
        Assert.Equal("/apache_pb.gif", p.Url);
        Assert.Equal("HTTP/1.0", p.Protocol);
        Assert.Equal(200, p.StatusCode);
        Assert.Equal(2326, p.ResponseSize);
        Assert.Equal("http://www.example.com/start.html", p.Referrer);
        Assert.Equal("Mozilla/4.08 [en] (Win98; I ;Nav)", p.UserAgent);
    }

    [Fact]
    public void Parses_common_format_without_referrer_and_agent()
    {
        Assert.True(_parser.TryParse("10.0.0.5 - - [01/Jan/2026:00:00:01 +0000] \"POST /login HTTP/1.1\" 302 -", out var p));
        Assert.Equal(302, p!.StatusCode);
        Assert.Null(p.ResponseSize);
        Assert.Null(p.Referrer);
        Assert.Null(p.UserAgent);
    }

    [Fact]
    public void Handles_escaped_quotes_in_user_agent()
    {
        const string line = "1.2.3.4 - - [01/Jan/2026:00:00:01 +0100] \"GET / HTTP/1.1\" 200 10 \"-\" \"evil\\\" <script>\"";
        Assert.True(_parser.TryParse(line, out var p));
        Assert.Equal("evil\\\" <script>", p!.UserAgent);
        Assert.Null(p.Referrer);
    }

    [Fact]
    public void Keeps_malformed_request_lines_from_scanners()
    {
        Assert.True(_parser.TryParse("1.2.3.4 - - [01/Jan/2026:00:00:01 +0000] \"\\x16\\x03\\x01\" 400 0 \"-\" \"-\"", out var p));
        Assert.Equal("-", p!.Method);
        Assert.Equal(400, p.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a log line")]
    [InlineData("1.2.3.4 - - [99/Foo/2026:00:00:01 +0000] \"GET / HTTP/1.1\" 200 1")]
    public void Rejects_invalid_lines(string line) => Assert.False(_parser.TryParse(line, out _));
}

public class UrlDecoderTests
{
    [Theory]
    [InlineData("/a?id=1%27%20OR%201%3D1", "/a?id=1' OR 1=1")]
    [InlineData("/a?q=union+select", "/a?q=union select")]
    [InlineData("%252e%252e%252fetc%252fpasswd", "../etc/passwd")]
    [InlineData("/plain/path", "/plain/path")]
    [InlineData(null, "")]
    public void Decodes_up_to_twice(string? input, string expected) => Assert.Equal(expected, UrlDecoder.Decode(input));
}

public class CsvEscapingTests
{
    [Theory]
    [InlineData("=HYPERLINK(\"http://evil\")", "\"'=HYPERLINK(\"\"http://evil\"\")\"")]
    [InlineData("+1", "\"'+1\"")]
    [InlineData("-2", "\"'-2\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("normal text", "\"normal text\"")]
    [InlineData(null, "\"\"")]
    public void Neutralises_formulas_and_quotes(string? input, string expected) => Assert.Equal(expected, Format.Csv(input));
}

public class IsPublicTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("185.220.101.45", true)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.56.101", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("not-an-ip", false)]
    public void Only_public_addresses_may_leave_the_machine(string ip, bool expected) =>
        Assert.Equal(expected, IpEnrichmentService.IsPublic(ip));
}

public class MetricsTests
{
    [Fact]
    public void Computes_standard_metrics()
    {
        var m = new Metrics("x", TP: 90, FP: 10, FN: 30, TN: 870);
        Assert.Equal(0.9, m.Precision, 6);
        Assert.Equal(0.75, m.Recall, 6);
        Assert.Equal(2 * 0.9 * 0.75 / 1.65, m.F1, 6);
        Assert.Equal(10.0 / 880, m.FalsePositiveRate, 6);
        Assert.Equal(0.96, m.Accuracy, 6);
    }

    [Fact]
    public void Empty_confusion_matrix_gives_zeros_not_NaN()
    {
        var m = new Metrics("x", 0, 0, 0, 0);
        Assert.Equal(0, m.Precision);
        Assert.Equal(0, m.Recall);
        Assert.Equal(0, m.F1);
    }

    [Fact]
    public void Parses_labels_file_and_skips_header()
    {
        using var csv = new MemoryStream("line,label\n1,normal\n2, sqli \n3,\"xss\"\nbad,row\n"u8.ToArray());
        var labels = EvaluationService.ParseLabels(csv);
        Assert.Equal(3, labels.Count);
        Assert.Equal("sqli", labels[2]);
        Assert.Equal("xss", labels[3]);
    }
}
