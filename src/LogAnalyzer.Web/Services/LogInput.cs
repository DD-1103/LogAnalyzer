using System.Text;

namespace LogAnalyzer.Web.Services;

/// <summary>Limits for one uploaded log file (configuration section "Processing").</summary>
public sealed class ProcessingOptions
{
    public const string Section = "Processing";

    /// <summary>Maximum size after gzip decompression (protects against gzip bombs). Default 2 GiB.</summary>
    public long MaxDecompressedBytes { get; set; } = 2L * 1024 * 1024 * 1024;

    /// <summary>Maximum ratio decompressed / compressed size. Normal access logs compress about 10-20x.</summary>
    public int MaxCompressionRatio { get; set; } = 50;

    /// <summary>Maximum number of lines per file (RQ3 needs 2M; the default leaves room).</summary>
    public int MaxLines { get; set; } = 5_000_000;

    /// <summary>Longer lines are not parsed (counted as failed); their rest is skipped without being stored in memory.</summary>
    public int MaxLineLength { get; set; } = 16 * 1024;

    /// <summary>Time budget for the threat-intel step of one file (best effort, after the file is Completed).</summary>
    public int ThreatIntelBudgetMinutes { get; set; } = 10;

    /// <summary>A file whose processing was interrupted this many times (app stopped or crashed) is marked Failed.</summary>
    public int MaxAttempts { get; set; } = 3;
}

/// <summary>A log file exceeded one of the <see cref="ProcessingOptions"/> limits. The message is shown to users.</summary>
public sealed class LogLimitExceededException(string message) : Exception(message);

/// <summary>Read-only stream wrapper that throws once more than <paramref name="maxBytes"/> bytes were read.</summary>
public sealed class LimitedReadStream(Stream inner, long maxBytes, string limitMessage) : Stream
{
    public long BytesRead { get; private set; }

    public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));

    public override int Read(Span<byte> buffer) => Count(inner.Read(buffer));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        Count(await inner.ReadAsync(buffer, ct));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    private int Count(int read)
    {
        BytesRead += read;
        if (BytesRead > maxBytes)
            throw new LogLimitExceededException(limitMessage);
        return read;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            inner.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>One line from <see cref="BoundedLineReader"/>. <see cref="TooLong"/> lines carry only their first characters.</summary>
public readonly record struct BoundedLine(string Text, bool TooLong);

/// <summary>
/// Line reader with a maximum line length. Unlike <see cref="StreamReader.ReadLineAsync()"/> it never builds a
/// string longer than the limit: the rest of an over-long line is skipped. Line ends: \n, \r\n and \r.
/// </summary>
public sealed class BoundedLineReader(TextReader reader, int maxLength) : IDisposable
{
    private readonly char[] _buffer = new char[64 * 1024];
    private readonly StringBuilder _line = new();
    private int _pos, _len;
    private bool _skipLf, _eof;

    public async ValueTask<BoundedLine?> ReadLineAsync(CancellationToken ct)
    {
        _line.Clear();
        var tooLong = false;
        var any = false;
        while (true)
        {
            if (_pos == _len)
            {
                if (_eof)
                    return any ? new BoundedLine(_line.ToString(), tooLong) : null;
                _len = await reader.ReadAsync(_buffer.AsMemory(), ct);
                _pos = 0;
                if (_len == 0)
                {
                    _eof = true;
                    continue;
                }
            }

            if (_skipLf)
            {
                _skipLf = false;
                if (_buffer[_pos] == '\n')
                {
                    _pos++;
                    continue;
                }
            }

            // Copy up to the next line end (or the end of the buffer).
            var start = _pos;
            while (_pos < _len && _buffer[_pos] is not ('\n' or '\r'))
                _pos++;
            var chunk = _pos - start;
            if (chunk > 0)
            {
                any = true;
                var room = maxLength - _line.Length;
                if (chunk > room)
                    tooLong = true;
                if (room > 0)
                    _line.Append(_buffer, start, Math.Min(chunk, room));
            }

            if (_pos < _len)
            {
                _skipLf = _buffer[_pos] == '\r';
                _pos++;
                return new BoundedLine(_line.ToString(), tooLong);
            }
        }
    }

    public void Dispose() => reader.Dispose();
}
