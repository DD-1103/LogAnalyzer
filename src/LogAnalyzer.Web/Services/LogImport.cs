using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services.LogFormats;

namespace LogAnalyzer.Web.Services;

/// <summary>Decisions of the import (which format, readable or not) and the texts shown for it; pure and unit-tested.</summary>
public static class LogImport
{
    /// <summary>Detection looks at most this far into a file that starts with lines no format can read.</summary>
    public const int MaxSampleLines = LogFormatDetector.SampleLines * 10;
    private const int MaxSampleChars = 4 * 1024 * 1024;
    private const int MaxHeaderLines = 20;

    /// <summary>
    /// Detects the format from the first lines. When nothing is recognised there (the output of another program in
    /// front of the log), the next block of lines is tried. Comments ("# ...") are never events and do not count;
    /// W3C directives ("#Fields: ...") are kept for every block, because some formats describe their columns in them.
    /// </summary>
    public static async Task<FormatDetection> DetectAsync(BoundedLineReader reader, LogParseContext context, CancellationToken ct)
    {
        var header = new List<string>();
        var block = new List<string>(LogFormatDetector.SampleLines);
        int lines = 0, chars = 0;
        var end = false;
        while (!end && lines < MaxSampleLines && chars < MaxSampleChars)
        {
            block.Clear();
            while (block.Count < LogFormatDetector.SampleLines && chars < MaxSampleChars)
            {
                // Blank lines count towards the characters, so a file of blank lines ends the search as well.
                if (await reader.ReadLineAsync(ct) is not { } line)
                {
                    end = true;
                    break;
                }
                chars += line.Text.Length + 1;
                if (line.TooLong || string.IsNullOrWhiteSpace(line.Text))
                    continue;
                if (line.Text[0] != '#')
                    block.Add(line.Text);
                else if (header.Count < MaxHeaderLines && line.Text.Length > 1 && char.IsLetter(line.Text[1]) && line.Text.Contains(':'))
                    header.Add(line.Text);
            }
            lines += block.Count;
            if (block.Count == 0)
                break;

            var detection = LogFormatDetector.Detect([.. header, .. block], context);
            if (detection.Format is not null)
                return detection;
        }
        return new FormatDetection(null, 0, 0);
    }

    /// <summary>
    /// A file of which no line could be read is Failed with this message instead of "Completed" with 0 events.
    /// Null when lines were read, or when there were none to read (blank lines, headers and comments only).
    /// </summary>
    public static string? FailureMessage(int totalLines, int parsedLines, ILogFormat? requested, ILogFormat? looksLike = null)
    {
        if (parsedLines > 0 || totalLines == 0)
            return null;
        var count = totalLines == 1 ? "The only line" : $"None of the {totalLines:N0} lines";
        var could = totalLines == 1 ? "could not be read" : "could be read";
        if (requested is null)
            return $"The log format was not recognised. {count} {could}. Upload the file again and choose its log format " +
                   "(the upload page lists the supported formats).";
        var hint = looksLike is not null && looksLike.Id != requested.Id ? $" The file looks like: {looksLike.DisplayName}." : "";
        return $"{count} {could} as {requested.DisplayName}, the log format chosen on upload.{hint} " +
               "Upload the file again with another log format or with automatic detection.";
    }

    /// <summary>Explanation for a completed file with no events or with mostly unreadable lines (null = nothing to say).</summary>
    public static string? Notice(LogFile file)
    {
        if (file.Status != LogFileStatus.Completed)
            return null;
        if (file.TotalLines == 0)
            return "The file contains no events: it is empty or has only blank lines, headers, comments or device messages without a connection.";
        if (file.ParsedLines == 0)
            return "No line of this file could be read, so no rule ran on it. Upload it again and choose its log format.";
        if (file.FailedLines > file.ParsedLines)
            return $"Only {file.ParsedLines:N0} of {file.TotalLines:N0} lines could be read as {FormatLabel(file)}. " +
                   "If this is another kind of log, upload it again and choose its log format.";
        return null;
    }

    /// <summary>
    /// Format shown for a file, null when none is known. Files imported before formats were stored have no format text;
    /// their events can only come from the access-log parser.
    /// </summary>
    public static string? FormatLabel(LogFile file) =>
        file.Format ?? (file is { ParsedLines: > 0, Source: LogSource.WebAccess }
            ? LogFormatRegistry.Find(WebAccessLogFormat.FormatId)!.DisplayName
            : null);

    /// <summary>Lines were processed, but none was understood.</summary>
    public static bool NotRecognised(LogFile file) =>
        file.Status is LogFileStatus.Completed or LogFileStatus.Failed && FormatLabel(file) is null
        && file is { TotalLines: > 0, ParsedLines: 0 };

    /// <summary>
    /// Highest line number a ground-truth label can have. TotalLines counts only events and unreadable lines (not blank
    /// lines, headers and skipped device messages), so it can be lower than the number of the last event's line.
    /// </summary>
    public static int MaxLabelLine(LogFile file, int lastEventLine) =>
        (int)Math.Min(int.MaxValue, Math.Max(1L, (long)Math.Max(file.TotalLines, lastEventLine) + file.FailedLines));

    /// <summary>Shortens a text to the column length without cutting a surrogate pair (emoji, ...) in half.</summary>
    public static string? Cut(string? value, int max)
    {
        if (value is null || value.Length <= max)
            return value;
        return value[..(max > 0 && char.IsHighSurrogate(value[max - 1]) ? max - 1 : max)];
    }
}
