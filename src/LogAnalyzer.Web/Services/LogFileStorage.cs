using LogAnalyzer.Web.Models;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// Stores uploaded logs on disk under App_Data/uploads, named by database id
/// (never by the user-supplied file name, to avoid path traversal).
/// </summary>
public sealed class LogFileStorage(IWebHostEnvironment env)
{
    public string Root { get; } = Path.Combine(env.ContentRootPath, "App_Data", "uploads");

    public static bool IsGzip(string fileName) =>
        fileName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase);

    public string GetPath(LogFile file) =>
        Path.Combine(Root, file.Id + (IsGzip(file.FileName) ? ".log.gz" : ".log"));

    public async Task SaveAsync(LogFile file, IFormFile upload, CancellationToken ct)
    {
        Directory.CreateDirectory(Root);
        await using var target = File.Create(GetPath(file));
        await upload.CopyToAsync(target, ct);
    }

    public void Delete(LogFile file)
    {
        var path = GetPath(file);
        if (File.Exists(path))
            File.Delete(path);
    }
}
