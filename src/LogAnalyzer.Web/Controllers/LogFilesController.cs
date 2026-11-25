using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;
using LogAnalyzer.Web.Services.LogFormats;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

public class LogFilesController(
    AppDbContext db,
    LogFileStorage storage,
    LogProcessingQueue queue,
    UserManager<AppUser> userManager,
    IAuditLog audit,
    ILogger<LogFilesController> logger) : Controller
{
    private const long MaxUploadBytes = 500L * 1024 * 1024; // 500 MB
    private const int PageSize = 50;
    private static readonly string[] AllowedExtensions = [".log", ".txt", ".gz"];

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var files = await db.LogFiles
            .AsNoTracking()
            .Include(f => f.UploadedBy)
            .OrderByDescending(f => f.UploadedAt)
            .ToListAsync();
        return View(files);
    }

    [HttpGet]
    public IActionResult Upload() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(MaxUploadBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = MaxUploadBytes)]
    public async Task<IActionResult> Upload(IFormFile? file, string? format, CancellationToken ct)
    {
        // "auto" (default) = detect from the first lines; otherwise one of the registered format ids.
        var requested = string.IsNullOrWhiteSpace(format) || format == LogFormatRegistry.AutoId ? null : LogFormatRegistry.Find(format)?.Id;
        ViewData["Format"] = requested;   // keeps the choice when the form is shown again
        if (requested is null && !string.IsNullOrWhiteSpace(format) && format != LogFormatRegistry.AutoId)
        {
            ModelState.AddModelError(string.Empty, "Unknown log format.");
            return View();
        }

        if (file is null || file.Length == 0)
        {
            ModelState.AddModelError(string.Empty, "Choose a log file to upload.");
            return View();
        }

        // "filename*=" may hold encoded line breaks: cleaned before the name is stored, logged and audited.
        var originalName = AuditLog.Clean(Path.GetFileName(file.FileName))!;
        var extension = Path.GetExtension(originalName).ToLowerInvariant();
        if (!AllowedExtensions.Contains(extension))
        {
            ModelState.AddModelError(string.Empty, "Only .log, .txt and .gz files are allowed.");
            return View();
        }

        var logFile = new LogFile
        {
            FileName = originalName.Length > 260 ? originalName[^260..] : originalName,
            SizeBytes = file.Length,
            UploadedById = userManager.GetUserId(User)!,
            UploadedByName = User.Identity?.Name,
            RequestedFormat = requested,
            Status = LogFileStatus.Pending
        };
        db.LogFiles.Add(logFile);
        await db.SaveChangesAsync(ct);

        try
        {
            await storage.SaveAsync(logFile, file, ct);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Saving upload {Name} failed", originalName);
            db.LogFiles.Remove(logFile);
            await db.SaveChangesAsync(CancellationToken.None);
            ModelState.AddModelError(string.Empty, "The file could not be saved. Try again.");
            return View();
        }

        await queue.EnqueueAsync(logFile.Id, ct);
        await audit.WriteAsync("LogFile.Upload", $"#{logFile.Id} {logFile.FileName}",
            $"{file.Length:N0} bytes, format {requested ?? LogFormatRegistry.AutoId}", ct);
        logger.LogInformation("User {User} uploaded {Name} ({Bytes} bytes) as log file {Id}",
            User.Identity?.Name, originalName, file.Length, logFile.Id);

        TempData["Success"] = $"\"{logFile.FileName}\" uploaded. Processing has started.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Details(int id, int page = 1, string? ip = null, int? status = null,
        FirewallAction? fwAction = null, int? dport = null)
    {
        var file = await db.LogFiles.AsNoTracking()
            .Include(f => f.UploadedBy)
            .FirstOrDefaultAsync(f => f.Id == id);
        if (file is null)
            return NotFound();

        // Filters of the other kind of log are ignored (the form does not show them, so they would hide all events).
        if (file.Source == LogSource.Firewall)
            status = null;
        else
            (fwAction, dport) = (null, null);

        var query = db.LogEvents.AsNoTracking().Where(e => e.LogFileId == id);
        if (!string.IsNullOrWhiteSpace(ip))
        {
            var address = IpAddressPolicy.Canonical(ip.Trim());   // events hold the canonical form
            query = query.Where(e => e.ClientIp == address);
        }
        if (status.HasValue)
            query = query.Where(e => e.StatusCode == status.Value);
        if (fwAction.HasValue)
            query = query.Where(e => e.Action == fwAction.Value);
        if (dport.HasValue)
            query = query.Where(e => e.DestinationPort == dport.Value);

        var count = await query.CountAsync();
        var totalPages = Math.Max(1, (int)Math.Ceiling(count / (double)PageSize));
        page = Math.Clamp(page, 1, totalPages);

        var events = await query
            .OrderBy(e => e.LineNumber)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        return View(new LogFileDetailsViewModel
        {
            File = file,
            Events = events,
            Page = page,
            TotalPages = totalPages,
            FilteredCount = count,
            Ip = ip,
            Status = status,
            FwAction = fwAction,
            DestinationPort = dport,
            AlertCount = await db.Alerts.CountAsync(a => a.LogFileId == id)
        });
    }

    /// <summary>
    /// Runs the current rules again (e.g. after a rule was changed) in the background worker.
    /// Alerts are recreated, so their triage status is reset.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> RerunDetection(int id, CancellationToken ct)
    {
        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null)
            return NotFound();
        if (file.Status != LogFileStatus.Completed)
        {
            TempData["Error"] = "Detection can only be re-run on a completed file.";
            return RedirectToAction(nameof(Details), new { id });
        }

        // Mark as busy right away so the UI shows progress and a second click is rejected.
        await db.LogFiles.Where(f => f.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.Status, LogFileStatus.Analyzing), ct);
        await queue.EnqueueDetectionAsync(id, ct);
        await audit.WriteAsync("LogFile.RerunDetection", $"#{id} {file.FileName}", null, ct);

        logger.LogInformation("User {User} re-ran detection on log file {Id}", User.Identity?.Name, id);
        TempData["Success"] = "Detection was queued. The alerts will be updated in a few seconds.";
        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpGet]
    public async Task<IActionResult> Evaluate(int id)
    {
        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id);
        return file is null ? NotFound() : View(new EvaluationViewModel { File = file });
    }

    /// <summary>Compares the alerts of a log file with a ground-truth labels CSV (line,label).</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(20L * 1024 * 1024)]
    [RequestFormLimits(MultipartBodyLengthLimit = 20L * 1024 * 1024)]
    public async Task<IActionResult> Evaluate(int id, IFormFile? labels,
        [FromServices] EvaluationService evaluation, CancellationToken ct)
    {
        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null)
            return NotFound();

        var model = new EvaluationViewModel { File = file };
        if (labels is null || labels.Length == 0)
        {
            ModelState.AddModelError(string.Empty, "Choose a labels CSV file (columns: line,label).");
            return View(model);
        }

        await using var stream = labels.OpenReadStream();
        var lastEventLine = await db.LogEvents.Where(e => e.LogFileId == id).MaxAsync(e => (int?)e.LineNumber, ct) ?? 0;
        var parsed = EvaluationService.ParseLabels(stream, LogImport.MaxLabelLine(file, lastEventLine));
        if (parsed.Count == 0)
        {
            ModelState.AddModelError(string.Empty, "No labels found. Expected lines like: 15,sqli");
            return View(model);
        }

        model.LabelsFileName = Path.GetFileName(labels.FileName);
        model.Result = await evaluation.EvaluateAsync(id, parsed, ct);
        var o = model.Result.Overall;
        await audit.WriteAsync("LogFile.Evaluate", $"#{id} {file.FileName}",
            $"labels {model.LabelsFileName}: P={o.Precision:P1} R={o.Recall:P1} F1={o.F1:P1}", ct);
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var file = await db.LogFiles.FirstOrDefaultAsync(f => f.Id == id);
        if (file is null)
            return NotFound();

        if (Helpers.Format.IsBusy(file.Status))
        {
            TempData["Error"] = "This file is still being processed. Try again when it finishes.";
            return RedirectToAction(nameof(Index));
        }

        // Big files have millions of rows: the background worker deletes them in batches (no request timeout).
        await db.LogFiles.Where(f => f.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.Status, LogFileStatus.Deleting));
        await queue.EnqueueDeleteAsync(id);
        await audit.WriteAsync("LogFile.Delete", $"#{id} {file.FileName}");

        logger.LogInformation("User {User} deleted log file {Id} ({Name})", User.Identity?.Name, id, file.FileName);
        TempData["Success"] = $"\"{file.FileName}\" is being deleted. Large files take a few seconds.";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>Parses a Failed file again from the stored upload (e.g. after a database outage).</summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Reprocess(int id, CancellationToken ct)
    {
        var file = await db.LogFiles.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id, ct);
        if (file is null)
            return NotFound();
        if (file.Status != LogFileStatus.Failed)
        {
            TempData["Error"] = "Only failed files can be processed again.";
            return RedirectToAction(nameof(Details), new { id });
        }
        if (!System.IO.File.Exists(storage.GetPath(file)))
        {
            TempData["Error"] = "The uploaded file is no longer on disk. Delete this entry and upload the file again.";
            return RedirectToAction(nameof(Details), new { id });
        }

        await db.LogFiles.Where(f => f.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(f => f.Status, LogFileStatus.Pending)
            .SetProperty(f => f.ProcessingAttempts, 0)
            .SetProperty(f => f.ErrorMessage, (string?)null), ct);
        await queue.EnqueueAsync(id, ct);
        await audit.WriteAsync("LogFile.Reprocess", $"#{id} {file.FileName}", null, ct);

        logger.LogInformation("User {User} re-processed log file {Id}", User.Identity?.Name, id);
        TempData["Success"] = "The file was queued for processing again.";
        return RedirectToAction(nameof(Details), new { id });
    }

    /// <summary>Downloads a PDF incident report for one log file.</summary>
    [HttpGet]
    public async Task<IActionResult> Report(int id, [FromServices] ReportService reports, CancellationToken ct)
    {
        var pdf = await reports.BuildLogFileReportAsync(id, User.Identity?.Name ?? "unknown", ct);
        if (pdf is null)
            return NotFound();

        var name = Path.GetFileNameWithoutExtension(
            (await db.LogFiles.AsNoTracking().Where(f => f.Id == id).Select(f => f.FileName).FirstAsync(ct)));
        var safeName = string.Concat(name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
        logger.LogInformation("User {User} downloaded the PDF report for log file {Id}", User.Identity?.Name, id);
        await audit.WriteAsync("Report.Pdf", $"#{id} {name}", null, ct);
        return File(pdf, "application/pdf", $"report-{safeName}-{DateTime.Now:yyyyMMdd}.pdf");
    }
}
