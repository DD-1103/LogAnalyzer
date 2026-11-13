using LogAnalyzer.Web.Data;
using LogAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Controllers;

/// <summary>Admin view of the audit trail (who did what and when). Entries are append-only: there is no edit or delete.</summary>
[Authorize(Roles = Roles.Admin)]
public class AuditController(AppDbContext db) : Controller
{
    private const int PageSize = 50;

    public async Task<IActionResult> Index(string? user, string? type, int page = 1, CancellationToken ct = default)
    {
        var query = db.AuditEntries.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(user))
            query = query.Where(a => a.UserName != null && a.UserName.Contains(user.Trim()));
        if (!string.IsNullOrWhiteSpace(type))
            query = query.Where(a => a.Action.StartsWith(type.Trim()));

        var count = await query.CountAsync(ct);
        var totalPages = Math.Max(1, (int)Math.Ceiling(count / (double)PageSize));
        page = Math.Clamp(page, 1, totalPages);

        return View(new AuditViewModel
        {
            Entries = await query.OrderByDescending(a => a.Id).Skip((page - 1) * PageSize).Take(PageSize).ToListAsync(ct),
            Actions = await db.AuditEntries.Select(a => a.Action).Distinct().OrderBy(a => a).ToListAsync(ct),
            User = user,
            Action = type,
            Page = page,
            TotalPages = totalPages,
            TotalCount = count
        });
    }
}
