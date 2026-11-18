using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<LogFile> LogFiles => Set<LogFile>();
    public DbSet<LogEvent> LogEvents => Set<LogEvent>();
    public DbSet<LogFileHourStat> LogFileHourStats => Set<LogFileHourStat>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AlertEvidence> AlertEvidence => Set<AlertEvidence>();
    public DbSet<IpInfo> IpInfos => Set<IpInfo>();
    public DbSet<IpReputation> IpReputations => Set<IpReputation>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<AlertComment> AlertComments => Set<AlertComment>();
    public DbSet<Notification> Notifications => Set<Notification>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<AppUser>(e =>
        {
            e.Property(x => x.FullName).HasMaxLength(150);
            e.Property(x => x.Tier).HasConversion<string>().HasMaxLength(10);
        });

        b.Entity<LogFile>(e =>
        {
            e.Property(x => x.FileName).HasMaxLength(260).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.Property(x => x.DetectionWarnings).HasMaxLength(2000);
            e.Property(x => x.UploadedByName).HasMaxLength(256);
            e.Ignore(x => x.UploaderDisplay);
            // Deleting a user account keeps the files: the link becomes null, UploadedByName keeps the e-mail.
            e.HasOne(x => x.UploadedBy).WithMany()
                .HasForeignKey(x => x.UploadedById)
                .OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<LogEvent>(e =>
        {
            e.Property(x => x.ClientIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.Method).HasMaxLength(16);
            e.Property(x => x.Url).HasMaxLength(4000);
            e.Property(x => x.Protocol).HasMaxLength(16);
            e.Property(x => x.Referrer).HasMaxLength(2000);
            e.Property(x => x.UserAgent).HasMaxLength(1000);
            e.HasOne(x => x.LogFile).WithMany(f => f.Events)
                .HasForeignKey(x => x.LogFileId)
                .OnDelete(DeleteBehavior.Cascade);
            // Every query filters by file: events page (ORDER BY LineNumber), detection and rule tester
            // (ORDER BY Timestamp, LineNumber). ClientIp serves the IP lookup page. No standalone Timestamp index:
            // it was never used with the file filter and only slowed down every bulk insert.
            e.HasIndex(x => new { x.LogFileId, x.LineNumber });
            e.HasIndex(x => new { x.LogFileId, x.Timestamp, x.LineNumber });
            e.HasIndex(x => x.ClientIp);
        });

        b.Entity<LogFileHourStat>(e =>
        {
            e.HasKey(x => new { x.LogFileId, x.Hour });
            e.HasOne<LogFile>().WithMany()
                .HasForeignKey(x => x.LogFileId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<DetectionRule>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(150).IsRequired();
            e.Property(x => x.Description).HasMaxLength(1000);
            e.Property(x => x.AttackType).HasConversion<string>().HasMaxLength(30);
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Field).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Pattern).HasMaxLength(2000);
            e.Property(x => x.MethodFilter).HasMaxLength(16);
            e.Property(x => x.PathPattern).HasMaxLength(500);
            e.HasIndex(x => x.Name).IsUnique();
        });

        b.Entity<Alert>(e =>
        {
            e.Property(x => x.Title).HasMaxLength(300);
            e.Property(x => x.SourceIp).HasMaxLength(45);
            e.Property(x => x.AttackType).HasConversion<string>().HasMaxLength(30);
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Notes).HasMaxLength(4000);
            e.Property(x => x.OriginalSeverity).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.SeverityNote).HasMaxLength(300);
            e.Property(x => x.Details).HasMaxLength(1000);
            e.HasOne(x => x.Rule).WithMany(r => r.Alerts)
                .HasForeignKey(x => x.RuleId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.LogFile).WithMany(f => f.Alerts)
                .HasForeignKey(x => x.LogFileId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.AssignedTo).WithMany()
                .HasForeignKey(x => x.AssignedToId)
                .OnDelete(DeleteBehavior.SetNull);
            e.Property(x => x.EscalatedBy).HasMaxLength(256);
            e.Property(x => x.EscalatedById).HasMaxLength(450);
            e.Property(x => x.EscalationReason).HasMaxLength(500);
            e.Property(x => x.Verdict).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.VerdictBy).HasMaxLength(256);
            e.HasIndex(x => x.EscalatedAt);
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.Severity);
            e.HasIndex(x => x.SourceIp);
        });

        // SQL Server forbids multiple cascade paths (LogFile -> Alert -> Evidence and LogFile -> LogEvent -> Evidence),
        // so the LogEvent side does not cascade.
        b.Entity<AlertEvidence>(e =>
        {
            e.HasOne(x => x.Alert).WithMany(a => a.Evidence)
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.LogEvent).WithMany()
                .HasForeignKey(x => x.LogEventId)
                .OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => new { x.AlertId, x.LogEventId }).IsUnique();
        });

        b.Entity<IpInfo>(e =>
        {
            e.HasKey(x => x.Ip);
            e.Property(x => x.Ip).HasMaxLength(45);
            e.Property(x => x.CountryCode).HasMaxLength(2);
            e.Property(x => x.CountryName).HasMaxLength(100);
            e.Property(x => x.City).HasMaxLength(100);
        });

        b.Entity<IpReputation>(e =>
        {
            // Holds IPs, domains (max 253) and SHA-256 hashes (64).
            e.Property(x => x.Ip).HasMaxLength(256).IsRequired();
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(10).HasDefaultValue(IndicatorType.Ip);
            e.Property(x => x.Provider).HasMaxLength(30).IsRequired();
            e.Property(x => x.Verdict).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.Summary).HasMaxLength(500);
            e.Property(x => x.AttributesJson).HasMaxLength(4000);
            e.Property(x => x.Error).HasMaxLength(500);
            e.Property(x => x.LastAttemptError).HasMaxLength(500);
            e.Ignore(x => x.HasVerdict);
            e.HasIndex(x => new { x.Ip, x.Provider }).IsUnique();
            e.HasIndex(x => x.Provider);
        });

        b.Entity<AuditEntry>(e =>
        {
            e.Property(x => x.UserName).HasMaxLength(256);
            e.Property(x => x.Action).HasMaxLength(100).IsRequired();
            e.Property(x => x.Target).HasMaxLength(300);
            e.Property(x => x.Details).HasMaxLength(2000);
            e.Property(x => x.IpAddress).HasMaxLength(45);
            e.HasIndex(x => x.Timestamp);
            e.HasIndex(x => x.Action);
        });

        b.Entity<AlertComment>(e =>
        {
            e.Property(x => x.AuthorId).HasMaxLength(450);
            e.Property(x => x.AuthorName).HasMaxLength(256).IsRequired();
            e.Property(x => x.Text).HasMaxLength(2000).IsRequired();
            e.Property(x => x.Kind).HasMaxLength(20);
            // Deleting alerts (re-run detection, file delete) removes their comments.
            e.HasOne(x => x.Alert).WithMany(a => a.Comments)
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.AlertId);
        });

        b.Entity<Notification>(e =>
        {
            e.Property(x => x.Title).HasMaxLength(200).IsRequired();
            e.Property(x => x.Body).HasMaxLength(500);
            e.Property(x => x.Link).HasMaxLength(300);
            e.Property(x => x.Kind).HasMaxLength(20);
            e.HasOne(x => x.User).WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.UserId, x.ReadAt });
        });
    }
}
