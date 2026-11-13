using LogAnalyzer.Web.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LogAnalyzer.Web.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<LogFile> LogFiles => Set<LogFile>();
    public DbSet<LogEvent> LogEvents => Set<LogEvent>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AlertEvidence> AlertEvidence => Set<AlertEvidence>();
    public DbSet<IpInfo> IpInfos => Set<IpInfo>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<AppUser>(e => e.Property(x => x.FullName).HasMaxLength(150));

        b.Entity<LogFile>(e =>
        {
            e.Property(x => x.FileName).HasMaxLength(260).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(20);
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.HasOne(x => x.UploadedBy).WithMany()
                .HasForeignKey(x => x.UploadedById)
                .OnDelete(DeleteBehavior.Restrict);
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
            e.HasIndex(x => x.LogFileId);
            e.HasIndex(x => x.ClientIp);
            e.HasIndex(x => x.Timestamp);
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
            e.HasOne(x => x.Rule).WithMany(r => r.Alerts)
                .HasForeignKey(x => x.RuleId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.LogFile).WithMany(f => f.Alerts)
                .HasForeignKey(x => x.LogFileId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.AssignedTo).WithMany()
                .HasForeignKey(x => x.AssignedToId)
                .OnDelete(DeleteBehavior.SetNull);
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
    }
}
