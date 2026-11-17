using LogAnalyzer.Web.Models;
using LogAnalyzer.Web.Services;

namespace LogAnalyzer.Tests;

/// <summary>SOC 1 / SOC 2 permissions on alerts.</summary>
public class UserManagementTests
{
    private static readonly AlertStatus[] All = Enum.GetValues<AlertStatus>();

    [Theory]
    [InlineData(AlertStatus.New)]
    [InlineData(AlertStatus.Investigating)]
    public void Soc1_WorksOnOpenAlertsOnly(AlertStatus current)
    {
        Assert.True(SocPermissions.CanChange(false, AnalystTier.Soc1, current, AlertStatus.Investigating));
        Assert.True(SocPermissions.CanChange(false, AnalystTier.Soc1, current, AlertStatus.New));
        Assert.False(SocPermissions.CanChange(false, AnalystTier.Soc1, current, AlertStatus.Closed));
        Assert.False(SocPermissions.CanChange(false, AnalystTier.Soc1, current, AlertStatus.FalsePositive));
    }

    [Theory]
    [InlineData(AlertStatus.Closed)]
    [InlineData(AlertStatus.FalsePositive)]
    public void Soc1_CannotReopenClosedAlerts(AlertStatus current)
    {
        Assert.Empty(SocPermissions.AllowedStatuses(false, AnalystTier.Soc1, current));
        Assert.False(SocPermissions.CanChange(false, AnalystTier.Soc1, current, AlertStatus.New));
    }

    [Fact]
    public void AnalystWithoutTier_IsTreatedAsSoc1()
    {
        Assert.Equal(AnalystTier.Soc1, SocPermissions.EffectiveTier(false, null));
        Assert.False(SocPermissions.CanChange(false, null, AlertStatus.New, AlertStatus.Closed));
    }

    [Theory]
    [InlineData(false, AnalystTier.Soc2)]
    [InlineData(true, null)]
    [InlineData(true, AnalystTier.Soc1)]
    public void Soc2AndAdmins_MayDoEverything(bool isAdmin, AnalystTier? tier)
    {
        foreach (var current in All)
            foreach (var next in All)
                Assert.True(SocPermissions.CanChange(isAdmin, tier, current, next), $"{current} -> {next}");
    }

    [Fact]
    public void OnlySoc1_EscalatesOpenAlertsOnce()
    {
        var open = new Alert { Status = AlertStatus.New };
        Assert.True(SocPermissions.CanEscalate(false, AnalystTier.Soc1, open));
        Assert.False(SocPermissions.CanEscalate(false, AnalystTier.Soc2, open));
        Assert.False(SocPermissions.CanEscalate(true, null, open));
        Assert.False(SocPermissions.CanEscalate(false, AnalystTier.Soc1, new Alert { Status = AlertStatus.Closed }));
        Assert.False(SocPermissions.CanEscalate(false, AnalystTier.Soc1,
            new Alert { Status = AlertStatus.Investigating, EscalatedAt = DateTime.UtcNow }));
    }

    [Fact]
    public void UploaderDisplay_SurvivesADeletedAccount()
    {
        Assert.Equal("ex@lab.test (deleted user)", new LogFile { UploadedByName = "ex@lab.test" }.UploaderDisplay);
        Assert.Equal("now@lab.test", new LogFile { UploadedBy = new AppUser { Email = "now@lab.test" } }.UploaderDisplay);
        Assert.Equal("unknown", new LogFile().UploaderDisplay);
    }
}
