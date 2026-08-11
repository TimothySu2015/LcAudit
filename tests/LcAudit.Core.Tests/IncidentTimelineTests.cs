using LcAudit.Core.Model;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>
/// 事發時間錨點比對。
/// <para>
/// 真實案例：一台被盜帳號的電腦，AnyDesk 的安裝時間正好就是帳號被盜的時間。
/// 工具本來就收集了那個時間戳，但沒有錨點時它只是時間軸裡的一行；
/// 有了錨點才會浮到報告最前面。
/// </para>
/// </summary>
public sealed class IncidentTimelineTests
{
    private static readonly DateTimeOffset Incident = new(2026, 8, 5, 3, 20, 0, TimeSpan.FromHours(8));

    private static Finding WithEvidence(string id, params Evidence[] evidence) => new()
    {
        Id = id,
        Module = id.Split('-')[0],
        Title = $"測試 {id}",
        Severity = Severity.High,
        Status = CheckStatus.Warning,
        Source = "測試",
        Evidence = evidence,
    };

    [Fact]
    public void 最接近事發時間的排在最前面()
    {
        var findings = new[]
        {
            WithEvidence("M2-04", new Evidence("遠端登入", "x", Incident.AddHours(-20))),
            WithEvidence("M2-06", new Evidence("AnyDesk 安裝時間", "x", Incident.AddMinutes(-8))),
            WithEvidence("M3-04", new Evidence("帳號建立", "x", Incident.AddHours(5))),
        };

        var matches = IncidentTimeline.Build(findings, Incident);

        Assert.Equal("M2-06", matches[0].Finding.Id);
        Assert.Equal("M3-04", matches[1].Finding.Id);
        Assert.Equal("M2-04", matches[2].Finding.Id);
    }

    [Fact]
    public void 超出比對範圍的跡證會被排除()
    {
        var findings = new[]
        {
            WithEvidence("M2-06", new Evidence("安裝時間", "x", Incident.AddDays(-10))),
        };

        Assert.Empty(IncidentTimeline.Build(findings, Incident));
    }

    [Fact]
    public void 沒有時間戳的證據不納入比對()
    {
        var findings = new[] { WithEvidence("M1-05", new Evidence("路徑", @"C:\x.dll")) };

        Assert.Empty(IncidentTimeline.Build(findings, Incident));
    }

    [Fact]
    public void 兩小時內視為相近()
    {
        var findings = new[]
        {
            WithEvidence("M2-06", new Evidence("安裝時間", "x", Incident.AddMinutes(-8))),
            WithEvidence("M2-04", new Evidence("遠端登入", "x", Incident.AddHours(-20))),
        };

        var close = IncidentTimeline.Closest(IncidentTimeline.Build(findings, Incident));

        Assert.Single(close);
        Assert.Equal("M2-06", close[0].Finding.Id);
    }

    [Theory]
    [InlineData(-8, "事發前 8 分鐘")]
    [InlineData(8, "事發後 8 分鐘")]
    [InlineData(-180, "事發前 3 小時")]
    [InlineData(-2880, "事發前 2 天")]
    public void 相對時間的描述(int offsetMinutes, string expected)
    {
        var match = new IncidentMatch(
            WithEvidence("M2-06"),
            new Evidence("x", "y"),
            TimeSpan.FromMinutes(offsetMinutes));

        Assert.Equal(expected, match.Describe());
    }

    [Fact]
    public void 幾乎同時的描述不分前後()
    {
        var match = new IncidentMatch(
            WithEvidence("M2-06"), new Evidence("x", "y"), TimeSpan.FromSeconds(-30));

        Assert.Equal("與事發時間幾乎同時", match.Describe());
    }
}
