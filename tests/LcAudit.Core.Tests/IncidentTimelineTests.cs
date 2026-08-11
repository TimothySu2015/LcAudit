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

        var matches = IncidentTimeline.Build(findings, IncidentWindow.At(Incident));

        Assert.Equal("M2-06", matches[0].Finding.Id);
        Assert.Equal("M3-04", matches[1].Finding.Id);
        Assert.Equal("M2-04", matches[2].Finding.Id);
    }

    [Fact]
    public void 沒有時間戳的證據不納入比對()
    {
        var findings = new[] { WithEvidence("M1-05", new Evidence("路徑", @"C:\x.dll")) };

        Assert.Empty(IncidentTimeline.Build(findings, IncidentWindow.At(Incident)));
    }

    [Fact]
    public void 兩小時內視為相近()
    {
        var findings = new[]
        {
            WithEvidence("M2-06", new Evidence("安裝時間", "x", Incident.AddMinutes(-8))),
            WithEvidence("M2-04", new Evidence("遠端登入", "x", Incident.AddHours(-20))),
        };

        var close = IncidentTimeline.Closest(IncidentTimeline.Build(findings, IncidentWindow.At(Incident)));

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

    // ---- 事發區間 ----
    //
    // 真實案例：使用者 02:00 還在線上掛機，07:30 發現帳號被盜。他給得出的是這個
    // 範圍，而不是一個時間點 ——「大約 04:00」只是推估。若只吃單一時間點，
    // 靠近 07:30 那端的事件（可能正是真正動手的時刻）反而不會被凸顯。

    private static readonly DateTimeOffset LastSeenOk = new(2026, 8, 9, 2, 0, 0, TimeSpan.FromHours(8));
    private static readonly DateTimeOffset Discovered = new(2026, 8, 9, 7, 30, 0, TimeSpan.FromHours(8));

    private static IncidentWindow Window => IncidentWindow.Between(LastSeenOk, Discovered);

    [Fact]
    public void 落在區間內的跡證距離為零並排在最前()
    {
        var findings = new[]
        {
            WithEvidence("M2-04", new Evidence("遠端登入", "x", LastSeenOk.AddHours(-3))),
            WithEvidence("M2-06", new Evidence("AnyDesk 安裝", "x", LastSeenOk.AddHours(4))),   // 06:00，區間內
            WithEvidence("M3-04", new Evidence("帳號建立", "x", Discovered.AddHours(6))),
        };

        var matches = IncidentTimeline.Build(findings, Window);

        Assert.Equal("M2-06", matches[0].Finding.Id);
        Assert.True(matches[0].IsWithinWindow);
        Assert.Equal("★ 就在事發區間內", matches[0].Describe());
    }

    [Fact]
    public void 區間兩端也算在內()
    {
        Assert.Equal(TimeSpan.Zero, Window.DistanceFrom(LastSeenOk));
        Assert.Equal(TimeSpan.Zero, Window.DistanceFrom(Discovered));
    }

    [Fact]
    public void 區間外的距離從最近的端點起算()
    {
        // 08:30 距離結束端點 07:30 是一小時，而不是距離起點 02:00 的六個半小時
        Assert.Equal(TimeSpan.FromHours(1), Window.DistanceFrom(Discovered.AddHours(1)));
        Assert.Equal(TimeSpan.FromHours(-1), Window.DistanceFrom(LastSeenOk.AddHours(-1)));
    }

    [Fact]
    public void 起訖顛倒時自動校正()
    {
        var reversed = IncidentWindow.Between(Discovered, LastSeenOk);

        Assert.Equal(LastSeenOk, reversed.Start);
        Assert.Equal(Discovered, reversed.End);
    }

    [Fact]
    public void 單一時間點退化為零長度區間()
    {
        var point = IncidentWindow.At(LastSeenOk);

        Assert.False(point.IsRange);
        Assert.Equal(TimeSpan.Zero, point.DistanceFrom(LastSeenOk));
        Assert.Equal("2026-08-09 02:00", point.Describe());
    }

    [Fact]
    public void 區間的顯示文字含起訖()
        => Assert.Equal("2026-08-09 02:00 ～ 2026-08-09 07:30", Window.Describe());

    /// <summary>
    /// 刻意不設距離上限。入侵的原因往往遠早於受害者「發現」的時間 ——
    /// 若硬性濾掉超過 N 天的事件，最關鍵的那筆證據反而會被工具默默丟掉。
    /// </summary>
    [Fact]
    public void 很久以前的跡證仍然列出並標明距離()
    {
        var findings = new[]
        {
            WithEvidence("M2-06", new Evidence("AnyDesk 安裝", "x", LastSeenOk.AddDays(-30))),
        };

        var match = Assert.Single(IncidentTimeline.Build(findings, Window));

        Assert.Equal("事發前 30 天", match.Describe());
        Assert.False(match.IsWithinWindow);
    }

    [Fact]
    public void 筆數上限生效()
    {
        var findings = Enumerable.Range(1, 80)
            .Select(i => WithEvidence("M2-04", new Evidence("事件", "x", LastSeenOk.AddMinutes(i))))
            .ToArray();

        Assert.Equal(IncidentTimeline.MaxMatches, IncidentTimeline.Build(findings, Window).Count);
    }
}
