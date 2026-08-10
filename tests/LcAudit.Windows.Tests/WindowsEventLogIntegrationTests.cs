using System.Security.Principal;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

[Trait("Category", "Integration")]
public sealed class WindowsEventLogIntegrationTests
{
    private readonly WindowsEventLog _log = new();

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// <b>關鍵回歸測試。</b>
    /// <para>
    /// 未提權讀取 Security 記錄時，<c>TolerateQueryErrors = true</c> 會讓錯誤被靜默吞掉 ——
    /// reader 建得起來、ReadEvent() 回 null，於是「讀不到」與「沒有事件」無法區分，
    /// M2 會全部報「通過」。這是比沒有檢查更糟的假安全感。
    /// </para>
    /// <para>
    /// 因此 Query 必須先明確探測可讀性並拋 <see cref="UnauthorizedAccessException"/>，
    /// 讓 SafeCheckDecorator 轉成 Inconclusive。
    /// </para>
    /// </summary>
    [Fact]
    public void 未提權讀取Security必須拋例外而非靜默回空()
    {
        var query = EventQueries.ByEventId(EventQueries.EventIdLogonSuccess, 90);

        if (IsElevated())
        {
            // 已提權時應正常讀取（可能為 0 筆，但不得拋例外）
            var records = _log.Query(EventQueries.SecurityLog, query, EventQueries.LogonProperties, 10);
            Assert.NotNull(records);
            return;
        }

        Assert.Throws<UnauthorizedAccessException>(
            () => _log.Query(EventQueries.SecurityLog, query, EventQueries.LogonProperties, 10));
    }

    [Fact]
    public void 可讀取的記錄檔能正常查詢()
    {
        // Application 記錄檔不需提權
        var records = _log.Query(
            "Application",
            EventQueries.ByEventIds([1000, 1001, 1026], 365),
            [],
            5);

        Assert.NotNull(records);
        Assert.True(records.Count <= 5, "maxEvents 上限未生效");
    }

    [Fact]
    public void 不存在的記錄檔拋FileNotFoundException()
        => Assert.Throws<FileNotFoundException>(
            () => _log.Query("LcAudit-NoSuchLog-9c2f", EventQueries.ByEventId(1, 7), [], 10));

    [Fact]
    public void maxEvents上限確實生效()
    {
        var records = _log.Query("Application", EventQueries.ByEventIds([1000, 1001, 1026], 365), [], 2);

        Assert.True(records.Count <= 2);
    }
}
