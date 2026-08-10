using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M2;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class M2CheckTests
{
    private static readonly DateTimeOffset Base = new(2026, 5, 1, 3, 0, 0, TimeSpan.FromHours(8));

    private static LogonRecord Logon(
        string ip,
        string user = "timothy",
        string domain = "DESKTOP",
        int logonType = 10,
        int minuteOffset = 0)
        => new(Base.AddMinutes(minuteOffset), user, domain, logonType, ip, "3389", "WS01");

    private static readonly IWindowsEventLog UnusedLog = new StubEventLog();

    private sealed class StubEventLog : IWindowsEventLog
    {
        public IReadOnlyList<EventRecordData> Query(
            string logName, string xpath, IReadOnlyList<string> propertyPaths, int maxEvents) => [];

        public bool LogExists(string logName) => true;
    }

    // ---- M2-01 遠端互動登入 ----

    [Fact]
    public void M2_01無紀錄判Pass()
    {
        var finding = new M2_01_RemoteInteractiveLogonCheck(UnusedLog).Evaluate([], 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(0, finding.Score);
    }

    [Fact]
    public void M2_01有紀錄判Warning並計半分()
    {
        var finding = new M2_01_RemoteInteractiveLogonCheck(UnusedLog)
            .Evaluate([Logon("192.168.1.50")], 90);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);   // High(20) 的 50%
    }

    [Fact]
    public void M2_01依來源IP彙總並標示首見末見()
    {
        var finding = new M2_01_RemoteInteractiveLogonCheck(UnusedLog).Evaluate(
        [
            Logon("203.0.113.5", minuteOffset: 0),
            Logon("203.0.113.5", minuteOffset: 120),
            Logon("192.168.1.50", minuteOffset: 60),
        ], 90);

        var summary = Assert.Single(finding.Evidence, e => e.Key == "來源 203.0.113.5");
        Assert.Contains("2 次", summary.Value);
        Assert.Contains("首見", summary.Value);
        Assert.Contains("末見", summary.Value);
    }

    [Fact]
    public void M2_01公網來源會在描述中特別點出()
    {
        var finding = new M2_01_RemoteInteractiveLogonCheck(UnusedLog)
            .Evaluate([Logon("203.0.113.5"), Logon("192.168.1.50")], 90);

        Assert.Contains("1 次來自公網位址", finding.Description);
    }

    // ---- M2-02 網路登入 ----

    [Fact]
    public void M2_02全為私有來源判Pass()
    {
        var finding = new M2_02_NetworkLogonCheck(UnusedLog).Evaluate(
        [
            Logon("192.168.1.10", logonType: 3),
            Logon("10.0.0.5", logonType: 3),
            Logon("-", logonType: 3),
        ], 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M2_02公網來源判Fail並計滿分()
    {
        var finding = new M2_02_NetworkLogonCheck(UnusedLog)
            .Evaluate([Logon("203.0.113.5", logonType: 3)], 90);

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(20, finding.Score);
    }

    [Fact]
    public void M2_02CGNAT位址不得誤判為公網()
    {
        // 電信業者 CGNAT，漏掉會對大量正常使用者誤報
        var finding = new M2_02_NetworkLogonCheck(UnusedLog)
            .Evaluate([Logon("100.64.1.1", logonType: 3)], 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M2_02無法解析的來源不判Fail()
    {
        // WorkstationName 被填進 IpAddress 欄位的情況，不該當成公網
        var finding = new M2_02_NetworkLogonCheck(UnusedLog)
            .Evaluate([Logon("WORKSTATION-01", logonType: 3)], 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    // ---- 系統帳號排除 ----

    [Theory]
    [InlineData("DESKTOP$")]
    [InlineData("ANONYMOUS LOGON")]
    [InlineData("SYSTEM")]
    [InlineData("LOCAL SERVICE")]
    [InlineData("NETWORK SERVICE")]
    [InlineData("-")]
    [InlineData("")]
    public void 系統帳號應被排除(string userName)
        => Assert.True(Logon("203.0.113.5", userName).IsSystemAccount);

    [Fact]
    public void 一般帳號不應被排除()
        => Assert.False(Logon("203.0.113.5", "timothy").IsSystemAccount);

    // ---- M2-03 登入失敗爆量 ----

    [Fact]
    public void M2_03未達門檻判Pass()
    {
        var failures = Enumerable.Range(0, 9)
            .Select(i => Logon("192.168.1.9", logonType: 3, minuteOffset: i))
            .ToList();

        Assert.Equal(CheckStatus.Pass, new M2_03_LogonFailureBurstCheck(UnusedLog).Evaluate(failures, 90).Status);
    }

    [Fact]
    public void M2_03單一小時達10次判Warning()
    {
        var failures = Enumerable.Range(0, 10)
            .Select(i => Logon("192.168.1.9", logonType: 3, minuteOffset: i))
            .ToList();

        var finding = new M2_03_LogonFailureBurstCheck(UnusedLog).Evaluate(failures, 90);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(5, finding.Score);   // Medium(10) 的 50%
    }

    [Fact]
    public void M2_03跨小時的失敗不會被合併計算()
    {
        // 03:55 起連續 10 次，跨到 04:xx —— 每個整點小時各 5 次，都未達門檻
        var failures = Enumerable.Range(0, 10)
            .Select(i => Logon("192.168.1.9", logonType: 3, minuteOffset: 55 + i))
            .ToList();

        Assert.Equal(CheckStatus.Pass, new M2_03_LogonFailureBurstCheck(UnusedLog).Evaluate(failures, 90).Status);
    }

    // ---- M2-00 記錄檔被清除 ----

    [Fact]
    public void M2_00無清除紀錄判Pass()
        => Assert.Equal(CheckStatus.Pass, new M2_00_LogClearedCheck(UnusedLog).Evaluate([], 90).Status);

    [Fact]
    public void M2_00有清除紀錄判Warning並警告其餘項不可信()
    {
        var finding = new M2_00_LogClearedCheck(UnusedLog).Evaluate([Base], 90);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("並不代表安全", finding.Description);
    }
}

public sealed class EventQueriesTests
{
    [Fact]
    public void 回溯天數換算為毫秒()
        => Assert.Equal(7_776_000_000L, EventQueries.LookbackMilliseconds(90));

    [Fact]
    public void 比較運算子必須是字面小於等於()
    {
        // EventLogQuery 收的是純 XPath，不是 XML。寫成 &lt;= 會被拒為「指定的查詢無效」，
        // 而且錯誤會被 SafeCheckDecorator 吞成 Inconclusive，極難察覺。
        var xpath = EventQueries.ByEventId(4624, 90);

        Assert.Contains("<=", xpath);
        Assert.DoesNotContain("&lt;", xpath);
    }

    [Fact]
    public void LogonByType會附加LogonType條件()
    {
        var xpath = EventQueries.LogonByType(10, 90);

        Assert.Contains("EventID=4624", xpath);
        Assert.Contains("Data[@Name='LogonType']='10'", xpath);
    }

    [Fact]
    public void 多個EventID以or串接()
    {
        var xpath = EventQueries.ByEventIds([21, 22, 23], 30);

        Assert.Contains("EventID=21 or EventID=22 or EventID=23", xpath);
    }

    [Fact]
    public void 回溯天數不可為零或負數()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => EventQueries.LookbackMilliseconds(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => EventQueries.LookbackMilliseconds(-1));
    }
}
