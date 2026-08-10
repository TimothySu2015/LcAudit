using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M3;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class M3CheckTests
{
    private sealed class StubRegistry : IRegistryReader
    {
        public object? GetLocalMachineValue(string keyPath, string valueName) => null;

        public IReadOnlyDictionary<string, object?> GetLocalMachineValues(string keyPath)
            => new Dictionary<string, object?>();

        public IReadOnlyList<string> GetLocalMachineSubKeyNames(string keyPath) => [];
    }

    private sealed class StubAccounts : ILocalAccountSource
    {
        public IReadOnlyList<GroupMember> GetAdministrators() => [];

        public IReadOnlyList<GroupMember> GetRemoteDesktopUsers() => [];

        public IReadOnlyList<LocalUser> GetLocalUsers() => [];

        public string CurrentUserName => "timothy";
    }

    private static readonly StubRegistry Registry = new();
    private static readonly StubAccounts Accounts = new();

    private static GroupMember Member(
        string name, bool wellKnown = false, bool local = true, string sid = "S-1-5-21-1-2-3-1001")
        => new(name, sid, wellKnown, local);

    // ---- M3-01 RDP 啟用 ----

    [Theory]
    [InlineData(0, CheckStatus.Warning)]   // 0 = 不拒絕 = 已啟用
    [InlineData(1, CheckStatus.Pass)]
    public void M3_01依fDenyTSConnections判定(int value, CheckStatus expected)
        => Assert.Equal(expected, new M3_01_RdpEnabledCheck(Registry).Evaluate(value).Status);

    [Fact]
    public void M3_01讀不到值判Inconclusive()
        => Assert.Equal(CheckStatus.Inconclusive, new M3_01_RdpEnabledCheck(Registry).Evaluate(null).Status);

    // ---- M3-02 RDP 埠號 ----

    [Fact]
    public void M3_02預設埠判Pass()
        => Assert.Equal(CheckStatus.Pass, new M3_02_RdpPortCheck(Registry).Evaluate(3389).Status);

    [Fact]
    public void M3_02埠號被改判Fail()
    {
        var finding = new M3_02_RdpPortCheck(Registry).Evaluate(33890);

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(20, finding.Score);
        Assert.Contains("33890", finding.Description);
    }

    // ---- M3-05 系統管理員群組（誤報風險最高） ----

    [Fact]
    public void M3_05只有內建成員與目前使用者判Pass()
    {
        var finding = new M3_05_AdministratorsGroupCheck(Accounts).Evaluate(
        [
            Member(@"PC\Administrator", wellKnown: true, sid: "S-1-5-21-1-2-3-500"),
            Member(@"PC\timothy"),
        ], "timothy");

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_05非預期的本機帳號判Fail()
    {
        var finding = new M3_05_AdministratorsGroupCheck(Accounts).Evaluate(
        [
            Member(@"PC\timothy"),
            Member(@"PC\backdoor"),
        ], "timothy");

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(40, finding.Score);
        Assert.Contains("backdoor", finding.Description);
    }

    [Fact]
    public void M3_05非預期的網域成員只判Warning()
    {
        // 公司配發的電腦本機 Administrators 常含網域群組 —— 判 Fail 會強制「極高」，
        // 對企業使用者是純誤報
        var finding = new M3_05_AdministratorsGroupCheck(Accounts).Evaluate(
        [
            Member(@"PC\timothy"),
            Member(@"CONTOSO\IT-Admins", local: false, sid: "S-1-5-21-9-9-9-1234"),
        ], "timothy");

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(20, finding.Score);
    }

    [Fact]
    public void M3_05以RID辨識內建帳號而非名稱()
    {
        // 攻擊者常把後門帳號改名為 Administrator。名稱會騙人，SID 的 RID 不會。
        var finding = new M3_05_AdministratorsGroupCheck(Accounts).Evaluate(
        [
            Member(@"PC\timothy"),
            Member(@"PC\Administrator", wellKnown: false, sid: "S-1-5-21-1-2-3-1337"),
        ], "timothy");

        Assert.Equal(CheckStatus.Fail, finding.Status);
    }

    [Fact]
    public void M3_05可用ExpectAdmin排除已知的第二管理員()
    {
        var check = new M3_05_AdministratorsGroupCheck(Accounts)
        {
            ExpectedMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "family-pc" },
        };

        var finding = check.Evaluate(
        [
            Member(@"PC\timothy"),
            Member(@"PC\family-pc"),
        ], "timothy");

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_05列不出成員判Inconclusive而非Pass()
    {
        // 列舉失敗回空集合，若判 Pass 就是「查不到」被誤報成「沒問題」
        var finding = new M3_05_AdministratorsGroupCheck(Accounts).Evaluate([], "timothy");

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
    }

    // ---- M3-03 / M3-04 ----

    [Fact]
    public void M3_03群組為空判Pass()
        => Assert.Equal(CheckStatus.Pass, new M3_03_RemoteDesktopUsersCheck(Accounts).Evaluate([]).Status);

    [Fact]
    public void M3_03有成員判Warning()
        => Assert.Equal(CheckStatus.Warning,
            new M3_03_RemoteDesktopUsersCheck(Accounts).Evaluate([Member(@"PC\someone")]).Status);

    [Fact]
    public void M3_04只有內建與自己判Pass()
    {
        var finding = new M3_04_LocalAccountsCheck(Accounts).Evaluate(
        [
            new LocalUser("Administrator", null, false, false, null),
            new LocalUser("Guest", null, false, false, null),
            new LocalUser("timothy", null, true, false, null),
        ], "timothy", 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_04非預期的啟用中帳號判Warning()
    {
        var finding = new M3_04_LocalAccountsCheck(Accounts).Evaluate(
        [
            new LocalUser("timothy", null, true, false, null),
            new LocalUser("hacker", null, true, false, null),
        ], "timothy", 90);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("hacker", finding.Description);
    }

    [Fact]
    public void M3_04已停用的非預期帳號不觸發警告()
    {
        var finding = new M3_04_LocalAccountsCheck(Accounts).Evaluate(
        [
            new LocalUser("timothy", null, true, false, null),
            new LocalUser("old-account", null, false, false, null),
        ], "timothy", 90);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_04近期建立的帳號會被標示且註明是推估值()
    {
        var finding = new M3_04_LocalAccountsCheck(Accounts).Evaluate(
        [
            new LocalUser("timothy", null, true, false, null),
            new LocalUser("Guest", null, false, false, DateTimeOffset.Now.AddDays(-3)),
        ], "timothy", 90);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("推估", finding.Description);
    }

    // ---- M3-10 / M3-11 Defender ----

    [Fact]
    public void M3_10沒有排除項目判Pass()
        => Assert.Equal(CheckStatus.Pass, new M3_10_DefenderExclusionsCheck(Registry).Evaluate([]).Status);

    [Fact]
    public void M3_10有排除項目判Warning()
    {
        var finding = new M3_10_DefenderExclusionsCheck(Registry)
            .Evaluate([("Paths", @"C:\Temp\evil"), ("Processes", "evil.exe")]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(2, finding.Evidence.Count);
    }

    [Theory]
    [InlineData(null, null, CheckStatus.Pass)]
    [InlineData(0, 0, CheckStatus.Pass)]
    [InlineData(1, null, CheckStatus.Fail)]
    [InlineData(null, 1, CheckStatus.Fail)]
    [InlineData(1, 1, CheckStatus.Fail)]
    public void M3_11依關閉旗標判定(int? realtime, int? antiSpyware, CheckStatus expected)
        => Assert.Equal(expected,
            new M3_11_DefenderStatusCheck(Registry).Evaluate(realtime, antiSpyware).Status);

    [Fact]
    public void M3_11要提醒第三方防毒也會造成同樣結果()
    {
        var finding = new M3_11_DefenderStatusCheck(Registry).Evaluate(1, null);

        Assert.Contains("第三方防毒", finding.Description);
    }

    // ---- M3-13 hosts（Critical） ----

    [Fact]
    public void M3_13乾淨的hosts判Pass()
    {
        var content = """
            # Copyright (c) 1993-2009 Microsoft Corp.
            #	127.0.0.1       localhost
            """;

        Assert.Equal(CheckStatus.Pass, new M3_13_HostsFileCheck().Evaluate(content, "hosts").Status);
    }

    [Theory]
    [InlineData("1.2.3.4 login.plaync.com")]
    [InlineData("1.2.3.4 www.ncsoft.com")]
    [InlineData("1.2.3.4 tw.beanfun.com")]
    [InlineData("1.2.3.4 accounts.google.com")]
    public void M3_13遊戲或入口網站導向判Fail(string line)
    {
        var finding = new M3_13_HostsFileCheck().Evaluate(line, "hosts");

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(40, finding.Score);
    }

    [Fact]
    public void M3_13無關的自訂對應不計分但仍列出證據()
    {
        // 本項為 Critical，一個 Warning 就是 20 分。廣告阻擋等自訂對應很常見，
        // 為此讓正常機器背 20 分不合理 —— 判 Pass 但完整列出供人工過目。
        var finding = new M3_13_HostsFileCheck().Evaluate("0.0.0.0 ads.example.com", "hosts");

        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(0, finding.Score);
        Assert.Contains(finding.Evidence, e => e.Value.Contains("ads.example.com", StringComparison.Ordinal));
    }

    [Fact]
    public void M3_13行內註解前的對應仍然生效()
    {
        // "1.2.3.4 login.plaync.com # 看起來像註解" 的前半段是真的會生效的
        var finding = new M3_13_HostsFileCheck()
            .Evaluate("1.2.3.4 login.plaync.com # 這是正常設定請忽略", "hosts");

        Assert.Equal(CheckStatus.Fail, finding.Status);
    }

    [Fact]
    public void M3_13整行註解不算對應()
        => Assert.Equal(CheckStatus.Pass,
            new M3_13_HostsFileCheck().Evaluate("# 1.2.3.4 login.plaync.com", "hosts").Status);

    [Fact]
    public void M3_13一行多主機名全部剖析()
    {
        var entries = M3_13_HostsFileCheck.ParseEntries("1.2.3.4 a.com b.com c.com").ToList();

        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal("1.2.3.4", e.Address));
    }
}
