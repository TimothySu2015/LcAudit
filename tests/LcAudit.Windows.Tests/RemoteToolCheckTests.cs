using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M2;
using LcAudit.Windows.Sources;
using LcAudit.Windows.Sources.RemoteTools;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class RemoteToolCheckTests
{
    private sealed class FakeScanner(RemoteToolTrace trace, string? logContent = null) : IRemoteToolScanner
    {
        public RemoteToolTrace Scan(RemoteToolDefinition tool) => trace;

        public string? ReadTextFile(string path) => logContent;
    }

    private sealed class StubEventLog : IWindowsEventLog
    {
        public IReadOnlyList<EventRecordData> Query(
            string logName, string xpath, IReadOnlyList<string> propertyPaths, int maxEvents) => [];

        public bool LogExists(string logName) => false;
    }

    private static readonly StubEventLog StubLog = new();

    private static RemoteToolTrace Trace(
        RemoteToolDefinition tool,
        string[]? directories = null,
        string[]? services = null,
        string[]? logs = null)
        => new(tool, directories ?? [], services ?? [], logs ?? []);

    // ---- M2-06 / M2-07 共用判定 ----

    [Fact]
    public async Task 沒有任何痕跡判Pass()
    {
        var scanner = new FakeScanner(Trace(RemoteToolCatalog.AnyDesk));

        var finding = await new M2_06_AnyDeskCheck(scanner, StubLog).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(0, finding.Score);
    }

    [Fact]
    public async Task 有安裝但無連入紀錄判Warning()
    {
        var scanner = new FakeScanner(Trace(
            RemoteToolCatalog.AnyDesk,
            directories: [@"C:\ProgramData\AnyDesk"],
            services: ["AnyDesk"]));

        var finding = await new M2_06_AnyDeskCheck(scanner, StubLog).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);   // High(20) 的 50%
        Assert.Contains("找不到連入紀錄檔", finding.Description);
    }

    [Fact]
    public async Task 有連入紀錄時明確指出是被連入()
    {
        var scanner = new FakeScanner(
            Trace(RemoteToolCatalog.AnyDesk,
                  directories: [@"C:\ProgramData\AnyDesk"],
                  logs: [@"C:\ProgramData\AnyDesk\connection_trace.txt"]),
            "Incoming 2026-05-01, 14:23  1234567890  someone");

        var finding = await new M2_06_AnyDeskCheck(scanner, StubLog).ExecuteAsync(Context(), default);

        // 「裝了」是 Warning，「有人真的連進來過」是 Fail —— 兩者的確定性差很多。
        // 且若判 Warning，單一項目只有 10 分，在 0–19 的「低」區間裡永遠出不去。
        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(20, finding.Score);
        Assert.Contains("連入", finding.Description);
        Assert.Contains(finding.Evidence, e => e.Value.Contains("1234567890", StringComparison.Ordinal));
    }

    [Fact]
    public async Task 連入紀錄的時間戳會進到證據供時間軸使用()
    {
        var scanner = new FakeScanner(
            Trace(RemoteToolCatalog.AnyDesk, logs: [@"C:\x\connection_trace.txt"]),
            "Incoming 2026-05-01, 14:23  1234567890  someone");

        var finding = await new M2_06_AnyDeskCheck(scanner, StubLog).ExecuteAsync(Context(), default);

        Assert.Contains(finding.Evidence, e => e.Timestamp.HasValue);
    }

    [Fact]
    public async Task TeamViewer走日月年格式()
    {
        var scanner = new FakeScanner(
            Trace(RemoteToolCatalog.TeamViewer, logs: [@"C:\x\Connections_incoming.txt"]),
            "1234567890 Name 05-01-2026 14:23:05 05-01-2026 14:40:11 User RemoteControl {g}");

        var finding = await new M2_07_TeamViewerCheck(scanner, StubLog).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Contains(finding.Evidence, e => e.Key.StartsWith("2026-01-05", StringComparison.Ordinal));
    }

    // ---- M2-08 ----

    [Fact]
    public void M2_08沒有痕跡判Pass()
    {
        var check = new M2_08_OtherRemoteToolsCheck(new FakeScanner(Trace(RemoteToolCatalog.AnyDesk)));

        var finding = check.Evaluate([Trace(RemoteToolCatalog.Others[0])]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M2_08偵測到工具判Warning並列出名稱()
    {
        var check = new M2_08_OtherRemoteToolsCheck(new FakeScanner(Trace(RemoteToolCatalog.AnyDesk)));

        var finding = check.Evaluate(
        [
            Trace(RemoteToolCatalog.Others[0], directories: [@"C:\Users\x\AppData\Roaming\RustDesk"]),
            Trace(RemoteToolCatalog.Others[1]),
        ]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);
        Assert.Contains(RemoteToolCatalog.Others[0].DisplayName, finding.Description);
        Assert.DoesNotContain(RemoteToolCatalog.Others[1].DisplayName, finding.Description);
    }

    // ---- 安裝時間與情境比對 ----
    //
    // 使用者往往根本不知道電腦上有這個遠端程式，「請核對是否為你本人所為」他答不出來。
    // 但「它是在你螢幕鎖定期間、而且當時有人遠端連著的時候裝上去的」不需要他回想任何事。

    private static RemoteToolTrace TraceWithInstallTime(DateTimeOffset installedAt)
        => new(RemoteToolCatalog.AnyDesk, [@"C:\ProgramData\AnyDesk"], [], [], installedAt);

    [Fact]
    public void 安裝時間會以帶時間戳的證據呈現以進入時間軸()
    {
        var installedAt = new DateTimeOffset(2026, 3, 15, 3, 22, 0, TimeSpan.FromHours(8));

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(installedAt)), StubLog)
            .Evaluate(TraceWithInstallTime(installedAt), []);

        var evidence = Assert.Single(finding.Evidence, e => e.Key.Contains("安裝時間", StringComparison.Ordinal));
        Assert.Equal(installedAt, evidence.Timestamp);
        Assert.Contains("2026-03-15 03:22", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 說明會直接問使用者認不認得這個程式()
    {
        // 這是使用者唯一答得出來的問題，比「是否為你授權」有用得多
        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(DateTimeOffset.Now)), StubLog)
            .Evaluate(TraceWithInstallTime(DateTimeOffset.Now), []);

        Assert.Contains("你認得這個程式嗎", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 安裝當下螢幕鎖定會被明確點出()
    {
        var installedAt = new DateTimeOffset(2026, 3, 15, 3, 22, 0, TimeSpan.FromHours(8));
        var context = new InstallTimeContext(0, null, ScreenWasLocked: true);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(installedAt)), StubLog)
            .Evaluate(TraceWithInstallTime(installedAt), [], context);

        Assert.Contains("螢幕是鎖定的", finding.Description, StringComparison.Ordinal);
        Assert.Contains("不是你本人在電腦前操作", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 安裝當下有遠端連線會被明確點出()
    {
        var installedAt = new DateTimeOffset(2026, 3, 15, 3, 22, 0, TimeSpan.FromHours(8));
        var context = new InstallTimeContext(2, installedAt.AddMinutes(-10), ScreenWasLocked: null);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(installedAt)), StubLog)
            .Evaluate(TraceWithInstallTime(installedAt), [], context);

        Assert.Contains("2 筆遠端連線事件", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 沒有佐證時不編造情境敘述()
    {
        // 未提權讀不到 Security 記錄、或本來就沒有遠端連線 —— 不該硬湊出一句話
        var installedAt = new DateTimeOffset(2026, 3, 15, 3, 22, 0, TimeSpan.FromHours(8));
        var context = new InstallTimeContext(0, null, ScreenWasLocked: null);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(installedAt)), StubLog)
            .Evaluate(TraceWithInstallTime(installedAt), [], context);

        Assert.DoesNotContain("不是你本人在電腦前操作", finding.Description, StringComparison.Ordinal);
        Assert.Contains("2026-03-15 03:22", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 取不到安裝時間時不影響其餘判定()
    {
        var trace = Trace(RemoteToolCatalog.AnyDesk, directories: [@"C:\ProgramData\AnyDesk"]);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(trace), StubLog).Evaluate(trace, []);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.DoesNotContain(finding.Evidence, e => e.Key.Contains("安裝時間", StringComparison.Ordinal));
    }

    // ---- 與紫P 安裝時間的比對 ----

    [Fact]
    public void 與紫P同一時段安裝會被明確點出()
    {
        // 受害者被誘導安裝遠端工具「協助處理」，對方接手後順道換掉紫P ——
        // 兩者相隔幾十分鐘不會是巧合
        var purpleAt = new DateTimeOffset(2026, 3, 15, 3, 0, 0, TimeSpan.FromHours(8));
        var toolAt = purpleAt.AddMinutes(40);
        var context = new InstallTimeContext(0, null, null, purpleAt);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(toolAt)), StubLog)
            .Evaluate(TraceWithInstallTime(toolAt), [], context);

        Assert.Contains("同一時段裝上", finding.Description, StringComparison.Ordinal);
        Assert.Contains("40 分鐘", finding.Description, StringComparison.Ordinal);
        Assert.Contains("2026-03-15 03:00", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 相隔很久時仍報出紫P安裝時間供判斷()
    {
        var purpleAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.FromHours(8));
        var toolAt = purpleAt.AddDays(60);
        var context = new InstallTimeContext(0, null, null, purpleAt);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(toolAt)), StubLog)
            .Evaluate(TraceWithInstallTime(toolAt), [], context);

        Assert.Contains("相隔約 60 天", finding.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("同一時段裝上", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 小時級距會以小時呈現()
    {
        var purpleAt = new DateTimeOffset(2026, 3, 15, 3, 0, 0, TimeSpan.FromHours(8));
        var context = new InstallTimeContext(0, null, null, purpleAt);
        var toolAt = purpleAt.AddHours(5);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(toolAt)), StubLog)
            .Evaluate(TraceWithInstallTime(toolAt), [], context);

        Assert.Contains("5 小時", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 未探測到紫P時不提及安裝時間比對()
    {
        var toolAt = new DateTimeOffset(2026, 3, 15, 3, 22, 0, TimeSpan.FromHours(8));
        var context = new InstallTimeContext(0, null, null, PurpleInstalledAt: null);

        var finding = new M2_06_AnyDeskCheck(new FakeScanner(TraceWithInstallTime(toolAt)), StubLog)
            .Evaluate(TraceWithInstallTime(toolAt), [], context);

        Assert.DoesNotContain("紫P", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void 未探測到紫P路徑時推估回null()
        => Assert.Null(InstallTimeCorrelator.EstimatePurpleInstallTime(null));

    // ---- 目錄清單健全性 ----

    [Fact]
    public void 工具清單沒有重複的顯示名稱()
    {
        var names = RemoteToolCatalog.All.Select(t => t.DisplayName).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void 每個工具至少有一種偵測特徵()
        => Assert.All(RemoteToolCatalog.All, t =>
            Assert.True(t.Directories.Count > 0 || t.ServiceNames.Count > 0,
                $"{t.DisplayName} 沒有任何偵測特徵"));

    private static Core.Abstractions.AuditContext Context() => new()
    {
        IsElevated = true,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(),
    };
}
