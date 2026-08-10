using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M2;
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

        var finding = await new M2_06_AnyDeskCheck(scanner).ExecuteAsync(Context(), default);

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

        var finding = await new M2_06_AnyDeskCheck(scanner).ExecuteAsync(Context(), default);

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

        var finding = await new M2_06_AnyDeskCheck(scanner).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("連入", finding.Description);
        Assert.Contains(finding.Evidence, e => e.Value.Contains("1234567890", StringComparison.Ordinal));
    }

    [Fact]
    public async Task 連入紀錄的時間戳會進到證據供時間軸使用()
    {
        var scanner = new FakeScanner(
            Trace(RemoteToolCatalog.AnyDesk, logs: [@"C:\x\connection_trace.txt"]),
            "Incoming 2026-05-01, 14:23  1234567890  someone");

        var finding = await new M2_06_AnyDeskCheck(scanner).ExecuteAsync(Context(), default);

        Assert.Contains(finding.Evidence, e => e.Timestamp.HasValue);
    }

    [Fact]
    public async Task TeamViewer走日月年格式()
    {
        var scanner = new FakeScanner(
            Trace(RemoteToolCatalog.TeamViewer, logs: [@"C:\x\Connections_incoming.txt"]),
            "1234567890 Name 05-01-2026 14:23:05 05-01-2026 14:40:11 User RemoteControl {g}");

        var finding = await new M2_07_TeamViewerCheck(scanner).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Warning, finding.Status);
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
