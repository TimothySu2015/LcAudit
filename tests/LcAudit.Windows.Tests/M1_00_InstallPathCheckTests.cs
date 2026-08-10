using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M1;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class M1_00_InstallPathCheckTests
{
    private sealed class FakeProbe(PurplePathProbeResult result) : IPurplePathProbe
    {
        public int ProbeCount { get; private set; }

        public PurplePathProbeResult Probe()
        {
            ProbeCount++;
            return result;
        }
    }

    private static AuditContext Context(string? purplePath = null) => new()
    {
        IsElevated = true,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(),
        PurpleInstallPath = purplePath,
    };

    [Fact]
    public async Task 探測成功時寫回AuditContext()
    {
        var probe = new FakeProbe(new PurplePathProbeResult(
            @"C:\Program Files\NCSOFT\PURPLE", "登錄檔 Uninstall 鍵", ["登錄檔 Uninstall 鍵"]));
        var context = Context();

        var finding = await new M1_00_InstallPathCheck(probe).ExecuteAsync(context, default);

        Assert.Equal(CheckStatus.Pass, finding.Status);
        // 這是 M1 其餘項的前提 —— 沒寫回去，M1-01/M1-02 就永遠 Inconclusive
        Assert.Equal(@"C:\Program Files\NCSOFT\PURPLE", context.PurpleInstallPath);
    }

    [Fact]
    public async Task 探測失敗時判Inconclusive並列出嘗試過的來源()
    {
        var probe = new FakeProbe(new PurplePathProbeResult(
            null, null, ["登錄檔 Uninstall 鍵", "常見安裝路徑", "執行中處理程序"]));

        var finding = await new M1_00_InstallPathCheck(probe).ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Equal(3, finding.Evidence.Count);
        Assert.Contains("--purple-path", finding.Recommendation);
    }

    [Fact]
    public async Task 使用者指定路徑時完全不做探測()
    {
        var probe = new FakeProbe(new PurplePathProbeResult(@"D:\探測到的", "登錄檔", []));
        var context = Context(@"D:\使用者指定");

        var finding = await new M1_00_InstallPathCheck(probe).ExecuteAsync(context, default);

        Assert.Equal(0, probe.ProbeCount);
        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(@"D:\使用者指定", context.PurpleInstallPath);
    }

    [Fact]
    public async Task 探測失敗不計分()
    {
        var probe = new FakeProbe(new PurplePathProbeResult(null, null, ["登錄檔"]));

        var finding = await new M1_00_InstallPathCheck(probe).ExecuteAsync(Context(), default);

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(0, finding.Score);
    }
}
