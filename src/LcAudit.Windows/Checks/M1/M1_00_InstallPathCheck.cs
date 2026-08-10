using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-00 探測紫P 安裝路徑。
/// <para>
/// 這是 M1 唯一會寫入 <see cref="AuditContext"/> 的檢查項 —— 探測結果供 M1 其餘項
/// 與 M4-01 使用。因此它必須最先執行（由 <c>AuditRunner</c> 依 Id 排序保證）。
/// </para>
/// <para>Severity 為 <c>Info</c>：找不到安裝路徑本身不是風險，只是無法繼續檢查。</para>
/// </summary>
public sealed class M1_00_InstallPathCheck(IPurplePathProbe probe) : ICheck
{
    public string Id => "M1-00";

    public string Module => "M1";

    public string Title => "探測紫P 安裝路徑";

    public Severity Severity => Severity.Info;

    public string Source => "登錄檔 Uninstall 鍵 / 常見安裝路徑 / 執行中處理程序";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        // 使用者以 --purple-path 明確指定時，跳過探測直接採用。
        if (!string.IsNullOrWhiteSpace(context.PurpleInstallPath))
        {
            return ValueTask.FromResult(Found(context.PurpleInstallPath, "使用者以 --purple-path 指定"));
        }

        var result = probe.Probe();
        if (result.InstallPath is null)
        {
            return ValueTask.FromResult(NotFound(result.AttemptedSources));
        }

        // 這裡是 M1 其餘項的前提，寫入後才輪到 M1-01 執行。
        context.PurpleInstallPath = result.InstallPath;

        return ValueTask.FromResult(Found(result.InstallPath, result.DiscoveredVia!));
    }

    private Finding Found(string installPath, string discoveredVia) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = CheckStatus.Pass,
        Source = Source,
        Description = $"已定位紫P 安裝路徑（來源：{discoveredVia}）。",
        Evidence =
        [
            new Evidence("安裝路徑", installPath),
            new Evidence("探測來源", discoveredVia),
        ],
    };

    private Finding NotFound(IReadOnlyList<string> attempted) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = CheckStatus.Inconclusive,
        Source = Source,
        Description = $"找不到紫P 安裝路徑（已嘗試：{string.Join("、", attempted)}）。M1 其餘檢查項將無法執行。",
        Recommendation = "若確實已安裝，請以 --purple-path \"安裝目錄\" 手動指定後重新執行。",
        Evidence = [.. attempted.Select(s => new Evidence("已嘗試來源", s))],
    };
}
