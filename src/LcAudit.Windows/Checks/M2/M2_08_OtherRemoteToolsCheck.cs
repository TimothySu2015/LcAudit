using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources.RemoteTools;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-08 其他遠端工具痕跡（RustDesk / ToDesk / 向日葵 / AweSun / AnyViewer /
/// DeskIn / ScreenConnect / Atera 等）。
/// <para>功能規格：偵測到 → <c>Warning</c>。Severity High。</para>
/// </summary>
public sealed class M2_08_OtherRemoteToolsCheck(IRemoteToolScanner scanner) : ICheck
{
    private DateTimeOffset? _purpleInstalledAt;

    public string Id => "M2-08";

    public string Module => "M2";

    public string Title => "其他遠端工具痕跡";

    public Severity Severity => Severity.High;

    public string Source => "檔案系統 + HKLM\\SYSTEM\\CurrentControlSet\\Services";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var traces = RemoteToolCatalog.Others.Select(scanner.Scan).ToList();
        _purpleInstalledAt = InstallTimeCorrelator.EstimatePurpleInstallTime(context.PurpleInstallPath);

        return ValueTask.FromResult(Evaluate(traces));
    }

    internal Finding Evaluate(IReadOnlyList<RemoteToolTrace> traces)
    {
        ArgumentNullException.ThrowIfNull(traces);

        var found = traces.Where(t => t.HasTrace).ToList();

        if (found.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"未偵測到清單中 {traces.Count} 種遠端工具的痕跡。",
                null,
                []);
        }

        var names = string.Join("、", found.Select(t => t.Tool.DisplayName));
        var evidence = new List<Evidence>();

        foreach (var trace in found)
        {
            // 安裝時間放在每個工具的最前面 —— 使用者往往不知道電腦上有這些程式，
            // 一個具體時間點比「請你回想有沒有授權過」有用得多
            if (trace.InstalledAt is { } installedAt)
            {
                evidence.Add(new Evidence(
                    $"{trace.Tool.DisplayName} 安裝時間（推估）",
                    installedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                    installedAt));
            }

            foreach (var directory in trace.FoundDirectories)
            {
                evidence.Add(new Evidence($"{trace.Tool.DisplayName} 目錄", directory));
            }

            foreach (var service in trace.FoundServices)
            {
                evidence.Add(new Evidence($"{trace.Tool.DisplayName} 服務", service));
            }
        }

        var installTimes = found
            .Where(t => t.InstalledAt.HasValue)
            .Select(t => $"{t.Tool.DisplayName}（{t.InstalledAt!.Value:yyyy-MM-dd HH:mm}）")
            .ToList();

        // 與紫P 同一時段裝上的，通常是同一次入侵過程的兩個步驟
        var sameSession = _purpleInstalledAt is { } purpleTime
            ? found.Where(t => t.InstalledAt is { } at
                               && (at - purpleTime).Duration() <= InstallTimeCorrelator.SameSessionWindow)
                   .Select(t => t.Tool.DisplayName)
                   .ToList()
            : [];

        var proximity = sameSession.Count > 0 && _purpleInstalledAt is { } pt
            ? $"**其中 {string.Join("、", sameSession)} 與紫P 幾乎是同一時段裝上的**"
              + $"（紫P 安裝於 {pt:yyyy-MM-dd HH:mm}）—— 同一時段出現這兩件事通常不是巧合。"
            : string.Empty;

        return Build(
            CheckStatus.Warning,
            $"偵測到 {found.Count} 種遠端存取工具：{names}。"
            + (installTimes.Count > 0 ? $"安裝時間約為 {string.Join("、", installTimes)}。" : string.Empty)
            + proximity
            + "**你認得這些程式嗎？如果完全沒印象裝過，那就是答案。**"
            + "這類工具本身合法，但也是帳號被盜案件中最常見的入侵管道 —— "
            + "受害者常在被誘導「協助處理問題」時自己裝上，之後對方就能隨時連入。",
            "沒印象裝過的直接移除，並在**另一台乾淨裝置**上更改所有帳號密碼。移除前請先保存本報告。"
            + "對照上面的安裝時間與報告中的時間軸，看看那個時間點你人在不在電腦前。",
            evidence);
    }

    private Finding Build(
        CheckStatus status,
        string description,
        string? recommendation,
        IReadOnlyList<Evidence> evidence) => new()
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = status,
            Source = Source,
            Description = description,
            Recommendation = recommendation,
            Evidence = evidence,
        };
}
