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
            foreach (var directory in trace.FoundDirectories)
            {
                evidence.Add(new Evidence($"{trace.Tool.DisplayName} 目錄", directory));
            }

            foreach (var service in trace.FoundServices)
            {
                evidence.Add(new Evidence($"{trace.Tool.DisplayName} 服務", service));
            }
        }

        return Build(
            CheckStatus.Warning,
            $"偵測到 {found.Count} 種遠端存取工具：{names}。"
            + "這類工具本身合法，但也是帳號被盜案件中最常見的入侵管道 —— "
            + "受害者常在被誘導「協助處理」時自行安裝，之後對方就能隨時連入。",
            "確認每一項是否為你本人安裝且仍需要。不需要的請移除；需要的請確認密碼與存取權限設定。",
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
