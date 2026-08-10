using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Validation;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-04 安裝檔下載來源。
/// <para>
/// 功能規格：<c>HostUrl</c>／<c>ReferrerUrl</c> 網域不在白名單 → <c>Fail</c>；
/// 完全沒有 MOTW → <c>Warning</c>。Severity <b>Critical</b>。
/// </para>
/// <para>
/// 白名單比對走 <see cref="DownloadHostValidator"/> —— 後綴比對，不是 Contains。
/// </para>
/// </summary>
public sealed class M1_04_DownloadSourceCheck(IZoneIdentifierReader zoneReader) : ICheck
{
    public string Id => "M1-04";

    public string Module => "M1";

    public string Title => "安裝檔下載來源";

    public Severity Severity => Severity.Critical;

    public string Source => "Zone.Identifier ADS（Mark of the Web）";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "未取得紫P 主程式路徑，無法檢查下載來源。",
                "可用 --purple-path 手動指定安裝目錄後重新執行。",
                []));
        }

        return ValueTask.FromResult(Evaluate(zoneReader.Read(executable), executable));
    }

    internal Finding Evaluate(ZoneIdentifier? zone, string filePath)
    {
        var evidence = new List<Evidence> { new("檔案路徑", filePath) };

        if (zone is null)
        {
            return Build(
                CheckStatus.Warning,
                "主程式沒有 Mark of the Web 記錄，無法得知下載來源。"
                + "可能是正常解壓縮或安裝程式所致，也可能是攻擊者刻意剝除了來源標記。",
                "若你記得是從官網下載的，可忽略；不確定的話建議從官網重新下載安裝。",
                evidence);
        }

        evidence.Add(new Evidence("ZoneId", zone.ZoneId?.ToString() ?? "(未記錄)"));
        evidence.Add(new Evidence("HostUrl", zone.HostUrl ?? "(未記錄)"));
        evidence.Add(new Evidence("ReferrerUrl", zone.ReferrerUrl ?? "(未記錄)"));

        // 兩個 URL 都要通過白名單；任一不通過即 Fail（技術設計 §4.5）
        var badUrls = new[] { zone.HostUrl, zone.ReferrerUrl }
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Where(url => !DownloadHostValidator.IsAllowedDownloadHost(url))
            .ToList();

        if (badUrls.Count > 0)
        {
            return Build(
                CheckStatus.Fail,
                $"主程式的下載來源不是官方網域：{string.Join("、", badUrls)}。"
                + $"官方網域只有 {string.Join("、", DownloadHostValidator.AllowedHosts)}。"
                + "從非官方來源取得的紫P 極可能被植入後門。",
                "立即停止使用此電腦登入遊戲，保存本報告後重灌系統，並在乾淨裝置上更改密碼。",
                evidence);
        }

        if (zone.HostUrl is null && zone.ReferrerUrl is null)
        {
            return Build(
                CheckStatus.Warning,
                "主程式有 Mark of the Web，但沒有記錄下載來源網址，無法驗證來源。",
                "不確定來源的話，建議從官網重新下載安裝。",
                evidence);
        }

        return Build(
            CheckStatus.Pass,
            "主程式的下載來源為官方網域。",
            null,
            evidence);
    }

    private Finding Build(
        CheckStatus status, string description, string? recommendation, IReadOnlyList<Evidence> evidence)
        => new()
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
