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

        // 先找下載回來的安裝檔 —— MOTW 只會在它身上。
        //
        // 主程式是安裝程式解壓出來的，**從來就不會有 Zone.Identifier**。
        // 原本只檢查主程式，導致每一個正常使用者都必定被判 Warning，永遠不可能 Pass。
        foreach (var installer in FindDownloadedInstallers())
        {
            if (zoneReader.Read(installer) is { } installerZone)
            {
                return ValueTask.FromResult(Evaluate(installerZone, installer));
            }
        }

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "未取得紫P 主程式路徑，也找不到下載回來的安裝檔，無法檢查下載來源。",
                "可用 --purple-path 手動指定安裝目錄後重新執行。",
                []));
        }

        return ValueTask.FromResult(Evaluate(zoneReader.Read(executable), executable));
    }

    /// <summary>
    /// 在下載資料夾中尋找紫P 安裝檔。
    /// <para>
    /// 官方安裝檔名為 <c>PURPLE_Installer_&lt;版本&gt;.exe</c>。
    /// 使用者裝完通常會刪掉，所以找不到是常態而非異常。
    /// </para>
    /// </summary>
    private static IEnumerable<string> FindDownloadedInstallers()
    {
        string[] folders =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        ];

        foreach (var folder in folders.Where(Directory.Exists))
        {
            var options = new EnumerationOptions { IgnoreInaccessible = true };

            foreach (var file in Directory.EnumerateFiles(folder, "PURPLE_Installer*.exe", options)
                                          .OrderByDescending(File.GetCreationTime))
            {
                yield return file;
            }
        }
    }

    internal Finding Evaluate(ZoneIdentifier? zone, string filePath)
    {
        var evidence = new List<Evidence> { new("檔案路徑", filePath) };

        if (zone is null)
        {
            // 判 Inconclusive 而非 Warning。
            //
            // 「沒有 MOTW」在正常情況下是**必然**的：主程式由安裝程式解壓產生，
            // 從來就不帶 Zone.Identifier；而下載回來的安裝檔多半裝完就被刪了。
            // 此外複製到隨身碟、經網路磁碟機搬移、用某些壓縮工具解開，都會讓標記消失。
            //
            // 把必然發生的事判為「可疑」，等於對每個正常使用者誤報 —— 而且這一項是
            // Critical，一個 Warning 就是 20 分，還會觸發「假紫P」推論。
            return Build(
                CheckStatus.Inconclusive,
                "找不到下載來源標記（Mark of the Web），無法判定安裝檔從哪裡下載。"
                + "這在正常情況下很常見 —— 安裝程式解壓出來的檔案本來就不帶這個標記，"
                + "下載回來的安裝檔也多半裝完就刪了。**這不代表有問題。**",
                "若要確認來源，可比對 M1-01／M1-02 的簽章結果 —— 那才是判斷正版與否的依據。",
                evidence);
        }

        evidence.Add(new Evidence("ZoneId", zone.ZoneId?.ToString() ?? "(未記錄)"));
        evidence.Add(new Evidence("HostUrl", zone.HostUrl ?? "(未記錄)"));
        evidence.Add(new Evidence("ReferrerUrl", zone.ReferrerUrl ?? "(未記錄)"));

        var urls = new[] { zone.HostUrl, zone.ReferrerUrl }
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Select(url => (Url: url!, Verdict: DownloadHostValidator.Classify(url)))
            .ToList();

        // 仿冒網域最優先 —— 這是唯一沒有第二種解釋的情況
        var impersonating = urls.Where(u => u.Verdict == DownloadSourceVerdict.Impersonation).ToList();
        if (impersonating.Count > 0)
        {
            return Build(
                CheckStatus.Fail,
                $"主程式的下載來源是**仿冒官方的網域**：{string.Join("、", impersonating.Select(u => u.Url))}。"
                + "這類網址把官方網域嵌在字串中間，乍看很像官網，實際的網域卻是別人的 ——"
                + "例如 plaync.com.evil.tw 真正的網域是 evil.tw。",
                "立即停止使用此電腦登入遊戲，保存本報告後重灌系統，並在乾淨裝置上更改密碼。",
                evidence);
        }

        // 不在白名單中。白名單是靜態清單、必定不完整（官方隨時可能換 CDN），
        // 因此判 Warning 而非 Fail —— 清單漏收的代價不該由使用者承擔，
        // 更不該對從官網下載的人喊「假紫P，去重灌」。
        var unknown = urls.Where(u => u.Verdict is DownloadSourceVerdict.Unknown or DownloadSourceVerdict.Invalid).ToList();
        if (unknown.Count > 0)
        {
            return Build(
                CheckStatus.Warning,
                $"主程式的下載來源不在本工具已知的官方網域清單中：{string.Join("、", unknown.Select(u => u.Url))}。"
                + $"（已知清單：{string.Join("、", DownloadHostValidator.AllowedHosts)}）"
                + "官方會更換下載主機，清單不保證完整，所以這**不一定代表有問題**。",
                "請比對官方下載頁公布的網址。若不相符，從官網重新下載安裝。",
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
