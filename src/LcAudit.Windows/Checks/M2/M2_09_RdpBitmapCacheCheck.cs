using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-09 RDP Bitmap 快取。
/// <para>
/// <b>方向極易搞混</b>：這個快取是「本機**當用戶端**連出去」時產生的畫面殘影，
/// 不是別人連進來的證據。功能規格特別標注了這點。Severity Info。
/// </para>
/// <para>
/// 取證價值：快取檔可還原出當時遠端桌面的畫面片段，是重要的鑑識素材 ——
/// 但本工具唯讀，只報告存在與否，不解析內容。
/// </para>
/// </summary>
public sealed class M2_09_RdpBitmapCacheCheck : ICheck
{
    public string Id => "M2-09";

    public string Module => "M2";

    public string Title => "RDP Bitmap 快取（對外連線殘留）";

    public Severity Severity => Severity.Info;

    public string Source => @"%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Terminal Server Client", "Cache");

        if (!Directory.Exists(cachePath))
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Pass,
                "沒有 RDP Bitmap 快取，代表本機未曾以遠端桌面連線到其他主機。",
                []));
        }

        var files = new DirectoryInfo(cachePath)
            .EnumerateFiles("*", SearchOption.TopDirectoryOnly)
            .OrderByDescending(f => f.LastWriteTime)
            .Take(20)
            .ToList();

        return ValueTask.FromResult(Evaluate(cachePath, files.Count, files.Select(f =>
            new Evidence(f.Name, $"{f.Length:N0} bytes，最後寫入 {f.LastWriteTime:yyyy-MM-dd HH:mm}",
                new DateTimeOffset(f.LastWriteTime)))));
    }

    internal Finding Evaluate(string cachePath, int fileCount, IEnumerable<Evidence> fileEvidence)
    {
        ArgumentNullException.ThrowIfNull(fileEvidence);

        if (fileCount == 0)
        {
            return Build(CheckStatus.Pass, "RDP Bitmap 快取目錄存在但沒有檔案。",
                [new Evidence("快取目錄", cachePath)]);
        }

        return Build(
            CheckStatus.Pass,
            $"發現 {fileCount} 個 RDP Bitmap 快取檔 —— 代表本機曾**連出去**到其他主機（不是被連入）。"
            + "這些檔案可還原當時的遠端桌面畫面片段，若要報案請一併保存。",
            [new Evidence("快取目錄", cachePath), .. fileEvidence]);
    }

    private Finding Build(CheckStatus status, string description, IReadOnlyList<Evidence> evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Evidence = evidence,
    };
}
