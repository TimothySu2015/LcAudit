using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Windows.Checks.M3;

/// <summary>
/// M3-13 Hosts 檔竄改。
/// <para>
/// 功能規格：含 <c>plaync</c>／<c>ncsoft</c>／<c>google</c> 相關導向 → <c>Fail</c>，
/// Severity <b>Critical</b>。
/// </para>
/// <para>
/// 把官方網域導到攻擊者主機，就能在使用者「確定自己連的是官網」的情況下攔截帳密。
/// 這是釣魚手法中最難察覺的一種 —— 網址列完全正確。
/// </para>
/// </summary>
public sealed class M3_13_HostsFileCheck : ICheck
{
    /// <summary>命中即視為針對性竄改的關鍵字。</summary>
    internal static readonly IReadOnlyList<string> SensitiveKeywords =
    [
        "plaync", "ncsoft", "playnccdn", "lineage", "google", "gamania", "beanfun",
    ];

    public string Id => "M3-13";

    public string Module => "M3";

    public string Title => "Hosts 檔竄改";

    public Severity Severity => Severity.Critical;

    public string Source => @"%SystemRoot%\System32\drivers\etc\hosts";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        if (!File.Exists(path))
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive, "找不到 hosts 檔。", null, []));
        }

        // share mode 給滿，避免干擾其他正在讀寫此檔的程序
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);

        return ValueTask.FromResult(Evaluate(reader.ReadToEnd(), path));
    }

    /// <summary>純判定邏輯，可用字串直接測試。</summary>
    internal Finding Evaluate(string content, string path)
    {
        ArgumentNullException.ThrowIfNull(content);

        var entries = ParseEntries(content).ToList();

        if (entries.Count == 0)
        {
            return Build(CheckStatus.Pass, "hosts 檔沒有任何自訂對應（僅註解或空白）。", null,
                [new Evidence("檔案路徑", path)]);
        }

        var sensitive = entries
            .Where(e => SensitiveKeywords.Any(k =>
                e.HostName.Contains(k, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var evidence = new List<Evidence> { new("檔案路徑", path) };
        evidence.AddRange(entries.Select(e => new Evidence(
            sensitive.Contains(e) ? "⚠ 可疑對應" : "自訂對應",
            $"{e.Address}　{e.HostName}")));

        if (sensitive.Count > 0)
        {
            var hosts = string.Join("、", sensitive.Select(e => e.HostName).Distinct(StringComparer.OrdinalIgnoreCase));

            return Build(
                CheckStatus.Fail,
                $"hosts 檔中有 {sensitive.Count} 筆指向遊戲或入口網站的對應：{hosts}。"
                + "這會讓你連到官網時實際被導向他人主機 —— 網址列顯示正確，但帳密送到了攻擊者手上。",
                "立即保存本報告，移除這些對應（需系統管理員權限），並在乾淨裝置上更改所有密碼。",
                evidence);
        }

        // 不判 Warning。功能規格只定義「含遊戲／入口網站導向 → Fail」，
        // 而本項是 Critical —— 一個 Warning 就是 20 分。廣告阻擋、開發用途的自訂對應
        // 相當常見，為此讓正常機器背 20 分並不合理。改為 Pass 但完整列出供人工過目。
        return Build(
            CheckStatus.Pass,
            $"hosts 檔有 {entries.Count} 筆自訂對應，都不涉及遊戲或入口網站"
            + "（常見於廣告阻擋或開發用途）。已於證據區完整列出，請自行確認是你加的。",
            null,
            evidence);
    }

    /// <summary>剖析 hosts 格式；忽略註解與空白行，一行可對應多個主機名。</summary>
    internal static IEnumerable<(string Address, string HostName)> ParseEntries(string content)
    {
        foreach (var rawLine in content.Split('\n'))
        {
            // 去掉行內註解 —— "127.0.0.1 evil.com # 偽裝成註解" 的前半段仍然生效
            var line = rawLine.Split('#')[0].Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var fields = line.Split([' ', '\t'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2)
            {
                continue;
            }

            for (var i = 1; i < fields.Length; i++)
            {
                yield return (fields[0], fields[i]);
            }
        }
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
