namespace LcAudit.Core.Model;

/// <summary>與事發時間相近的一筆跡證。</summary>
/// <param name="Finding">來源檢查項。</param>
/// <param name="Evidence">該筆證據。</param>
/// <param name="Offset">與事發時間的差距（負值為事發之前）。</param>
public sealed record IncidentMatch(Finding Finding, Evidence Evidence, TimeSpan Offset)
{
    /// <summary>顯示用的相對時間描述，如「事發前 12 分鐘」。</summary>
    public string Describe()
    {
        var magnitude = Offset.Duration();
        var direction = Offset < TimeSpan.Zero ? "事發前" : "事發後";

        var amount = magnitude.TotalMinutes < 1 ? "不到 1 分鐘"
            : magnitude.TotalHours < 1 ? $"{magnitude.TotalMinutes:0} 分鐘"
            : magnitude.TotalDays < 1 ? $"{magnitude.TotalHours:0.#} 小時"
            : $"{magnitude.TotalDays:0.#} 天";

        return magnitude.TotalMinutes < 1 ? "與事發時間幾乎同時" : $"{direction} {amount}";
    }

    /// <summary>
    /// 顯示用的說明文字。
    /// <para>
    /// 部分檢查項（如 M2-04）直接把時間戳當作證據的 Key，若原樣印出會讓同一個時間
    /// 在一行裡出現兩次。這種情況改用檢查項名稱當標籤。
    /// </para>
    /// </summary>
    public string Label => DateTimeOffset.TryParse(Evidence.Key, out _) ? Finding.Title : Evidence.Key;
}

/// <summary>
/// 以事發時間為錨點，把所有帶時間戳的跡證依距離排序。
/// <para>
/// 工具收集了大量時間戳 —— 遠端工具安裝時間、紫P 安裝時間、遠端登入、螢幕鎖定解鎖、
/// 帳號建立 —— 但沒有錨點時，這些只是一堆讓使用者自己比對的數字。
/// </para>
/// <para>
/// 真實案例：一台被盜帳號的電腦，AnyDesk 的安裝時間正好就是帳號被盜的時間。
/// 有了錨點，報告第一行就能寫出「AnyDesk 於 03:12 安裝，事發前 8 分鐘」，
/// 而不是讓使用者在時間軸裡自己找。
/// </para>
/// </summary>
public static class IncidentTimeline
{
    /// <summary>納入比對的範圍。超過這個距離就與事發無關了。</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromDays(3);

    /// <summary>「幾乎同時」的判定範圍 —— 落在這個區間的跡證會被特別標示。</summary>
    public static readonly TimeSpan CloseWindow = TimeSpan.FromHours(2);

    /// <summary>找出與事發時間相近的跡證，最接近的排最前面。</summary>
    public static IReadOnlyList<IncidentMatch> Build(
        IReadOnlyList<Finding> findings,
        DateTimeOffset incidentTime,
        TimeSpan? window = null)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var limit = window ?? DefaultWindow;

        return
        [
            .. findings
                .SelectMany(f => f.Evidence
                    .Where(e => e.Timestamp.HasValue)
                    .Select(e => new IncidentMatch(f, e, e.Timestamp!.Value - incidentTime)))
                .Where(m => m.Offset.Duration() <= limit)
                .OrderBy(m => m.Offset.Duration()),
        ];
    }

    /// <summary>只取「幾乎同時」的那些 —— 這些才是真正值得放在報告最前面的。</summary>
    public static IReadOnlyList<IncidentMatch> Closest(IReadOnlyList<IncidentMatch> matches)
    {
        ArgumentNullException.ThrowIfNull(matches);

        return [.. matches.Where(m => m.Offset.Duration() <= CloseWindow)];
    }
}
