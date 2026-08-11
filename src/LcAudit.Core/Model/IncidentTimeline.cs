namespace LcAudit.Core.Model;

/// <summary>
/// 事發區間。
/// <para>
/// 受害者提供的通常**不是一個時間點，而是一段範圍** —— 例如「02:00 我還在線上掛機，
/// 07:30 發現東西不見了」。真正確定的是這兩個端點，中間的「大約 04:00」只是推估。
/// </para>
/// <para>只給單一時間點時，<see cref="End"/> 等於 <see cref="Start"/>，退化為零長度區間。</para>
/// </summary>
public sealed record IncidentWindow(DateTimeOffset Start, DateTimeOffset End)
{
    public static IncidentWindow At(DateTimeOffset moment) => new(moment, moment);

    public static IncidentWindow Between(DateTimeOffset a, DateTimeOffset b)
        => a <= b ? new IncidentWindow(a, b) : new IncidentWindow(b, a);

    public bool IsRange => End > Start;

    public bool Contains(DateTimeOffset moment) => moment >= Start && moment <= End;

    /// <summary>與區間的距離。落在區間內為零，否則是到最近端點的距離（負值代表在區間之前）。</summary>
    public TimeSpan DistanceFrom(DateTimeOffset moment)
    {
        if (Contains(moment))
        {
            return TimeSpan.Zero;
        }

        return moment < Start ? moment - Start : moment - End;
    }

    public string Describe() => IsRange
        ? $"{Start:yyyy-MM-dd HH:mm} ～ {End:yyyy-MM-dd HH:mm}"
        : Start.ToString("yyyy-MM-dd HH:mm");
}

/// <summary>與事發區間相近的一筆跡證。</summary>
/// <param name="Finding">來源檢查項。</param>
/// <param name="Evidence">該筆證據。</param>
/// <param name="Offset">與事發區間的距離（零代表落在區間內，負值為區間之前）。</param>
public sealed record IncidentMatch(Finding Finding, Evidence Evidence, TimeSpan Offset)
{
    /// <summary>落在事發區間內 —— 這是最值得優先查證的一類。</summary>
    public bool IsWithinWindow => Offset == TimeSpan.Zero;

    /// <summary>顯示用的相對時間描述，如「事發前 12 分鐘」。</summary>
    public string Describe()
    {
        if (IsWithinWindow)
        {
            return "★ 就在事發區間內";
        }

        var magnitude = Offset.Duration();
        var direction = Offset < TimeSpan.Zero ? "事發前" : "事發後";

        var amount = magnitude.TotalMinutes < 1 ? "不到 1 分鐘"
            : magnitude.TotalHours < 1 ? $"{magnitude.TotalMinutes:0} 分鐘"
            : magnitude.TotalDays < 1 ? $"{magnitude.TotalHours:0.#} 小時"
            : $"{magnitude.TotalDays:0.#} 天";

        return $"{direction} {amount}";
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
    /// <summary>「相近」的判定範圍 —— 落在區間內、或距離區間這麼近的跡證會被特別標示。</summary>
    public static readonly TimeSpan CloseWindow = TimeSpan.FromHours(2);

    /// <summary>列出的筆數上限。</summary>
    public const int MaxMatches = 50;

    /// <summary>
    /// 依「與事發區間的距離」排序所有帶時間戳的跡證，最接近的排最前面。
    /// <para>
    /// <b>刻意不設距離上限。</b>入侵的原因往往遠早於受害者「發現」的時間 ——
    /// 攻擊者可能數天甚至數週前就植入了遠端工具，潛伏到適當時機才動手。
    /// 若硬性濾掉超過 N 天的事件，最關鍵的那筆證據反而會被工具默默丟掉。
    /// </para>
    /// <para>
    /// 排序後距離遠的自然沉到後面，而且描述會明講「事發前 10 天」——
    /// 相不相關由使用者判斷，不該由工具替他決定。
    /// </para>
    /// </summary>
    public static IReadOnlyList<IncidentMatch> Build(
        IReadOnlyList<Finding> findings,
        IncidentWindow window)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(window);

        return
        [
            .. findings
                .SelectMany(f => f.Evidence
                    .Where(e => e.Timestamp.HasValue)
                    .Select(e => new IncidentMatch(f, e, window.DistanceFrom(e.Timestamp!.Value))))
                .OrderBy(m => m.Offset.Duration())
                .Take(MaxMatches),
        ];
    }

    /// <summary>落在事發區間內、或距離不到 2 小時的那些 —— 最值得優先查證。</summary>
    public static IReadOnlyList<IncidentMatch> Closest(IReadOnlyList<IncidentMatch> matches)
    {
        ArgumentNullException.ThrowIfNull(matches);

        return [.. matches.Where(m => m.Offset.Duration() <= CloseWindow)];
    }
}
