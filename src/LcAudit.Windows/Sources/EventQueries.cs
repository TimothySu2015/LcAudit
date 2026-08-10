namespace LcAudit.Windows.Sources;

/// <summary>
/// 事件記錄的 XPath 查詢字串組裝（純字串運算，可單元測試）。
/// <para>
/// 篩選一律下推到 XPath，不要撈回來再用 C# 過濾 —— 4624 在一般機器上動輒數萬筆，
/// 全撈會直接吃掉 NFR-01 的 3 分鐘預算。
/// </para>
/// </summary>
public static class EventQueries
{
    /// <summary>Security 記錄檔名稱。</summary>
    public const string SecurityLog = "Security";

    /// <summary>安全性記錄檔已清除。命中時 M2 全模組的 Pass 都不具意義。</summary>
    public const int EventIdLogCleared = 1102;

    public const int EventIdLogonSuccess = 4624;
    public const int EventIdLogonFailure = 4625;
    public const int EventIdWorkstationLocked = 4800;
    public const int EventIdWorkstationUnlocked = 4801;

    /// <summary>LogonType 10 = 遠端互動式登入（RDP）。</summary>
    public const int LogonTypeRemoteInteractive = 10;

    /// <summary>LogonType 3 = 網路登入（SMB／遠端 WMI 等）。</summary>
    public const int LogonTypeNetwork = 3;

    /// <summary>回溯天數換算為 timediff 的毫秒值。</summary>
    public static long LookbackMilliseconds(int days)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(days);
        return days * 86_400_000L;
    }

    /// <summary>
    /// 指定 EventID 於回溯期間內的查詢。
    /// <para>
    /// 比較運算子必須是字面的 <c>&lt;=</c>。<see cref="System.Diagnostics.Eventing.Reader.EventLogQuery"/>
    /// 收的是純 XPath 運算式，不是 XML —— 寫成 XML 跳脫的實體參考會被拒（「指定的查詢無效」），
    /// 而且錯誤會被 SafeCheckDecorator 吞成 Inconclusive，極難察覺。已實測確認。
    /// </para>
    /// </summary>
    public static string ByEventId(int eventId, int lookbackDays)
        => $"*[System[(EventID={eventId}) and TimeCreated[timediff(@SystemTime) <= {LookbackMilliseconds(lookbackDays)}]]]";

    /// <summary>多個 EventID 於回溯期間內的查詢。</summary>
    public static string ByEventIds(IReadOnlyList<int> eventIds, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(eventIds);
        ArgumentOutOfRangeException.ThrowIfZero(eventIds.Count);

        var idClause = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
        return $"*[System[({idClause}) and TimeCreated[timediff(@SystemTime) <= {LookbackMilliseconds(lookbackDays)}]]]";
    }

    /// <summary>4624 且 LogonType 為指定值的查詢。</summary>
    public static string LogonByType(int logonType, int lookbackDays)
        => ByEventId(EventIdLogonSuccess, lookbackDays)
           + $" and *[EventData[Data[@Name='LogonType']='{logonType}']]";

    /// <summary>4624 的具名欄位路徑，順序即回傳陣列的索引順序。</summary>
    public static readonly IReadOnlyList<string> LogonProperties =
    [
        "Event/EventData/Data[@Name='TargetUserName']",
        "Event/EventData/Data[@Name='TargetDomainName']",
        "Event/EventData/Data[@Name='LogonType']",
        "Event/EventData/Data[@Name='IpAddress']",
        "Event/EventData/Data[@Name='IpPort']",
        "Event/EventData/Data[@Name='WorkstationName']",
    ];

    /// <summary>4800 / 4801 的具名欄位路徑。</summary>
    public static readonly IReadOnlyList<string> SessionProperties =
    [
        "Event/EventData/Data[@Name='TargetUserName']",
        "Event/EventData/Data[@Name='TargetDomainName']",
    ];
}
