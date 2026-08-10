using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Validation;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-04 終端服務工作階段。
/// <para>
/// 功能規格：<c>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</c>
/// 的 EventID 21/22/23/24/25，有紀錄則列出時間軸。Severity High。
/// </para>
/// <para>
/// 這個記錄檔不需系統管理員權限即可讀取，因此未提權時它是 M2 少數仍能運作的項目 ——
/// 也是未提權執行時最有價值的遠端存取跡證來源。
/// </para>
/// </summary>
public sealed class M2_04_TerminalServicesSessionCheck(IWindowsEventLog eventLog) : ICheck
{
    internal const string LogName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

    /// <summary>21=工作階段登入，22=Shell 啟動，23=登出，24=中斷連線，25=重新連線。</summary>
    internal static readonly IReadOnlyList<int> SessionEventIds = [21, 22, 23, 24, 25];

    private static readonly IReadOnlyDictionary<int, string> EventNames = new Dictionary<int, string>
    {
        [21] = "工作階段登入",
        [22] = "Shell 啟動",
        [23] = "工作階段登出",
        [24] = "工作階段中斷連線",
        [25] = "工作階段重新連線",
    };

    public string Id => "M2-04";

    public string Module => "M2";

    public string Title => "終端服務工作階段";

    public Severity Severity => Severity.High;

    public string Source => LogName;

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        // 從未使用過遠端桌面的機器可能根本沒有這個記錄檔 —— 那是「查不到」而非「執行失敗」。
        if (!eventLog.LogExists(LogName))
        {
            return ValueTask.FromResult(new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Inconclusive,
                Source = Source,
                Description = "本機沒有終端服務工作階段記錄檔，通常代表從未啟用過遠端桌面功能。",
            });
        }

        var records = eventLog.Query(
            LogName,
            EventQueries.ByEventIds(SessionEventIds, context.LookbackDays),
            ["Event/UserData/EventXML/User", "Event/UserData/EventXML/Address"],
            WindowsEventLog.DefaultMaxEvents);

        return ValueTask.FromResult(Evaluate(records, context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<EventRecordData> records, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(records);

        // 這個記錄檔**也會記錄本機主控台的登入登出** —— 使用者自己開關機、鎖定解鎖
        // 都會產生事件，來源欄位是「本機」（在地化字串）或空值。
        //
        // 原本不分來源全部計入，導致一台從未被遠端連入的機器出現「52 筆終端服務事件，
        // 主機曾被他人連入」。實測那 52 筆裡遠端來源是 0 筆。
        //
        // 判定方式：來源欄位能解析成 IP 位址才算遠端。這樣不必依賴「本機」/"LOCAL"
        // 這種會隨系統語言變動的字串。
        var remote = records
            .Where(r => PrivateAddressClassifier.Classify(r.Property(1))
                        is AddressScope.Public or AddressScope.Private)
            .ToList();

        if (remote.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                records.Count == 0
                    ? $"過去 {lookbackDays} 天內沒有終端服務工作階段紀錄。"
                    : $"過去 {lookbackDays} 天內有 {records.Count} 筆終端服務事件，"
                      + "但全部來自本機主控台（也就是你自己在這台電腦前登入／登出），"
                      + "沒有任何一筆來自遠端。",
                null,
                []);
        }

        // 只有「登入」與「重新連線」代表有人實際連進來；中斷與登出是其配套事件。
        var logons = remote.Count(r => r.EventId is 21 or 25);

        return Build(
            CheckStatus.Warning,
            $"過去 {lookbackDays} 天內有 {remote.Count} 筆**來自遠端**的終端服務事件"
            + $"（其中 {logons} 次為登入或重新連線）。"
            + (records.Count > remote.Count
                ? $"另有 {records.Count - remote.Count} 筆來自本機主控台，已排除不計。"
                : string.Empty)
            + "若這些時間點你並未使用遠端桌面，代表主機曾被他人連入。",
            "核對時間軸與來源位址。有不認得的紀錄請保存本報告並停用遠端桌面。",
            [
                .. remote.OrderByDescending(r => r.TimeCreated)
                         .Take(30)
                         .Select(r => new Evidence(
                             r.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
                             $"{EventNames.GetValueOrDefault(r.EventId, $"EventID {r.EventId}")}"
                             + $"｜使用者 {r.Property(0) ?? "(未記錄)"}"
                             + $"｜來源 {r.Property(1) ?? "(未記錄)"}",
                             r.TimeCreated)),
            ]);
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
