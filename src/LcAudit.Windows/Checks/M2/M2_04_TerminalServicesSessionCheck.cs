using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
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

        if (records.Count == 0)
        {
            return new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Pass,
                Source = Source,
                Description = $"過去 {lookbackDays} 天內沒有終端服務工作階段紀錄。",
            };
        }

        // 只有「登入」與「重新連線」代表有人實際連進來；中斷與登出是其配套事件。
        var logons = records.Count(r => r.EventId is 21 or 25);

        return new Finding
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = CheckStatus.Warning,
            Source = Source,
            Description = $"過去 {lookbackDays} 天內有 {records.Count} 筆終端服務事件"
                          + $"（其中 {logons} 次為登入或重新連線）。"
                          + "若這些時間點你並未使用遠端桌面，代表主機曾被他人連入。",
            Recommendation = "核對時間軸與來源位址。有不認得的紀錄請保存本報告並停用遠端桌面。",
            Evidence =
            [
                .. records.OrderByDescending(r => r.TimeCreated)
                          .Take(30)
                          .Select(r => new Evidence(
                              r.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
                              $"{EventNames.GetValueOrDefault(r.EventId, $"EventID {r.EventId}")}"
                              + $"｜使用者 {r.Property(0) ?? "(未記錄)"}"
                              + $"｜來源 {r.Property(1) ?? "(未記錄)"}",
                              r.TimeCreated)),
            ],
        };
    }
}
