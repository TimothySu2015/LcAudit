using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-10 螢幕鎖定／解鎖時間軸（Security 4800 / 4801）。
/// <para>
/// 功能規格：建立活動時間軸供比對「人不在時的活動」。Severity Info —— 本身不判異常，
/// 價值在於讓使用者能對照「這個時間我人不在電腦前」。
/// </para>
/// </summary>
public sealed class M2_10_LockUnlockTimelineCheck(IWindowsEventLog eventLog) : ICheck
{
    public string Id => "M2-10";

    public string Module => "M2";

    public string Title => "螢幕鎖定／解鎖時間軸";

    public Severity Severity => Severity.Info;

    public string Source => "Security.evtx / EventID 4800, 4801";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var records = eventLog.Query(
            EventQueries.SecurityLog,
            EventQueries.ByEventIds(
                [EventQueries.EventIdWorkstationLocked, EventQueries.EventIdWorkstationUnlocked],
                context.LookbackDays),
            EventQueries.SessionProperties,
            WindowsEventLog.DefaultMaxEvents);

        return ValueTask.FromResult(Evaluate(records, context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<EventRecordData> records, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(records);

        if (records.Count == 0)
        {
            return Build(CheckStatus.Pass, $"過去 {lookbackDays} 天內沒有螢幕鎖定／解鎖紀錄。", []);
        }

        var locks = records.Count(r => r.EventId == EventQueries.EventIdWorkstationLocked);
        var unlocks = records.Count - locks;

        return Build(
            CheckStatus.Pass,
            $"過去 {lookbackDays} 天內有 {locks} 次鎖定、{unlocks} 次解鎖。"
            + "請對照其他模組的時間軸 —— 若在「螢幕鎖定期間」出現登入或程式安裝活動，那不會是你本人做的。",
            [
                .. records.OrderByDescending(r => r.TimeCreated)
                          .Take(50)
                          .Select(r => new Evidence(
                              r.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
                              (r.EventId == EventQueries.EventIdWorkstationLocked ? "鎖定" : "解鎖")
                              + $"｜{r.Property(1)}\\{r.Property(0)}",
                              r.TimeCreated)),
            ]);
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
