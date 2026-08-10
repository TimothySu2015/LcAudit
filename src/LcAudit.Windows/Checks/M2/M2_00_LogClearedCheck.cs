using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// 安全性記錄檔是否曾被清除（Security 1102）。
/// <para>
/// 技術設計 §4.6 的「額外必做」。命中時 M2 其餘項的 <c>Pass</c> 都不具意義 ——
/// 攻擊者取得管理員權限後清除記錄，正是為了讓這類稽核查不到東西（已知限制 L-01）。
/// </para>
/// <para>
/// 編號用 M2-00 讓它排在 M2 最前面執行，結論才能寫在其餘項之前。
/// </para>
/// </summary>
public sealed class M2_00_LogClearedCheck(IWindowsEventLog eventLog) : ICheck
{
    public string Id => "M2-00";

    public string Module => "M2";

    public string Title => "安全性記錄檔是否曾被清除";

    public Severity Severity => Severity.High;

    public string Source => "Security.evtx / EventID 1102";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var records = eventLog.Query(
            EventQueries.SecurityLog,
            EventQueries.ByEventId(EventQueries.EventIdLogCleared, context.LookbackDays),
            [],
            WindowsEventLog.DefaultMaxEvents);

        return ValueTask.FromResult(Evaluate([.. records.Select(r => r.TimeCreated)], context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<DateTimeOffset> clearTimes, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(clearTimes);

        if (clearTimes.Count == 0)
        {
            return new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Pass,
                Source = Source,
                Description = $"過去 {lookbackDays} 天內沒有安全性記錄檔被清除的紀錄。",
            };
        }

        return new Finding
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = CheckStatus.Warning,
            Source = Source,
            Description = $"安全性記錄檔曾被清除 {clearTimes.Count} 次。"
                          + "清除記錄需要管理員權限，且是入侵者湮滅跡證的典型動作。"
                          + "**本模組其餘項目若判定為「通過」，並不代表安全 —— 相關證據可能已被刪除。**",
            Recommendation = "把清除時間點視為可疑時段，對照該時段前後的其他跡證。日後請調高事件記錄的保留大小。",
            Evidence =
            [
                .. clearTimes.OrderDescending()
                             .Take(10)
                             .Select(t => new Evidence("清除時間", t.ToString("yyyy-MM-dd HH:mm:ss zzz"), t)),
            ],
        };
    }
}
