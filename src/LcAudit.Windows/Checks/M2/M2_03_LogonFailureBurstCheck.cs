using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-03 登入失敗爆量（Security 4625）。
/// <para>功能規格：單一小時內 ≥ 10 次 → <c>Warning</c>。Severity Medium。</para>
/// </summary>
public sealed class M2_03_LogonFailureBurstCheck(IWindowsEventLog eventLog) : ICheck
{
    /// <summary>單一小時內的失敗次數門檻（功能規格 M2-03）。</summary>
    internal const int BurstThreshold = 10;

    public string Id => "M2-03";

    public string Module => "M2";

    public string Title => "登入失敗爆量";

    public Severity Severity => Severity.Medium;

    public string Source => "Security.evtx / EventID 4625";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var records = eventLog.Query(
            EventQueries.SecurityLog,
            EventQueries.ByEventId(EventQueries.EventIdLogonFailure, context.LookbackDays),
            EventQueries.LogonProperties,
            WindowsEventLog.DefaultMaxEvents);

        var failures = records.Select(LogonRecord.FromEvent).ToList();

        return ValueTask.FromResult(Evaluate(failures, context.LookbackDays));
    }

    /// <summary>純判定：以「整點小時」分桶計數，任一桶達門檻即 Warning。</summary>
    internal Finding Evaluate(IReadOnlyList<LogonRecord> failures, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(failures);

        var buckets = failures
            .GroupBy(f => new DateTimeOffset(f.Time.Year, f.Time.Month, f.Time.Day, f.Time.Hour, 0, 0, f.Time.Offset))
            .Where(g => g.Count() >= BurstThreshold)
            .OrderByDescending(g => g.Count())
            .ToList();

        if (buckets.Count == 0)
        {
            return new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Pass,
                Source = Source,
                Description = $"過去 {lookbackDays} 天內共 {failures.Count} 次登入失敗，"
                              + $"未出現單一小時 {BurstThreshold} 次以上的密集失敗。",
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
            Description = $"偵測到 {buckets.Count} 個小時區間出現密集登入失敗"
                          + $"（單一小時 ≥ {BurstThreshold} 次），符合密碼暴力破解的樣式。",
            Recommendation = "確認是否為自己輸錯密碼。若非，代表有人在嘗試登入本機，建議停用遠端桌面並更改密碼。",
            Evidence =
            [
                .. buckets.Take(10).Select(b => new Evidence(
                    b.Key.ToString("yyyy-MM-dd HH:00"),
                    $"{b.Count()} 次失敗，帳號："
                    + string.Join("、", b.Select(f => f.Account).Distinct().Order(StringComparer.Ordinal).Take(5)),
                    b.Key)),
            ],
        };
    }
}
