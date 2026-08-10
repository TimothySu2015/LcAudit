using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-01 遠端互動登入（Security 4624，LogonType 10 = RDP）。
/// <para>功能規格：有紀錄 → <c>Warning</c>，並列出時間、來源 IP、帳號。Severity High。</para>
/// </summary>
public sealed class M2_01_RemoteInteractiveLogonCheck(IWindowsEventLog eventLog) : ICheck
{
    public string Id => "M2-01";

    public string Module => "M2";

    public string Title => "遠端互動登入（RDP）";

    public Severity Severity => Severity.High;

    public string Source => "Security.evtx / EventID 4624 (LogonType 10)";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var records = eventLog.Query(
            EventQueries.SecurityLog,
            EventQueries.LogonByType(EventQueries.LogonTypeRemoteInteractive, context.LookbackDays),
            EventQueries.LogonProperties,
            WindowsEventLog.DefaultMaxEvents);

        var logons = records.Select(LogonRecord.FromEvent)
                            .Where(r => !r.IsSystemAccount)
                            .ToList();

        return ValueTask.FromResult(Evaluate(logons, context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<LogonRecord> logons, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(logons);

        if (logons.Count == 0)
        {
            return new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Pass,
                Source = Source,
                Description = $"過去 {lookbackDays} 天內沒有遠端桌面登入紀錄。",
            };
        }

        var externalCount = logons.Count(l => l.Scope == Core.Validation.AddressScope.Public);

        return new Finding
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = CheckStatus.Warning,
            Source = Source,
            Description = $"過去 {lookbackDays} 天內有 {logons.Count} 次遠端桌面登入"
                          + (externalCount > 0 ? $"，其中 {externalCount} 次來自公網位址。" : "。")
                          + "若這些時間點你並未使用遠端桌面，代表主機曾被他人連入。",
            Recommendation = "逐筆核對時間與來源 IP。有不認得的紀錄請保存本報告並考慮停用遠端桌面。",
            Evidence = [.. BuildEvidence(logons)],
        };
    }

    /// <summary>依時間排序列出；同一來源 IP 另做彙總，方便看出「首見／末見」。</summary>
    private static IEnumerable<Evidence> BuildEvidence(IReadOnlyList<LogonRecord> logons)
    {
        foreach (var group in logons.GroupBy(l => l.IpAddress ?? "(未記錄)")
                                    .OrderByDescending(g => g.Count()))
        {
            var first = group.Min(l => l.Time);
            var last = group.Max(l => l.Time);
            var accounts = string.Join("、", group.Select(l => l.Account).Distinct().Order(StringComparer.Ordinal));

            yield return new Evidence(
                $"來源 {group.Key}",
                $"{group.Count()} 次，帳號：{accounts}，首見 {first:yyyy-MM-dd HH:mm}，末見 {last:yyyy-MM-dd HH:mm}",
                last);
        }

        // 最近 10 筆明細，供比對「人不在時的活動」
        foreach (var logon in logons.OrderByDescending(l => l.Time).Take(10))
        {
            yield return new Evidence(
                logon.Time.ToString("yyyy-MM-dd HH:mm:ss zzz"),
                $"{logon.Account} 自 {logon.IpAddress ?? "(未記錄)"}:{logon.IpPort ?? "-"}",
                logon.Time);
        }
    }
}
