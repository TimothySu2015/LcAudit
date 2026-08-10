using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Validation;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-02 網路登入（Security 4624，LogonType 3）。
/// <para>
/// 功能規格：排除 ANONYMOUS LOGON 與電腦帳號後，來源 IP 非私有網段 → <c>Fail</c>。Severity High。
/// </para>
/// <para>
/// 私有網段的認定見 <see cref="PrivateAddressClassifier"/> —— 漏掉 CGNAT 或 link-local
/// 會讓正常的區網存取被判為 Fail。
/// </para>
/// </summary>
public sealed class M2_02_NetworkLogonCheck(IWindowsEventLog eventLog) : ICheck
{
    public string Id => "M2-02";

    public string Module => "M2";

    public string Title => "來自公網的網路登入";

    public Severity Severity => Severity.High;

    public string Source => "Security.evtx / EventID 4624 (LogonType 3)";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var records = eventLog.Query(
            EventQueries.SecurityLog,
            EventQueries.LogonByType(EventQueries.LogonTypeNetwork, context.LookbackDays),
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

        var external = logons.Where(l => l.Scope == AddressScope.Public).ToList();

        if (external.Count == 0)
        {
            return new Finding
            {
                Id = Id,
                Module = Module,
                Title = Title,
                Severity = Severity,
                Status = CheckStatus.Pass,
                Source = Source,
                Description = $"過去 {lookbackDays} 天內的網路登入（共 {logons.Count} 次）皆來自私有網段或本機。",
            };
        }

        return new Finding
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = CheckStatus.Fail,
            Source = Source,
            Description = $"偵測到 {external.Count} 次來自公網位址的網路登入。"
                          + "家用電腦不應該有來自網際網路的直接登入 —— 這通常代表主機曝露在公網上，或已被入侵。",
            Recommendation = "保存本報告，檢查路由器是否有連接埠轉送設定，並更改所有帳號密碼。",
            Evidence = [.. BuildEvidence(external)],
        };
    }

    private static IEnumerable<Evidence> BuildEvidence(IReadOnlyList<LogonRecord> external)
    {
        foreach (var group in external.GroupBy(l => l.IpAddress ?? "(未記錄)")
                                      .OrderByDescending(g => g.Count()))
        {
            var accounts = string.Join("、", group.Select(l => l.Account).Distinct().Order(StringComparer.Ordinal));

            yield return new Evidence(
                $"公網來源 {group.Key}",
                $"{group.Count()} 次，帳號：{accounts}，"
                + $"首見 {group.Min(l => l.Time):yyyy-MM-dd HH:mm}，末見 {group.Max(l => l.Time):yyyy-MM-dd HH:mm}",
                group.Max(l => l.Time));
        }
    }
}
