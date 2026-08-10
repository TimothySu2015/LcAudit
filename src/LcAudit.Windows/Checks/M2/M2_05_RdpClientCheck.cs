using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-05 RDP 用戶端連線嘗試。
/// <para>
/// <b>注意方向</b>：這個記錄檔記的是「這台電腦**連出去**到別人那裡」，
/// 不是別人連進來。Severity Info —— 它本身不是入侵跡證，
/// 但能還原「這台機器在什麼時候被誰拿去連線到哪裡」。
/// </para>
/// </summary>
public sealed class M2_05_RdpClientCheck(IWindowsEventLog eventLog) : ICheck
{
    internal const string LogName = "Microsoft-Windows-TerminalServices-RDPClient/Operational";

    /// <summary>1024 = RDP 用戶端嘗試連線到指定主機。</summary>
    internal const int EventIdConnectionAttempt = 1024;

    public string Id => "M2-05";

    public string Module => "M2";

    public string Title => "RDP 用戶端連線嘗試（對外）";

    public Severity Severity => Severity.Info;

    public string Source => LogName;

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        if (!eventLog.LogExists(LogName))
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "本機沒有 RDP 用戶端記錄檔，通常代表從未用這台電腦連線到其他主機。",
                []));
        }

        var records = eventLog.Query(
            LogName,
            EventQueries.ByEventId(EventIdConnectionAttempt, context.LookbackDays),
            ["Event/EventData/Data[@Name='Value']"],
            WindowsEventLog.DefaultMaxEvents);

        return ValueTask.FromResult(Evaluate(records, context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<EventRecordData> records, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(records);

        if (records.Count == 0)
        {
            return Build(CheckStatus.Pass, $"過去 {lookbackDays} 天內沒有對外的 RDP 連線嘗試。", []);
        }

        return Build(
            CheckStatus.Pass,
            $"過去 {lookbackDays} 天內有 {records.Count} 次對外 RDP 連線嘗試。"
            + "這是本機連出去的紀錄，不代表被入侵；但若你沒印象用過，值得留意。",
            [
                .. records.GroupBy(r => r.Property(0) ?? "(未記錄)")
                          .OrderByDescending(g => g.Count())
                          .Take(20)
                          .Select(g => new Evidence(
                              $"目標 {g.Key}",
                              $"{g.Count()} 次，末見 {g.Max(r => r.TimeCreated):yyyy-MM-dd HH:mm}",
                              g.Max(r => r.TimeCreated))),
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
