using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M2;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-08 安裝時間與異常時間點關聯。
/// <para>功能規格：安裝時間與 M2 發現的可疑遠端時段接近 → <c>Warning</c>。Severity Medium。</para>
/// <para>
/// <b>不從 M2 取結果</b>：本項依編號在 M2 之前執行，而模組間刻意不共享狀態。
/// 改為自行查詢終端服務工作階段記錄 —— 該記錄檔不需提權即可讀取，
/// 未提權時仍能完成關聯，比依賴 Security 記錄更可靠。
/// </para>
/// </summary>
public sealed class M1_08_InstallTimeCorrelationCheck(IWindowsEventLog eventLog) : ICheck
{
    /// <summary>
    /// 「接近」的定義：安裝時間前後 24 小時內有遠端連入。
    /// <para>
    /// 規格只說「接近」而未定義。取 ±24 小時是因為攻擊者取得遠端存取後未必立刻動手，
    /// 而窗口再放大就會把無關的日常遠端使用一起掃進來。
    /// </para>
    /// </summary>
    internal static readonly TimeSpan CorrelationWindow = TimeSpan.FromHours(24);

    public string Id => "M1-08";

    public string Module => "M1";

    public string Title => "安裝時間與遠端存取的關聯";

    public Severity Severity => Severity.Medium;

    public string Source => "檔案建立時間 + 終端服務工作階段記錄";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Build(CheckStatus.Inconclusive, "未取得紫P 主程式路徑。", null, []));
        }

        var installedAt = new DateTimeOffset(File.GetCreationTime(executable));

        if (!eventLog.LogExists(M2_04_TerminalServicesSessionCheck.LogName))
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Pass,
                $"紫P 安裝於 {installedAt:yyyy-MM-dd HH:mm}，本機沒有遠端桌面記錄可供比對。",
                null,
                [new Evidence("安裝時間", installedAt.ToString("yyyy-MM-dd HH:mm:ss"), installedAt)]));
        }

        var sessions = eventLog.Query(
            M2_04_TerminalServicesSessionCheck.LogName,
            EventQueries.ByEventIds(M2_04_TerminalServicesSessionCheck.SessionEventIds, context.LookbackDays),
            ["Event/UserData/EventXML/User", "Event/UserData/EventXML/Address"],
            WindowsEventLog.DefaultMaxEvents);

        return ValueTask.FromResult(Evaluate(installedAt, sessions));
    }

    internal Finding Evaluate(DateTimeOffset installedAt, IReadOnlyList<EventRecordData> sessions)
    {
        ArgumentNullException.ThrowIfNull(sessions);

        var evidence = new List<Evidence>
        {
            new("安裝時間", installedAt.ToString("yyyy-MM-dd HH:mm:ss"), installedAt),
        };

        var nearby = sessions
            .Where(s => (s.TimeCreated - installedAt).Duration() <= CorrelationWindow)
            .OrderBy(s => s.TimeCreated)
            .ToList();

        if (nearby.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"紫P 安裝於 {installedAt:yyyy-MM-dd HH:mm}，前後 {CorrelationWindow.TotalHours:0} 小時內沒有遠端連入紀錄。"
                + "（若 M2 有偵測到遠端工具，請比對兩者的安裝時間是否接近。）",
                null,
                evidence);
        }

        evidence.AddRange(nearby.Take(20).Select(s => new Evidence(
            s.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
            $"遠端工作階段事件 {s.EventId}｜使用者 {s.Property(0) ?? "(未記錄)"}"
            + $"｜來源 {s.Property(1) ?? "(未記錄)"}"
            + $"｜與安裝時間相差 {(s.TimeCreated - installedAt).Duration().TotalHours:0.0} 小時",
            s.TimeCreated)));

        return Build(
            CheckStatus.Warning,
            $"紫P 安裝於 {installedAt:yyyy-MM-dd HH:mm}，前後 {CorrelationWindow.TotalHours:0} 小時內有 "
            + $"{nearby.Count} 筆遠端連入紀錄。若安裝不是你本人操作的，很可能是遠端連入者裝的。",
            "回想這個時間點你是否在使用電腦、是否自行安裝了紫P。若否，視同入侵處理。",
            evidence);
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
