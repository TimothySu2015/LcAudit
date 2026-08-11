namespace LcAudit.Core.Model;

/// <summary>完整報告，對應功能規格 §8.2 的 JSON 結構。Reporting 層只吃這個型別。</summary>
public sealed record AuditReport
{
    /// <summary>報告格式版本。與 <see cref="ToolVersion"/> 是兩回事，格式沒改就不會動。</summary>
    public string SchemaVersion => "1.0";

    /// <summary>
    /// 產生本報告的工具版本。
    /// <para>
    /// 報告可能在事發數週後才被翻出來比對，屆時工具早已更新過 —— 沒有版本號就無法判斷
    /// 「這份報告當時漏掉了哪些檢查項」或「某個判定是不是舊版的已知誤報」。
    /// </para>
    /// </summary>
    public required string ToolVersion { get; init; }

    public required DateTimeOffset ScannedAt { get; init; }

    /// <summary>是否以系統管理員身分執行。未提權時 Security log 相關項會是 Inconclusive。</summary>
    public required bool IsElevated { get; init; }

    public required HostInfo Host { get; init; }

    /// <summary>使用者提供的事發時間；未指定為 <c>null</c>。</summary>
    public DateTimeOffset? IncidentTime { get; init; }

    public required AuditSummary Summary { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
}
