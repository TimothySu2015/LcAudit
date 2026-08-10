namespace LcAudit.Core.Model;

/// <summary>完整報告，對應功能規格 §8.2 的 JSON 結構。Reporting 層只吃這個型別。</summary>
public sealed record AuditReport
{
    public string SchemaVersion => "1.0";

    public required DateTimeOffset ScannedAt { get; init; }

    /// <summary>是否以系統管理員身分執行。未提權時 Security log 相關項會是 Inconclusive。</summary>
    public required bool IsElevated { get; init; }

    public required HostInfo Host { get; init; }

    public required AuditSummary Summary { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
}
