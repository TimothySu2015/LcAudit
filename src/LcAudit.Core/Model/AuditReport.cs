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

    /// <summary>
    /// 本份報告的唯一識別碼，同時出現在檔名、報告內容與郵件主旨中。
    /// <para>
    /// 用途是「這份報告是誰的」—— 使用者把報告寄來時，光看主機名稱無法區分
    /// （很多人都叫 DESKTOP-XXXXXX），也不該要求他們附上個人資訊。
    /// </para>
    /// <para>
    /// 用 32 位元十六進位（<c>Guid</c> 的 N 格式）而非含連字號的 D 格式 ——
    /// 檔名本身已經用 <c>-</c> 當分隔符，再混入連字號會讓檔名難以拆解。
    /// </para>
    /// </summary>
    public required string ReportId { get; init; }

    public required DateTimeOffset ScannedAt { get; init; }

    /// <summary>是否以系統管理員身分執行。未提權時 Security log 相關項會是 Inconclusive。</summary>
    public required bool IsElevated { get; init; }

    public required HostInfo Host { get; init; }

    /// <summary>使用者提供的事發區間；未指定為 <c>null</c>。</summary>
    public IncidentWindow? IncidentWindow { get; init; }

    public required AuditSummary Summary { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
}
