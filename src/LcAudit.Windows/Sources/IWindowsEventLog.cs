namespace LcAudit.Windows.Sources;

/// <summary>單筆事件記錄的擷取結果。</summary>
/// <param name="TimeCreated">事件發生時間（本機時區）。</param>
/// <param name="EventId">事件識別碼。</param>
/// <param name="Properties">
/// 依查詢時指定的具名 XPath 順序取出的欄位值；欄位不存在為 <c>null</c>。
/// </param>
public sealed record EventRecordData(
    DateTimeOffset TimeCreated,
    int EventId,
    IReadOnlyList<string?> Properties)
{
    /// <summary>安全地取用欄位，索引越界或欄位缺漏回 <c>null</c>。</summary>
    public string? Property(int index)
        => index >= 0 && index < Properties.Count ? Properties[index] : null;
}

/// <summary>
/// Windows 事件記錄查詢。
/// <para>
/// 讀取 Security 記錄需要系統管理員權限；未提權時實作會拋
/// <see cref="UnauthorizedAccessException"/>，由 <c>SafeCheckDecorator</c> 轉為
/// Inconclusive（NFR-04）。呼叫端不應自行 try/catch。
/// </para>
/// </summary>
public interface IWindowsEventLog
{
    /// <summary>依 XPath 查詢，只取出指定的具名欄位。</summary>
    /// <param name="logName">記錄檔名稱，如 <c>"Security"</c>。</param>
    /// <param name="xpath">查詢條件，用 <see cref="EventQueries"/> 組裝。</param>
    /// <param name="propertyPaths">要取出的具名欄位 XPath；傳空集合則只取時間與 EventID。</param>
    /// <param name="maxEvents">筆數上限（NFR-01，預設 5000）。</param>
    IReadOnlyList<EventRecordData> Query(
        string logName,
        string xpath,
        IReadOnlyList<string> propertyPaths,
        int maxEvents);
}
