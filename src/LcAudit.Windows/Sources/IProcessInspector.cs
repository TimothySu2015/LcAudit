namespace LcAudit.Windows.Sources;

/// <summary>執行中處理程序的資訊。</summary>
/// <param name="ProcessId">PID。</param>
/// <param name="Name">處理程序名稱（不含副檔名與路徑）。</param>
public sealed record ProcessSummary(int ProcessId, string Name);

/// <summary>
/// 處理程序查詢。
/// <para>
/// 分成兩個層級：<see cref="ListProcesses"/> 只取名稱與 PID（走系統快照，不開 handle，
/// 完全不觸發反作弊）；<see cref="TryGetImagePath"/> 才會開 handle，且只用
/// <c>PROCESS_QUERY_LIMITED_INFORMATION</c>。呼叫端應盡量只用前者。
/// </para>
/// </summary>
public interface IProcessInspector
{
    IReadOnlyList<ProcessSummary> ListProcesses();

    /// <summary>取執行檔路徑；失敗回 <c>null</c>（正常結果，非例外）。</summary>
    string? TryGetImagePath(int processId);
}
