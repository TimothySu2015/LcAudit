using LcAudit.Core.Model;

namespace LcAudit.Core.Abstractions;

/// <summary>
/// 跨檢查項共享的執行期狀態。
/// <para>
/// 刻意保持極小 —— 只有兩項共享狀態，其餘一律不共享，避免檢查項之間產生隱性順序相依。
/// </para>
/// </summary>
public sealed class AuditContext
{
    /// <summary>是否以系統管理員身分執行。未提權不得中斷流程，相關項標 Inconclusive（TC-02）。</summary>
    public required bool IsElevated { get; init; }

    /// <summary>事件記錄回溯天數，預設 90。</summary>
    public required int LookbackDays { get; init; }

    /// <summary>以 <c>--skip-module</c> 指定跳過的模組（<c>"M1"</c>～<c>"M4"</c>）。</summary>
    public required IReadOnlySet<string> SkippedModules { get; init; }

    /// <summary>M1-00 探測出的紫P 安裝路徑，供 M1 其餘項與 M4-01 使用。未探測到為 null。</summary>
    public string? PurpleInstallPath { get; set; }

    /// <summary>
    /// 使用者提供的事發區間（帳號被盜的時間範圍）。
    /// <para>
    /// 受害者通常給得出的不是一個時間點，而是「幾點還好、幾點發現不見」的範圍。
    /// 工具本身有大量時間戳卻沒有錨點，給了這個區間才能把跡證依相關性排序。
    /// </para>
    /// </summary>
    public IncidentWindow? IncidentWindow { get; init; }

    /// <summary>
    /// Pre-flight 偵測到的遊戲／反作弊程序 PID。
    /// <para>
    /// 偵測只用 <c>Process.ProcessName</c> 比對名稱，不開 process handle。
    /// M4-03 必須排除這些 PID —— 對受保護程序取執行檔路徑會觸發反作弊，
    /// 詳見 CLAUDE.md「反作弊共存規則」。
    /// </para>
    /// </summary>
    public IReadOnlySet<int> ProtectedPids { get; set; } = new HashSet<int>();

    /// <summary>是否偵測到遊戲或反作弊程序執行中。</summary>
    public bool IsGameRunning => ProtectedPids.Count > 0;
}
