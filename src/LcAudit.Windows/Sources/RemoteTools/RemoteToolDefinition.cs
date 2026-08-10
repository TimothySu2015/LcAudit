namespace LcAudit.Windows.Sources.RemoteTools;

/// <summary>一套遠端存取工具的偵測特徵（功能規格附錄 B）。</summary>
/// <param name="DisplayName">顯示名稱。</param>
/// <param name="Directories">安裝或資料目錄，含未展開的環境變數。</param>
/// <param name="ServiceNames">
/// 登錄檔 <c>HKLM\SYSTEM\CurrentControlSet\Services</c> 底下的服務名稱。
/// 結尾為 <c>*</c> 表示前綴比對（如 ScreenConnect 的執行個體服務名帶亂數後綴）。
/// </param>
/// <param name="IncomingLogFiles">連入紀錄檔，用於區分「別人連進來」與「自己連出去」。</param>
public sealed record RemoteToolDefinition(
    string DisplayName,
    IReadOnlyList<string> Directories,
    IReadOnlyList<string> ServiceNames,
    IReadOnlyList<string> IncomingLogFiles);

/// <summary>單一工具的掃描結果。</summary>
/// <param name="Tool">對應的定義。</param>
/// <param name="FoundDirectories">實際存在的目錄。</param>
/// <param name="FoundServices">實際存在的服務登錄檔項目。</param>
/// <param name="FoundIncomingLogs">實際存在的連入紀錄檔。</param>
public sealed record RemoteToolTrace(
    RemoteToolDefinition Tool,
    IReadOnlyList<string> FoundDirectories,
    IReadOnlyList<string> FoundServices,
    IReadOnlyList<string> FoundIncomingLogs)
{
    /// <summary>是否找到任何痕跡。</summary>
    public bool HasTrace =>
        FoundDirectories.Count > 0 || FoundServices.Count > 0 || FoundIncomingLogs.Count > 0;
}
