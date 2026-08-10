namespace LcAudit.Windows.Sources;

/// <summary>
/// Authenticode 簽章驗證的資料來源。
/// <para>
/// Checks 一律透過此介面取得簽章資訊，不直接呼叫 Win32 ——
/// 判定邏輯（O= 比對、狀態對應）才能用 fake 實作做純單元測試。
/// </para>
/// </summary>
public interface IAuthenticodeVerifier
{
    /// <summary>
    /// 只驗**內嵌**簽章。M1 用這個。
    /// <para>
    /// 紫P 是第三方應用程式，本來就該有自己的內嵌簽章，不會出現在 Windows 目錄中 ——
    /// 對它放寬到目錄簽章沒有意義，反而擴大攻擊面。
    /// </para>
    /// </summary>
    SignatureVerdict Verify(string filePath);

    /// <summary>
    /// 內嵌簽章不過時，再查**目錄**簽章。M3-06／M3-08 用這個。
    /// <para>
    /// Windows 系統檔案（<c>SecurityHealthSystray.exe</c>、絕大多數 <c>.sys</c> 驅動）
    /// 沒有內嵌簽章而由 CatRoot 的目錄檔背書。只驗內嵌會把整個作業系統判成未簽章 ——
    /// 實測顯示 150 個自動啟動服務中會誤標 13 個。
    /// </para>
    /// </summary>
    SignatureVerdict VerifyIncludingCatalog(string filePath);
}
