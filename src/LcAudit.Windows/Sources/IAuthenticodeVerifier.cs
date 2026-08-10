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
    SignatureVerdict Verify(string filePath);
}
