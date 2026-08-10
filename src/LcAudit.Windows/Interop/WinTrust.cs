using System.Runtime.InteropServices;

namespace LcAudit.Windows.Interop;

/// <summary>
/// <c>wintrust.dll</c> 的 Authenticode 簽章驗證（技術設計 §4.1）。
/// <para>
/// <b>這是判定「簽章是否有效」的唯一正確途徑。</b>
/// <c>X509Certificate.CreateFromSignedFile()</c> 根本不驗證簽章，只是掃檔案找像憑證的東西 ——
/// 把 NCSOFT 公開憑證塞進資源區段的偽造紫P 就能通過。絕對不可使用。
/// </para>
/// </summary>
internal static partial class WinTrust
{
    /// <summary><c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c></summary>
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    // dwUIChoice
    private const uint WTD_UI_NONE = 2;

    // fdwRevocationChecks —— 必須為 NONE。查撤銷會發出網路請求，違反完全離線約束（NFR-06）。
    private const uint WTD_REVOKE_NONE = 0;

    // dwUnionChoice
    private const uint WTD_CHOICE_FILE = 1;

    // dwStateAction
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    // dwProvFlags —— 只用快取，確保不觸發網路
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static partial int WinVerifyTrust(IntPtr hwnd, in Guid pgActionID, IntPtr pWVTData);

    /// <summary>
    /// 驗證檔案的內嵌 Authenticode 簽章，回傳 HRESULT 與（必要時）GetLastError。
    /// <para>
    /// 只驗內嵌簽章（<c>WTD_CHOICE_FILE</c>）。目錄簽章（Catalog，如 notepad.exe、
    /// kernel32.dll）不在此範圍，會被判為未簽章 —— 這是刻意的：紫P 是第三方應用程式，
    /// 本來就該有自己的內嵌簽章，不會出現在 Windows 的目錄中。
    /// </para>
    /// </summary>
    internal static unsafe (int HResult, int LastError) VerifyEmbeddedSignature(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        fixed (char* pFilePath = filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = (IntPtr)pFilePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = (IntPtr)(&fileInfo),
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var action = GenericVerifyV2;
            var pData = (IntPtr)(&data);

            int hResult;
            int lastError;
            try
            {
                hResult = WinVerifyTrust(IntPtr.Zero, in action, pData);
                lastError = Marshal.GetLastWin32Error();
            }
            finally
            {
                // 第二次呼叫必做，否則洩漏 state data handle。
                // 放在 finally 確保即使上面拋例外也會釋放。
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                _ = WinVerifyTrust(IntPtr.Zero, in action, pData);
            }

            return (hResult, lastError);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
