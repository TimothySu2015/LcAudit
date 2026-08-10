using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LcAudit.Windows.Interop;

/// <summary>
/// 目錄簽章（Catalog）驗證。
/// <para>
/// Windows 的系統檔案（<c>notepad.exe</c>、<c>kernel32.dll</c>、絕大多數 <c>.sys</c> 驅動）
/// <b>沒有內嵌簽章</b>，而是由 <c>%SystemRoot%\System32\CatRoot</c> 底下的 <c>.cat</c>
/// 目錄檔集中背書。只驗內嵌簽章會把整個作業系統判成「未簽章」。
/// </para>
/// <para>
/// <b>M1 刻意不使用這個</b>：紫P 是第三方應用程式，本來就該有自己的內嵌簽章，
/// 不會出現在 Windows 目錄中；對 M1 放寬到目錄簽章沒有意義。
/// 這裡是給 M3-06／M3-08（開機啟動項與服務）用的，那些項目大量是 Windows 系統檔。
/// </para>
/// </summary>
internal static partial class WinTrustCatalog
{
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint FILE_SHARE_DELETE = 4;
    private const uint OPEN_EXISTING = 3;

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static partial int WinVerifyTrust(IntPtr hwnd, in Guid pgActionID, IntPtr pWVTData);

    [LibraryImport("wintrust.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        SafeFileHandle hFile,
        ref uint pcbHash,
        [Out] byte[]? pbHash,
        uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static partial IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        [In] byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        IntPtr phPrevCatInfo);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo,
        uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW",
                   StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    /// <summary>
    /// 驗證檔案是否被某個目錄檔背書。
    /// <para>找不到目錄項目或驗證失敗都回 <c>null</c>，代表「無法以目錄簽章證明」。</para>
    /// </summary>
    internal static int? VerifyCatalogSignature(string filePath)
    {
        // share mode 給滿，避免干擾正在執行的系統元件
        using var file = CreateFile(
            filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (file.IsInvalid)
        {
            return null;
        }

        if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return null;
        }

        try
        {
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, null, 0) || hashSize == 0)
            {
                return null;
            }

            var hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, hash, 0))
            {
                return null;
            }

            var catalogContext = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (catalogContext == IntPtr.Zero)
            {
                // 沒有任何目錄檔涵蓋這個檔案 —— 它真的沒有簽章
                return null;
            }

            try
            {
                return VerifyViaCatalogContext(filePath, catalogContext, hash, catAdmin);
            }
            finally
            {
                _ = CryptCATAdminReleaseCatalogContext(catAdmin, catalogContext, 0);
            }
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static unsafe int? VerifyViaCatalogContext(
        string filePath, IntPtr catalogContext, byte[] hash, IntPtr catAdmin)
    {
        var catalogInfo = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };

        if (!CryptCATCatalogInfoFromContext(catalogContext, ref catalogInfo, 0))
        {
            return null;
        }

        var catalogFilePath = new string(catalogInfo.wszCatalogFile);
        if (string.IsNullOrWhiteSpace(catalogFilePath))
        {
            return null;
        }

        return VerifyAgainstCatalog(filePath, catalogFilePath, Convert.ToHexString(hash), catAdmin);
    }

    private static unsafe int VerifyAgainstCatalog(
        string filePath, string catalogFilePath, string memberTag, IntPtr catAdmin)
    {
        fixed (char* pCatalogPath = catalogFilePath)
        fixed (char* pMemberTag = memberTag)
        fixed (char* pFilePath = filePath)
        {
            var catalogInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                pcwszCatalogFilePath = (IntPtr)pCatalogPath,
                pcwszMemberTag = (IntPtr)pMemberTag,
                pcwszMemberFilePath = (IntPtr)pFilePath,
                hCatAdmin = catAdmin,
            };

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,   // 離線要求（NFR-06）
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pCatalog = (IntPtr)(&catalogInfo),
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var action = WinTrust.GenericVerifyV2;
            var pData = (IntPtr)(&data);

            try
            {
                return WinVerifyTrust(IntPtr.Zero, in action, pData);
            }
            finally
            {
                // 與內嵌簽章驗證一樣，第二次 CLOSE 呼叫必做
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                _ = WinVerifyTrust(IntPtr.Zero, in action, pData);
            }
        }
    }

    /// <summary>
    /// <c>LibraryImport</c> 來源產生器只接受 blittable 結構，不支援 <c>ByValTStr</c>，
    /// 因此路徑用 fixed buffer 表示，取用時再轉字串。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct CATALOG_INFO
    {
        public uint cbStruct;
        public fixed char wszCatalogFile[260];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
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
        public IntPtr pCatalog;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
