using System.Runtime.InteropServices;

namespace LcAudit.Windows.Interop;

/// <summary>
/// <c>crypt32.dll</c> —— 從 PE 檔的 Authenticode 簽章中抽出簽章者憑證（技術設計 §4.2）。
/// </summary>
internal static partial class Crypt32
{
    internal const uint CERT_QUERY_OBJECT_FILE = 1;

    /// <summary>
    /// <b>唯一允許的內容型別旗標。</b>
    /// <para>
    /// 使用 <c>CERT_QUERY_CONTENT_FLAG_ALL</c> 視同實作缺陷 —— 它會掃描檔案的任意位置
    /// （含資源區段與內容區段）尋找任何像密碼學物件的東西，而不只是 Authenticode 簽章。
    /// 攻擊者只要把官方公開憑證塞進資源區段就能冒充簽章者。
    /// </para>
    /// </summary>
    internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10; // 0x400

    internal const uint CERT_QUERY_FORMAT_FLAG_BINARY = 2;

    private const uint CMSG_SIGNER_INFO_PARAM = 6;
    private const uint X509_ASN_ENCODING = 0x00000001;
    private const uint PKCS_7_ASN_ENCODING = 0x00010000;
    private const uint CERT_FIND_SUBJECT_CERT = 0x000B0007;

    [LibraryImport("crypt32.dll", EntryPoint = "CryptQueryObject", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptQueryObject(
        uint dwObjectType,
        string pvObject,
        uint dwExpectedContentTypeFlags,
        uint dwExpectedFormatTypeFlags,
        uint dwFlags,
        out uint pdwMsgAndCertEncodingType,
        out uint pdwContentType,
        out uint pdwFormatType,
        out IntPtr phCertStore,
        out IntPtr phMsg,
        out IntPtr ppvContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        uint dwParamType,
        uint dwIndex,
        IntPtr pvData,
        ref uint pcbData);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    private static partial IntPtr CertFindCertificateInStore(
        IntPtr hCertStore,
        uint dwCertEncodingType,
        uint dwFindFlags,
        uint dwFindType,
        IntPtr pvFindPara,
        IntPtr pPrevCertContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertFreeCertificateContext(IntPtr pCertContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptMsgClose(IntPtr hCryptMsg);

    /// <summary>
    /// 取出簽章者憑證的 DER 位元組；沒有內嵌 PKCS#7 簽章時回 <c>null</c>。
    /// </summary>
    internal static byte[]? TryGetSignerCertificate(string filePath)
    {
        var queried = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,   // 絕不可改為 _ALL
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            out _,
            out _,
            out _,
            out var rawStore,
            out var rawMsg,
            out _);

        using var store = new SafeCertStoreHandle(rawStore);
        using var msg = new SafeCryptMsgHandle(rawMsg);

        if (!queried || store.IsInvalid || msg.IsInvalid)
        {
            return null;
        }

        // 兩段式呼叫：先問長度，再配置緩衝區取值。
        uint signerInfoSize = 0;
        if (!CryptMsgGetParam(msg.DangerousGetHandle(), CMSG_SIGNER_INFO_PARAM, 0, IntPtr.Zero, ref signerInfoSize)
            || signerInfoSize == 0)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal((int)signerInfoSize);
        try
        {
            if (!CryptMsgGetParam(msg.DangerousGetHandle(), CMSG_SIGNER_INFO_PARAM, 0, buffer, ref signerInfoSize))
            {
                return null;
            }

            var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(buffer);

            // CERT_FIND_SUBJECT_CERT 只讀 CERT_INFO 的 Issuer 與 SerialNumber，
            // 但結構配置必須完整正確，API 是照位移讀的。
            var certInfo = new CERT_INFO
            {
                Issuer = signerInfo.Issuer,
                SerialNumber = signerInfo.SerialNumber,
            };

            var pCertInfo = Marshal.AllocHGlobal(Marshal.SizeOf<CERT_INFO>());
            try
            {
                Marshal.StructureToPtr(certInfo, pCertInfo, false);

                var rawContext = CertFindCertificateInStore(
                    store.DangerousGetHandle(),
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    pCertInfo,
                    IntPtr.Zero);

                using var certContext = new SafeCertContextHandle(rawContext);
                return certContext.IsInvalid ? null : certContext.GetEncodedCertificate();
            }
            finally
            {
                Marshal.FreeHGlobal(pCertInfo);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_DATA_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_BIT_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
        public uint cUnusedBits;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPT_DATA_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ATTRIBUTES
    {
        public uint cAttr;
        public IntPtr rgAttr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CERT_PUBLIC_KEY_INFO
    {
        public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
        public CRYPT_BIT_BLOB PublicKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CMSG_SIGNER_INFO
    {
        public uint dwVersion;
        public CRYPT_DATA_BLOB Issuer;
        public CRYPT_DATA_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        public CRYPT_DATA_BLOB EncryptedHash;
        public CRYPT_ATTRIBUTES AuthAttrs;
        public CRYPT_ATTRIBUTES UnauthAttrs;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CERT_INFO
    {
        public uint dwVersion;
        public CRYPT_DATA_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPT_DATA_BLOB Issuer;
        public long NotBefore;
        public long NotAfter;
        public CRYPT_DATA_BLOB Subject;
        public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        public CRYPT_BIT_BLOB IssuerUniqueId;
        public CRYPT_BIT_BLOB SubjectUniqueId;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CERT_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public uint cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }
}
