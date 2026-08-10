using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LcAudit.Windows.Interop;

/// <summary>
/// <c>CryptQueryObject</c> 產出的憑證存放區 handle。
/// <para>技術設計 §4.2 要求以 SafeHandle 包裝，不靠 finally 手動釋放。</para>
/// </summary>
internal sealed class SafeCertStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeCertStoreHandle(IntPtr handle)
        : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => Crypt32.CertCloseStore(handle, 0);
}

/// <summary><c>CryptQueryObject</c> 產出的 PKCS#7 訊息 handle。</summary>
internal sealed class SafeCryptMsgHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeCryptMsgHandle(IntPtr handle)
        : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => Crypt32.CryptMsgClose(handle);
}

/// <summary><c>CertFindCertificateInStore</c> 產出的憑證內容 handle。</summary>
internal sealed class SafeCertContextHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeCertContextHandle(IntPtr handle)
        : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => Crypt32.CertFreeCertificateContext(handle);

    /// <summary>取出 DER 編碼的憑證位元組。</summary>
    internal byte[] GetEncodedCertificate()
    {
        var context = Marshal.PtrToStructure<Crypt32.CERT_CONTEXT>(handle);
        var bytes = new byte[context.cbCertEncoded];
        Marshal.Copy(context.pbCertEncoded, bytes, 0, bytes.Length);
        return bytes;
    }
}
