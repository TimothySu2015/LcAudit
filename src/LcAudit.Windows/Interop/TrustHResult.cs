namespace LcAudit.Windows.Interop;

/// <summary><c>WinVerifyTrust</c> 的回傳碼（技術設計 §4.1 對照表）。</summary>
internal static class TrustHResult
{
    internal const int S_OK = 0;

    /// <summary>完全未簽章。需再看 GetLastError 才能區分「無簽章」與「檔案讀不到」。</summary>
    internal const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

    /// <summary><b>檔案被竄改</b> —— 最高優先警示。</summary>
    internal const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);

    internal const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);

    internal const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);

    /// <summary>憑證鏈不完整，常見於自簽。</summary>
    internal const int CERT_E_CHAINING = unchecked((int)0x800B010A);

    /// <summary>憑證過期。若有時間戳可降級（M1-03）。</summary>
    internal const int CERT_E_EXPIRED = unchecked((int)0x800B0101);

    /// <summary>政策阻擋，非簽章本身的問題。</summary>
    internal const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

    /// <summary>檔案格式不被任何 SIP 認得（例如根本不是 PE 檔）。</summary>
    internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);

    internal const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
}
