using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LcAudit.Core.Validation;
using LcAudit.Windows.Interop;

namespace LcAudit.Windows.Sources;

/// <summary>
/// 以 <c>WinVerifyTrust</c>（狀態）＋ <c>CryptQueryObject</c>（簽章者）驗證 Authenticode 簽章。
/// <para>
/// <b>兩者皆通過才算 Pass。</b>只做其中一項都能被繞過：
/// 只驗狀態不看簽章者 → 任何有效簽章都算數；
/// 只看簽章者不驗狀態 → 塞一張憑證進檔案就冒充成功。
/// </para>
/// </summary>
public sealed class AuthenticodeVerifier : IAuthenticodeVerifier
{
    public SignatureVerdict Verify(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
        {
            return new SignatureVerdict
            {
                FilePath = filePath,
                Trust = SignatureTrust.FileNotReadable,
                HResult = TrustHResult.TRUST_E_NOSIGNATURE,
            };
        }

        var (hResult, lastError) = WinTrust.VerifyEmbeddedSignature(filePath);
        var trust = MapTrust(hResult, lastError);

        // 未簽章就沒有簽章者可抽 —— 省去一次無謂的檔案掃描。
        if (trust is SignatureTrust.NoSignature or SignatureTrust.FileNotReadable)
        {
            return new SignatureVerdict
            {
                FilePath = filePath,
                Trust = trust,
                HResult = hResult,
            };
        }

        var certificate = TryLoadSignerCertificate(filePath);

        return new SignatureVerdict
        {
            FilePath = filePath,
            Trust = trust,
            HResult = hResult,
            SignerOrganization = certificate is null
                ? null
                : SignerNameValidator.GetOrganization(certificate.SubjectName),
            SignerSubject = certificate?.Subject,
            NotBefore = certificate?.NotBefore,
            NotAfter = certificate?.NotAfter,
        };
    }

    /// <summary>HRESULT → <see cref="SignatureTrust"/>（技術設計 §4.1 對照表）。</summary>
    internal static SignatureTrust MapTrust(int hResult, int lastError) => hResult switch
    {
        TrustHResult.S_OK => SignatureTrust.Valid,

        // TRUST_E_NOSIGNATURE 需再看 GetLastError 才能區分「真的沒簽章」與
        // 「檔案不是 PE、或 SIP 讀不到」。
        TrustHResult.TRUST_E_NOSIGNATURE => lastError is TrustHResult.TRUST_E_SUBJECT_FORM_UNKNOWN
                                                      or TrustHResult.TRUST_E_PROVIDER_UNKNOWN
            ? SignatureTrust.FileNotReadable
            : SignatureTrust.NoSignature,

        TrustHResult.TRUST_E_BAD_DIGEST => SignatureTrust.BadDigest,
        TrustHResult.TRUST_E_EXPLICIT_DISTRUST => SignatureTrust.ExplicitDistrust,
        TrustHResult.TRUST_E_SUBJECT_NOT_TRUSTED => SignatureTrust.SubjectNotTrusted,
        TrustHResult.CERT_E_CHAINING => SignatureTrust.ChainIncomplete,
        TrustHResult.CERT_E_EXPIRED => SignatureTrust.Expired,
        TrustHResult.CRYPT_E_SECURITY_SETTINGS => SignatureTrust.SecuritySettings,
        _ => SignatureTrust.Unknown,
    };

    private static X509Certificate2? TryLoadSignerCertificate(string filePath)
    {
        var encoded = Crypt32.TryGetSignerCertificate(filePath);
        if (encoded is null || encoded.Length == 0)
        {
            return null;
        }

        try
        {
            // X509CertificateLoader 是 .NET 9+ 的取代品；舊的 X509Certificate2(byte[]) 已過時。
            return X509CertificateLoader.LoadCertificate(encoded);
        }
        catch (CryptographicException)
        {
            // 抽出的位元組不是合法憑證 —— 視同無法辨識簽章者。
            return null;
        }
    }
}
