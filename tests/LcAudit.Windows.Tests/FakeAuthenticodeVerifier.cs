using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Tests;

/// <summary>讓 M1 各檢查項的判定邏輯可以脫離真實檔案測試。</summary>
internal sealed class FakeAuthenticodeVerifier(SignatureVerdict verdict) : IAuthenticodeVerifier
{
    public SignatureVerdict Verify(string filePath) => verdict with { FilePath = filePath };

    public SignatureVerdict VerifyIncludingCatalog(string filePath) => Verify(filePath);

    internal static SignatureVerdict Verdict(
        SignatureTrust trust,
        string? organization = null,
        string? subject = null) => new()
        {
            FilePath = @"C:\Program Files\PURPLE\Purple.exe",
            Trust = trust,
            HResult = trust == SignatureTrust.Valid ? 0 : unchecked((int)0x800B0100),
            SignerOrganization = organization,
            SignerSubject = subject,
        };
}
