using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 對真實 PE 檔案驗證 WinVerifyTrust + CryptQueryObject（技術設計 §7.1 的驗收表）。
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuthenticodeVerifierIntegrationTests
{
    private readonly AuthenticodeVerifier _verifier = new();

    [Fact]
    public void 內嵌簽章的檔案判為Valid並取得簽章者()
    {
        // xunit 2.x 沒有動態略過，找不到素材時直接結束。
        // 正常開發機一定有 %ProgramFiles%\dotnet\dotnet.exe（內嵌簽章），實務上不會走到這裡。
        var signed = TestAssets.FindEmbeddedSignedExecutable();
        if (signed is null)
        {
            return;
        }

        var verdict = _verifier.Verify(signed);

        Assert.Equal(SignatureTrust.Valid, verdict.Trust);
        Assert.False(string.IsNullOrWhiteSpace(verdict.SignerOrganization));
        Assert.True(verdict.IsTrustedAndIdentified);
    }

    [Fact]
    public void 未簽章的檔案判為NoSignature()
    {
        var verdict = _verifier.Verify(TestAssets.CreateUnsigned());

        Assert.Equal(SignatureTrust.NoSignature, verdict.Trust);
        Assert.Null(verdict.SignerOrganization);
    }

    /// <summary>
    /// <b>本階段最重要的回歸測試。</b>
    /// <para>
    /// 已實測確認的繞過手法：拿一個正版已簽章檔案改動內容（植入惡意碼），
    /// <c>CreateFromSignedFile</c> 仍會回報原本的簽章者，對竄改毫無反應 ——
    /// 實測中它對被竄改的 dotnet.exe 回報「O=Microsoft Corporation」。
    /// 假紫P 最省事的做法就是改造正版，不必自己弄憑證。
    /// </para>
    /// <para>
    /// 這個測試失敗，代表有人把不做驗證的 API 寫回去了。
    /// </para>
    /// </summary>
    [Fact]
    public void 被竄改的檔案判為BadDigest()
    {
        var tampered = TestAssets.CreateTampered();
        if (tampered is null)
        {
            return;
        }

        var verdict = _verifier.Verify(tampered);

        Assert.Equal(SignatureTrust.BadDigest, verdict.Trust);
    }

    /// <summary>
    /// 未簽章但檔案內含憑證位元組者，必須判為未簽章。
    /// <para>
    /// <b>注意這個素材的實際強度</b>：技術設計 §7.1 把它列為「回歸測試的核心」，
    /// 但實測發現它並未重現 §0 描述的繞過。已試過兩種構造 —— DER 附加於 PE 尾端、
    /// 以及編為 .NET 內嵌資源 —— <c>CreateFromSignedFile</c> 兩者都是拋
    /// <c>CryptographicException</c>，而不是回報憑證裡的簽章者。
    /// </para>
    /// <para>
    /// 因此本測試只是一個合理的負面案例，**不是**守門員。
    /// 真正驗證得了的守門員是 <see cref="被竄改的檔案判為BadDigest"/>
    /// 與 <see cref="ForbiddenApiGuardTests"/> 的原始碼掃描。
    /// </para>
    /// </summary>
    [Fact]
    public void 內嵌憑證但未簽章的檔案仍必須判為未簽章()
    {
        var trap = TestAssets.CreateCertificateEmbeddedUnsigned();

        var verdict = _verifier.Verify(trap);

        Assert.Equal(SignatureTrust.NoSignature, verdict.Trust);

        // 關鍵斷言：憑證雖然在檔案裡，但不得被當成簽章者。
        Assert.Null(verdict.SignerOrganization);
        Assert.Null(verdict.SignerSubject);
        Assert.False(verdict.IsTrustedAndIdentified);
    }

    [Fact]
    public void 不存在的檔案判為FileNotReadable()
    {
        var verdict = _verifier.Verify(Path.Combine(Path.GetTempPath(), "no-such-file-9c2f.exe"));

        Assert.Equal(SignatureTrust.FileNotReadable, verdict.Trust);
    }

    [Fact]
    public void 不是PE檔的檔案不會被誤判為已簽章()
    {
        var textFile = Path.Combine(Path.GetTempPath(), $"lcaudit-{Guid.NewGuid():N}.txt");
        File.WriteAllText(textFile, "這不是 PE 檔");

        try
        {
            var verdict = _verifier.Verify(textFile);

            Assert.NotEqual(SignatureTrust.Valid, verdict.Trust);
            Assert.Null(verdict.SignerOrganization);
        }
        finally
        {
            File.Delete(textFile);
        }
    }
}
