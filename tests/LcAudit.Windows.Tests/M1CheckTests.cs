using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M1;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>M1-01 / M1-02 的判定邏輯，用 fake verifier 測試，不碰真實檔案。</summary>
public sealed class M1CheckTests
{
    private static readonly AuditContext EmptyContext = new()
    {
        IsElevated = true,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(),
    };

    private static M1_01_SignatureStatusCheck StatusCheck(SignatureVerdict verdict)
        => new(new FakeAuthenticodeVerifier(verdict));

    private static M1_02_SignerIdentityCheck IdentityCheck(SignatureVerdict verdict)
        => new(new FakeAuthenticodeVerifier(verdict));

    // ---- M1-01 簽章狀態 ----

    [Theory]
    [InlineData(SignatureTrust.Valid, CheckStatus.Pass)]
    [InlineData(SignatureTrust.NoSignature, CheckStatus.Fail)]
    [InlineData(SignatureTrust.BadDigest, CheckStatus.Fail)]
    [InlineData(SignatureTrust.ExplicitDistrust, CheckStatus.Fail)]
    [InlineData(SignatureTrust.SubjectNotTrusted, CheckStatus.Fail)]
    [InlineData(SignatureTrust.ChainIncomplete, CheckStatus.Fail)]
    [InlineData(SignatureTrust.Expired, CheckStatus.Warning)]
    [InlineData(SignatureTrust.SecuritySettings, CheckStatus.Warning)]
    [InlineData(SignatureTrust.FileNotReadable, CheckStatus.Inconclusive)]
    [InlineData(SignatureTrust.Unknown, CheckStatus.Inconclusive)]
    public void M1_01狀態對應符合技術設計對照表(SignatureTrust trust, CheckStatus expected)
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(trust);

        Assert.Equal(expected, StatusCheck(verdict).Evaluate(verdict).Status);
    }

    [Fact]
    public void M1_01為Critical且Fail時計40分()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.NoSignature);

        var finding = StatusCheck(verdict).Evaluate(verdict);

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(40, finding.Score);
    }

    [Fact]
    public void M1_01竄改的描述要點名檔案被改過()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.BadDigest);

        Assert.Contains("竄改", StatusCheck(verdict).Evaluate(verdict).Description);
    }

    [Fact]
    public async Task M1_01未探測到安裝路徑時判Inconclusive()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.Valid);

        var finding = await StatusCheck(verdict).ExecuteAsync(EmptyContext, default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Equal(0, finding.Score);
        Assert.Contains("--purple-path", finding.Recommendation);
    }

    // ---- M1-02 簽章者身分 ----

    [Fact]
    public void M1_02官方簽章者且簽章有效才Pass()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.Valid, "NCSOFT Corporation");

        Assert.Equal(CheckStatus.Pass, IdentityCheck(verdict).Evaluate(verdict).Status);
    }

    [Fact]
    public void M1_02非官方組織判Fail()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.Valid, "Evil Ltd");

        var finding = IdentityCheck(verdict).Evaluate(verdict);

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Contains("Evil Ltd", finding.Description);
    }

    [Fact]
    public void M1_02把NCSOFT塞進CN不能通過()
    {
        // CN 含 NCSOFT 但 O= 是別人 —— 用 Subject.Contains 會中的招
        var verdict = FakeAuthenticodeVerifier.Verdict(
            SignatureTrust.Valid,
            organization: "Evil Ltd",
            subject: "CN=NCSOFT-Free-Launcher, O=Evil Ltd");

        Assert.Equal(CheckStatus.Fail, IdentityCheck(verdict).Evaluate(verdict).Status);
    }

    [Fact]
    public void M1_02沒有簽章者判Fail()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.NoSignature);

        Assert.Equal(CheckStatus.Fail, IdentityCheck(verdict).Evaluate(verdict).Status);
    }

    [Fact]
    public void M1_02簽章者正確但簽章無效仍判Fail()
    {
        // 把官方憑證抽出來塞進偽造檔案會呈現的樣子：組織對，但 WinVerifyTrust 不過
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.BadDigest, "NCSOFT Corporation");

        var finding = IdentityCheck(verdict).Evaluate(verdict);

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Contains("憑證正確不代表簽章有效", finding.Description);
    }

    [Fact]
    public void M1_02檔案讀不到判Inconclusive而非Fail()
    {
        // 環境問題不該計 40 分
        var verdict = FakeAuthenticodeVerifier.Verdict(SignatureTrust.FileNotReadable);

        var finding = IdentityCheck(verdict).Evaluate(verdict);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Equal(0, finding.Score);
    }

    [Fact]
    public void M1_02證據要保留完整Subject供人工研判()
    {
        var verdict = FakeAuthenticodeVerifier.Verdict(
            SignatureTrust.Valid, "Evil Ltd", "CN=NCSOFT-Free-Launcher, O=Evil Ltd");

        var finding = IdentityCheck(verdict).Evaluate(verdict);

        Assert.Contains(finding.Evidence, e => e.Value == "CN=NCSOFT-Free-Launcher, O=Evil Ltd");
    }
}
