using System.Security.Cryptography.X509Certificates;
using LcAudit.Core.Validation;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>M1-02 簽章者身分比對（技術設計 §4.3）。</summary>
public sealed class SignerNameValidatorTests
{
    [Fact]
    public void 取出標準DN的O欄位()
    {
        var dn = new X500DistinguishedName("CN=PURPLE Launcher, O=NCSOFT Corporation, C=KR");

        Assert.Equal("NCSOFT Corporation", SignerNameValidator.GetOrganization(dn));
    }

    [Fact]
    public void 把NCSOFT塞進CN不能通過()
    {
        // 這是不解析 DN、直接用 Subject.Contains("NCSOFT") 會中的招
        var dn = new X500DistinguishedName("CN=NCSOFT-Free-Launcher, O=Evil Ltd");

        Assert.Equal("Evil Ltd", SignerNameValidator.GetOrganization(dn));
        Assert.Equal(SignerVerdict.NotOfficial,
            SignerNameValidator.Classify(SignerNameValidator.GetOrganization(dn)));
    }

    [Fact]
    public void 沒有O欄位回傳null()
    {
        var dn = new X500DistinguishedName("CN=NCSOFT Corporation");

        Assert.Null(SignerNameValidator.GetOrganization(dn));
    }

    /// <summary>
    /// 已實際觀察到的官方憑證組織名稱。
    /// 韓國法人是 <c>NCsoft Corp.</c>、美國法人是 <c>NCsoft</c> ——
    /// 兩者都不是技術設計 §4.3 寫的 <c>NCSOFT Corporation</c>，連大小寫都不同。
    /// </summary>
    [Theory]
    [InlineData("NCsoft Corp.")]        // C=KR，SGTRUST CODE SIGNING CA
    [InlineData("NCsoft")]              // C=US，VeriSign
    [InlineData("NCSOFT Corporation")]  // 技術設計文件所載
    [InlineData("NCSOFT CORP.")]        // 大小寫不構成安全邊界
    [InlineData("  NCsoft Corp.  ")]    // 前後空白不應影響判定
    public void 已知的官方組織名稱判為Official(string organization)
        => Assert.Equal(SignerVerdict.Official, SignerNameValidator.Classify(organization));

    /// <summary>
    /// 含 NCSOFT 但不在清單中 —— 很可能是尚未收錄的官方憑證變體。
    /// 判 LikelyOfficial 而非 NotOfficial，避免把正版使用者嚇去重灌。
    /// </summary>
    [Theory]
    [InlineData("NCSOFT Taiwan Ltd.")]
    [InlineData("NCsoft West")]
    [InlineData("NCSOFT 서비스")]
    public void 含NCSOFT但未收錄判為LikelyOfficial(string organization)
        => Assert.Equal(SignerVerdict.LikelyOfficial, SignerNameValidator.Classify(organization));

    [Theory]
    [InlineData("Evil Ltd")]
    [InlineData("Microsoft Corporation")]
    [InlineData("NC Soft Corporation")]   // 有空格就不含 "NCSOFT" 這個字串
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void 與NCSOFT無關者判為NotOfficial(string? organization)
        => Assert.Equal(SignerVerdict.NotOfficial, SignerNameValidator.Classify(organization));

    [Fact]
    public void 放寬比對後CN陷阱仍然擋得住()
    {
        // 放寬到「含 NCSOFT」之後，最需要確認的就是這一點：
        // 我們仍然只看 O= 欄位，把 NCSOFT 塞進 CN 依然無效
        var dn = new X500DistinguishedName("CN=NCSOFT Corporation, O=Evil Ltd, C=TW");

        Assert.Equal(SignerVerdict.NotOfficial,
            SignerNameValidator.Classify(SignerNameValidator.GetOrganization(dn)));
    }

    [Fact]
    public void 實際觀察到的韓國法人憑證可正確解析()
    {
        var dn = new X500DistinguishedName(
            "CN=NCsoft Corp., O=NCsoft Corp., STREET=507 Teheran-ro, L=Seoul, S=Seoul, C=KR");

        Assert.Equal("NCsoft Corp.", SignerNameValidator.GetOrganization(dn));
        Assert.Equal(SignerVerdict.Official, SignerNameValidator.Classify(dn));
    }

    [Fact]
    public void 實際觀察到的美國法人憑證可正確解析()
    {
        var dn = new X500DistinguishedName(
            "CN=NCsoft, OU=Digital ID Class 3 - Microsoft Software Validation v2, "
            + "O=NCsoft, L=Austin, S=Texas, C=US");

        Assert.Equal("NCsoft", SignerNameValidator.GetOrganization(dn));
        Assert.Equal(SignerVerdict.Official, SignerNameValidator.Classify(dn));
    }

    [Fact]
    public void 多值RDN不會讓解析爆掉()
    {
        // 韓國憑證可能出現多值 RDN（技術設計 §9-3 待實測）。
        // 目前行為：跳過多值 RDN，繼續找後面的單值 O=，不拋例外。
        var dn = new X500DistinguishedName("CN=A+OU=B, O=NCSOFT Corporation");

        var organization = SignerNameValidator.GetOrganization(dn);

        Assert.Equal("NCSOFT Corporation", organization);
    }
}
