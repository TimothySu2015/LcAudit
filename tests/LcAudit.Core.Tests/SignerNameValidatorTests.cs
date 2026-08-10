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
        Assert.False(SignerNameValidator.IsExpectedOrganization(
            SignerNameValidator.GetOrganization(dn)));
    }

    [Fact]
    public void 沒有O欄位回傳null()
    {
        var dn = new X500DistinguishedName("CN=NCSOFT Corporation");

        Assert.Null(SignerNameValidator.GetOrganization(dn));
    }

    [Theory]
    [InlineData("NCSOFT Corporation", true)]
    [InlineData("NCSOFT corporation", false)]   // 區分大小寫
    [InlineData("NCSOFT Corporation ", false)]  // 尾隨空白視為不同組織
    [InlineData("NCSOFT", false)]
    [InlineData("Evil Ltd", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void 組織名稱須完全相符(string? organization, bool expected)
        => Assert.Equal(expected, SignerNameValidator.IsExpectedOrganization(organization));

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
