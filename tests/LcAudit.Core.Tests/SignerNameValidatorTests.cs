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
    [InlineData("NC Corporation")]      // 現行值，取自官方安裝檔實際簽章
    [InlineData("NCsoft Corp.")]        // 舊值，C=KR，SGTRUST CODE SIGNING CA
    [InlineData("NCsoft")]              // 舊值，C=US，VeriSign
    [InlineData("NCSOFT Corporation")]  // 技術設計文件所載（實際上是錯的）
    [InlineData("NCSOFT CORP.")]        // 大小寫不構成安全邊界
    [InlineData("  NC Corporation  ")]  // 前後空白不應影響判定
    public void 已知的官方組織名稱判為Official(string organization)
        => Assert.Equal(SignerVerdict.Official, SignerNameValidator.Classify(organization));

    /// <summary>
    /// <b>本檔最重要的回歸測試。</b>
    /// <para>
    /// 官方安裝檔 PURPLE_Installer_2_26_803_19.exe 的實際簽章者。
    /// 公司已從 NCSOFT 更名為 NC Corporation，組織名稱中不再含 "NCSOFT" 字串 ——
    /// 任何以 <c>Contains("NCSOFT")</c> 為基礎的判定都會把官方安裝檔判為假紫P，
    /// 對 100% 的正常使用者喊「端點已不可信，建議重灌」。
    /// </para>
    /// </summary>
    [Fact]
    public void 官方安裝檔的實際簽章者必須判為Official()
    {
        var dn = new X500DistinguishedName(
            "CN=NC Corporation, O=NC Corporation, L=Seongnam, S=Gyeonggi, C=KR");

        Assert.Equal("NC Corporation", SignerNameValidator.GetOrganization(dn));
        Assert.Equal(SignerVerdict.Official, SignerNameValidator.Classify(dn));
    }

    /// <summary>
    /// 含 NCSOFT 但不在清單中 —— 很可能是尚未收錄的官方憑證變體。
    /// 判 LikelyOfficial 而非 NotOfficial，避免把正版使用者嚇去重灌。
    /// </summary>
    /// <summary>
    /// 集團旗下的其他法人 —— 第一個字詞為 NC 或 NCSOFT 開頭即視為疑似官方。
    /// 判 LikelyOfficial（Warning）而非 NotOfficial（Fail），避免把正版使用者嚇去重灌。
    /// </summary>
    [Theory]
    [InlineData("NC Taiwan Co., Ltd.")]
    [InlineData("NC Japan K.K.")]
    [InlineData("NCSOFT Taiwan Ltd.")]
    [InlineData("NCsoft West")]
    [InlineData("NC Soft Corporation")]
    public void NC集團的其他法人判為LikelyOfficial(string organization)
        => Assert.Equal(SignerVerdict.LikelyOfficial, SignerNameValidator.Classify(organization));

    /// <summary>
    /// 用字詞邊界比對而非 Contains，才排得掉這些前綴相近但無關的公司。
    /// 若用 <c>Contains("NC")</c>，連 Encoding Ltd 都會通過。
    /// </summary>
    [Theory]
    [InlineData("Evil Ltd")]
    [InlineData("Microsoft Corporation")]
    [InlineData("NCR Corporation")]
    [InlineData("NCC Group")]
    [InlineData("Encoding Ltd")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void 與NC集團無關者判為NotOfficial(string? organization)
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
