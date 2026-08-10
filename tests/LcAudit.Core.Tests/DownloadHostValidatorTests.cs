using LcAudit.Core.Validation;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>
/// M1-04 網域白名單（技術設計 §4.4 的驗收表）。
/// 這是整個工具最容易寫錯、寫錯又最沒感覺的一段 —— 誤放行等於 M1-04 完全失效。
/// </summary>
public sealed class DownloadHostValidatorTests
{
    [Theory]
    [InlineData("https://lineageclassic.plaync.com/download")]
    [InlineData("https://plaync.com/x")]
    [InlineData("http://plaync.com/x")]
    [InlineData("https://cdn.playnccdn.com/a/b")]
    [InlineData("https://ncsoft.com")]
    [InlineData("https://a.b.c.plaync.com/deep")]
    [InlineData("https://PLAYNC.COM/x")]              // 大小寫正規化
    [InlineData("https://plaync.com./x")]             // FQDN 尾點
    public void 官方網域應通過(string url)
        => Assert.True(DownloadHostValidator.IsAllowedDownloadHost(url));

    [Theory]
    [InlineData("https://plaync.com.evil.tw/x")]      // 後綴比對的核心案例
    [InlineData("https://evil.com/?ref=plaync.com")]  // 查詢字串誘餌
    [InlineData("https://plaync-com.tw/x")]           // 連字號變體
    [InlineData("https://EVIL.COM")]
    [InlineData("https://notplaync.com/x")]           // 未帶點的後綴
    [InlineData("https://plaync.com.tw/x")]           // 相似但非白名單
    [InlineData("https://evil.com/plaync.com")]       // 路徑誘餌
    public void 仿冒網域必須被擋(string url)
        => Assert.False(DownloadHostValidator.IsAllowedDownloadHost(url));

    [Theory]
    [InlineData("ftp://plaync.com/x")]
    [InlineData("file:///C:/temp/purple.exe")]
    public void 非HTTP協定不視為官方來源(string url)
        => Assert.False(DownloadHostValidator.IsAllowedDownloadHost(url));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    public void 無法解析的輸入一律不放行(string? url)
        => Assert.False(DownloadHostValidator.IsAllowedDownloadHost(url));

    [Fact]
    public void Punycode同形異義網域不得混入白名單()
    {
        // xn--plync-nsa.com 是含變音符號的仿冒網域，經 IdnHost 正規化後不等於 plaync.com
        Assert.False(DownloadHostValidator.IsAllowedDownloadHost("https://xn--plync-nsa.com/x"));
    }

    /// <summary>
    /// 官方下載頁指向 https://gs-purple-inst.download.ncupdate.com/Purple/PURPLE_Installer_*.exe
    /// —— 功能規格的白名單漏了 ncupdate.com。漏掉它的後果是：任何人從官網下載紫P
    /// 都會被判為非官方來源。
    /// </summary>
    [Fact]
    public void 官方安裝檔下載主機必須在白名單中()
        => Assert.Equal(
            DownloadSourceVerdict.Official,
            DownloadHostValidator.Classify(
                "https://gs-purple-inst.download.ncupdate.com/Purple/PURPLE_Installer_2_26_803_19.exe"));

    [Fact]
    public void 白名單包含已確認的官方網域()
        => Assert.Equal(
            ["plaync.com", "playnccdn.com", "ncsoft.com", "ncupdate.com"],
            DownloadHostValidator.AllowedHosts);

    // ---- 三級判定 ----

    [Theory]
    [InlineData("https://lineageclassic.plaync.com/download")]
    [InlineData("https://assets.playnccdn.com/x.png")]
    [InlineData("https://tw.ncsoft.com/x")]
    [InlineData("https://gs-purple-inst.download.ncupdate.com/x.exe")]
    public void 官方網域及其子網域判為Official(string url)
        => Assert.Equal(DownloadSourceVerdict.Official, DownloadHostValidator.Classify(url));

    /// <summary>
    /// 網域字串裡嵌了官方網域卻不是它的子網域 —— 只有刻意仿冒一種解釋，
    /// 這一級才判 Fail。
    /// </summary>
    [Theory]
    [InlineData("https://plaync.com.evil.tw/x.exe")]
    [InlineData("https://ncupdate.com.download.evil.tw/x.exe")]
    [InlineData("https://fake-plaync.com.tw/x.exe")]
    public void 嵌入官方網域的仿冒網址判為Impersonation(string url)
        => Assert.Equal(DownloadSourceVerdict.Impersonation, DownloadHostValidator.Classify(url));

    /// <summary>
    /// 與官方網域無關者判為 Unknown 而非惡意 —— 白名單是靜態清單、必定不完整，
    /// 官方隨時可能換 CDN。漏收的代價不該由使用者承擔。
    /// </summary>
    [Theory]
    [InlineData("https://some-mirror.example.com/purple.exe")]
    [InlineData("https://evil.com/?ref=plaync.com")]
    public void 與官方無關的網域判為Unknown(string url)
        => Assert.Equal(DownloadSourceVerdict.Unknown, DownloadHostValidator.Classify(url));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a url")]
    [InlineData("ftp://plaync.com/x")]
    [InlineData("file:///C:/temp/purple.exe")]
    public void 無法解析或非HTTP判為Invalid(string? url)
        => Assert.Equal(DownloadSourceVerdict.Invalid, DownloadHostValidator.Classify(url));
}
