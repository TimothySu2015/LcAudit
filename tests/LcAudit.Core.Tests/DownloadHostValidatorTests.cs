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

    [Fact]
    public void 白名單內容符合功能規格()
        => Assert.Equal(
            ["plaync.com", "playnccdn.com", "ncsoft.com"],
            DownloadHostValidator.AllowedHosts);
}
