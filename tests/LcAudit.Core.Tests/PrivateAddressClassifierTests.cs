using LcAudit.Core.Validation;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>
/// M2-02 的判定依據。誤把私有位址判為公網 → 正常區網登入被報 Fail(20 分)。
/// </summary>
public sealed class PrivateAddressClassifierTests
{
    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("100.64.0.1")]      // CGNAT —— 電信業者常用，漏掉會大量誤報
    [InlineData("100.127.255.255")]
    [InlineData("169.254.1.1")]     // link-local
    [InlineData("::1")]             // IPv6 loopback
    [InlineData("fe80::1")]         // IPv6 link-local
    [InlineData("fc00::1")]         // IPv6 ULA
    [InlineData("fd12:3456::1")]    // IPv6 ULA
    [InlineData("::ffff:192.168.0.1")]  // IPv4-mapped，須先攤平
    public void 私有與本機位址(string address)
        => Assert.Equal(AddressScope.Private, PrivateAddressClassifier.Classify(address));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.15.0.1")]      // 172.16/12 的下邊界外
    [InlineData("172.32.0.1")]      // 上邊界外
    [InlineData("192.169.1.1")]     // 192.168/16 外
    [InlineData("100.63.0.1")]      // CGNAT 下邊界外
    [InlineData("100.128.0.1")]     // 上邊界外
    [InlineData("169.253.1.1")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.8.8")]
    public void 公網位址(string address)
        => Assert.Equal(AddressScope.Public, PrivateAddressClassifier.Classify(address));

    [Theory]
    [InlineData("-")]               // 4624 本機登入時的常見值
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    public void 佔位值不得被當成公網(string? address)
        => Assert.Equal(AddressScope.Unspecified, PrivateAddressClassifier.Classify(address));

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("999.999.999.999")]
    [InlineData("WORKSTATION-01")]
    public void 無法解析的值(string address)
        => Assert.Equal(AddressScope.Invalid, PrivateAddressClassifier.Classify(address));

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("-", false)]
    [InlineData("not-an-ip", false)]
    public void 只有明確的公網位址算外部來源(string address, bool expected)
        => Assert.Equal(expected, PrivateAddressClassifier.IsExternalSource(address));
}
