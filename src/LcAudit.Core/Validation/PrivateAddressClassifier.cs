using System.Net;
using System.Net.Sockets;

namespace LcAudit.Core.Validation;

/// <summary>位址的網路歸屬。</summary>
public enum AddressScope
{
    /// <summary>私有／本機位址 —— 來自區網或本機，M2-02 不判為異常。</summary>
    Private,

    /// <summary>公網位址 —— M2-02 的 Fail 條件。</summary>
    Public,

    /// <summary>事件記錄常見的佔位值（<c>-</c>、空字串、<c>0.0.0.0</c>），無來源可言。</summary>
    Unspecified,

    /// <summary>無法解析為 IP 位址。</summary>
    Invalid,
}

/// <summary>
/// M2-02「來源 IP 非私有網段 → Fail」的判定依據。
/// <para>
/// 功能規格只寫「非私有網段」而未列舉，這裡是定案的清單。漏掉任何一段都會讓
/// 正常的區網或 CGNAT 登入被判為 <c>Fail</c>（High，20 分）—— 誤報比漏報更傷可信度。
/// </para>
/// <para>
/// Security 4624 的 <c>IpAddress</c> 欄位在本機登入時常是 <c>-</c> 或空字串，
/// 未特別處理會被當成「非私有」而誤判，因此獨立為 <see cref="AddressScope.Unspecified"/>。
/// </para>
/// </summary>
public static class PrivateAddressClassifier
{
    public static AddressScope Classify(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || address == "-")
        {
            return AddressScope.Unspecified;
        }

        if (!IPAddress.TryParse(address.Trim(), out var ip))
        {
            return AddressScope.Invalid;
        }

        return Classify(ip);
    }

    public static AddressScope Classify(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // IPv4-mapped IPv6（::ffff:192.168.0.1）需先攤平，否則會被當成一般 IPv6 判為公網
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => ClassifyIPv4(address),
            AddressFamily.InterNetworkV6 => ClassifyIPv6(address),
            _ => AddressScope.Invalid,
        };
    }

    private static AddressScope ClassifyIPv4(IPAddress address)
    {
        var b = address.GetAddressBytes();

        // 0.0.0.0/8 —— 未指定
        if (b[0] == 0)
        {
            return AddressScope.Unspecified;
        }

        return b[0] switch
        {
            10 => AddressScope.Private,                                   // RFC1918 10/8
            127 => AddressScope.Private,                                  // loopback 127/8
            172 when b[1] is >= 16 and <= 31 => AddressScope.Private,     // RFC1918 172.16/12
            192 when b[1] == 168 => AddressScope.Private,                 // RFC1918 192.168/16
            100 when b[1] is >= 64 and <= 127 => AddressScope.Private,    // CGNAT 100.64/10
            169 when b[1] == 254 => AddressScope.Private,                 // link-local 169.254/16
            _ => AddressScope.Public,
        };
    }

    private static AddressScope ClassifyIPv6(IPAddress address)
    {
        if (IPAddress.IPv6Any.Equals(address))
        {
            return AddressScope.Unspecified;
        }

        if (IPAddress.IPv6Loopback.Equals(address)
            || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal)
        {
            return AddressScope.Private;
        }

        // Unique Local Address fc00::/7 —— 前 7 bit 為 1111110
        var b = address.GetAddressBytes();
        return (b[0] & 0xFE) == 0xFC ? AddressScope.Private : AddressScope.Public;
    }

    /// <summary>是否應視為「來自外部的連線」—— 只有明確的公網位址才算。</summary>
    public static bool IsExternalSource(string? address) => Classify(address) == AddressScope.Public;
}
