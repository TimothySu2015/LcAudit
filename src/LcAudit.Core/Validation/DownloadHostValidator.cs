namespace LcAudit.Core.Validation;

/// <summary>
/// M1-04 安裝檔下載來源白名單（技術設計 §4.4）。
/// <para>
/// <b>必須是後綴比對。</b><c>Contains</c>／<c>-like "*plaync*"</c> 會讓
/// <c>plaync.com.evil.tw</c> 與 <c>https://evil.com/?ref=plaync.com</c> 通過，
/// 整個 M1-04 就失效了。
/// </para>
/// </summary>
public static class DownloadHostValidator
{
    /// <summary>
    /// 官方網域白名單（功能規格 FR-M1）。
    /// 靜態清單，需隨官方變更手動維護（已知限制 L-06）。
    /// </summary>
    public static readonly IReadOnlyList<string> AllowedHosts =
        ["plaync.com", "playnccdn.com", "ncsoft.com"];

    /// <summary>
    /// 判斷下載來源 URL 是否來自官方網域。
    /// 無法解析、非 http(s)、或不在白名單一律回 <c>false</c>（fail closed）。
    /// </summary>
    public static bool IsAllowedDownloadHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        // 只認 http(s)。file://、ftp:// 等一律不視為官方來源。
        // Uri.UriSchemeHttp 是 static readonly 而非 const，不能寫成 is 模式，只能逐一比較。
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return false;
        }

        // IdnHost 會把 Punycode 正規化，擋掉同形異義網域；TrimEnd('.') 處理 FQDN 尾點。
        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0)
        {
            return false;
        }

        return AllowedHosts.Any(allowed =>
            string.Equals(host, allowed, StringComparison.Ordinal)
            || host.EndsWith('.' + allowed, StringComparison.Ordinal));
    }
}
