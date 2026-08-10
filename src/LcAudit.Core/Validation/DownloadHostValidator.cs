namespace LcAudit.Core.Validation;

/// <summary>下載來源的判定結果。</summary>
public enum DownloadSourceVerdict
{
    /// <summary>官方網域或其子網域。</summary>
    Official,

    /// <summary>
    /// 網域字串中嵌了官方網域，卻不是它的子網域 —— 例如 <c>plaync.com.evil.tw</c>。
    /// 這只有刻意仿冒一種解釋。
    /// </summary>
    Impersonation,

    /// <summary>
    /// 與官方網域無關。可能是惡意來源，也可能只是白名單漏收的官方 CDN ——
    /// 白名單是靜態的，必定不完整，因此不逕行判定為惡意。
    /// </summary>
    Unknown,

    /// <summary>無法解析為 http(s) 網址。</summary>
    Invalid,
}

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
    /// <para>
    /// <b><c>ncupdate.com</c> 是實測確認的安裝檔下載主機</b>，功能規格的清單漏了它 ——
    /// 官方下載頁指向 <c>https://gs-purple-inst.download.ncupdate.com/Purple/PURPLE_Installer_*.exe</c>。
    /// 漏掉它的後果是：任何人從官網下載紫P 都會被判 Fail → Critical → 極高，
    /// 也就是對絕大多數正常使用者喊「假紫P，建議重灌」。
    /// </para>
    /// <para>
    /// 靜態清單，必定不完整（已知限制 L-06）。正因如此，
    /// <see cref="Classify"/> 對「不在清單中」只給 Unknown 而非直接視為惡意 ——
    /// 清單漏收的代價不該由使用者承擔。
    /// </para>
    /// </summary>
    public static readonly IReadOnlyList<string> AllowedHosts =
        ["plaync.com", "playnccdn.com", "ncsoft.com", "ncupdate.com"];

    /// <summary>
    /// 三級判定下載來源。
    /// <para>
    /// 白名單必定不完整（官方隨時可能換 CDN），所以「不在清單中」不等於「惡意」。
    /// 但「網域字串裡嵌了官方網域卻不是它的子網域」就是刻意仿冒，沒有第二種解釋 ——
    /// <c>plaync.com.evil.tw</c> 正是這種。這一級才判 Fail。
    /// </para>
    /// </summary>
    public static DownloadSourceVerdict Classify(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)
            || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return DownloadSourceVerdict.Invalid;
        }

        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0)
        {
            return DownloadSourceVerdict.Invalid;
        }

        foreach (var allowed in AllowedHosts)
        {
            // 正確的後綴比對：本身或其子網域
            if (string.Equals(host, allowed, StringComparison.Ordinal)
                || host.EndsWith('.' + allowed, StringComparison.Ordinal))
            {
                return DownloadSourceVerdict.Official;
            }

            // 網域中嵌了官方網域字串，卻不是它的子網域 —— 只有仿冒會長這樣
            if (host.Contains(allowed, StringComparison.Ordinal))
            {
                return DownloadSourceVerdict.Impersonation;
            }
        }

        return DownloadSourceVerdict.Unknown;
    }

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
