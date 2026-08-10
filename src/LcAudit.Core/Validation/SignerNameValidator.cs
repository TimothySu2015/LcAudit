using System.Security.Cryptography.X509Certificates;

namespace LcAudit.Core.Validation;

/// <summary>簽章者身分的判定結果。</summary>
public enum SignerVerdict
{
    /// <summary>組織名稱與已知的官方值相符。</summary>
    Official,

    /// <summary>
    /// 組織名稱含 NCSOFT 但不在已知清單中 —— 很可能是尚未收錄的官方憑證變體。
    /// 判 Warning 而非 Fail，避免把正版使用者嚇去重灌。
    /// </summary>
    LikelyOfficial,

    /// <summary>組織名稱與 NCSOFT 無關。這才是明確的假紫P。</summary>
    NotOfficial,
}

/// <summary>
/// M1-02 簽章者身分比對（技術設計 §4.3）。
/// <para>
/// <b>必須解析 DN 後比對 O= 欄位。</b><c>cert.Subject.Contains("NCSOFT")</c> 會讓
/// <c>CN=NCSOFT-Free-Launcher, O=Evil Ltd</c> 通過 —— 攻擊者只要把字串塞進 CN 就能繞過。
/// </para>
/// </summary>
public static class SignerNameValidator
{
    /// <summary>
    /// 已知的官方簽章者組織名稱。
    /// <para>
    /// <b>同一個發行者名下有多張憑證，字串並不一致</b>，且不同法人（韓國／美國／各地區）
    /// 的組織名稱寫法也不同。已實際觀察到的值：
    /// </para>
    /// <list type="bullet">
    /// <item><c>NCsoft Corp.</c> — 韓國法人（<c>L=Seoul, C=KR</c>，SGTRUST CODE SIGNING CA）</item>
    /// <item><c>NCsoft</c> — 美國法人（<c>L=Austin, S=Texas, C=US</c>，VeriSign）</item>
    /// </list>
    /// <para>
    /// <b>技術設計 §4.3 寫的 <c>NCSOFT Corporation</c> 是錯的</b>，且從未經實檔驗證。
    /// 現行官方安裝檔的簽章者是 <c>NC Corporation</c> —— 公司已更名，連 "NCSOFT"
    /// 這個字串都不再出現。舊值保留在清單中僅為相容於尚未更新的舊安裝。
    /// </para>
    /// <para>
    /// 拿到新的實際值時請加進這裡 —— 加入清單只會讓判定更準，不會放寬安全性，
    /// 因為 <see cref="Classify"/> 對「疑似官方」本來就已經給出 Warning 而非 Pass。
    /// </para>
    /// </summary>
    public static readonly IReadOnlyList<string> KnownOfficialOrganizations =
    [
        // 現行值 —— 取自官方安裝檔 PURPLE_Installer_2_26_803_19.exe 的實際簽章，
        // 完整 Subject：CN=NC Corporation, O=NC Corporation, L=Seongnam, S=Gyeonggi, C=KR
        // 簽發者為 Microsoft ID Verified CS EOC CA（Azure Trusted Signing）。
        "NC Corporation",

        // 舊值 —— NCSOFT 更名為 NC Corporation 之前的憑證
        "NCsoft Corp.",
        "NCsoft",
        "NCSOFT Corporation",
        "NCSOFT Corp.",
        "NCSOFT",
    ];

    /// <summary>
    /// Organization 屬性的 OID。
    /// 刻意比對 OID 而非 <c>FriendlyName</c> —— FriendlyName 依平台與地區設定而異，
    /// 在 Linux CI 上跑單元測試時可能拿不到 "O"。
    /// </summary>
    private const string OrganizationOid = "2.5.4.10";

    /// <summary>取出 DN 中的 O= 欄位值；不存在回 <c>null</c>。</summary>
    public static string? GetOrganization(X500DistinguishedName subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        foreach (var rdn in subject.EnumerateRelativeDistinguishedNames())
        {
            // 多值 RDN 會讓 GetSingleElementType 拋 InvalidOperationException。
            // 韓國憑證可能出現這種結構（技術設計 §9-3 待實測），先跳過而非讓整個檢查爆掉。
            string? oid;
            try
            {
                oid = rdn.GetSingleElementType().Value;
            }
            catch (InvalidOperationException)
            {
                continue;
            }

            if (string.Equals(oid, OrganizationOid, StringComparison.Ordinal))
            {
                return rdn.GetSingleElementValue();
            }
        }

        return null;
    }

    /// <summary>
    /// 比對組織名稱。分離出來讓測試不必準備真實憑證。
    /// <para>
    /// 三級判定，刻意往「不誤傷正版」的方向失敗：官方憑證的實際字串有多種寫法，
    /// 若一律要求完全相符，正版使用者會被告知「假紫P，建議重灌」——
    /// 那是這個工具最嚴重的失敗模式。
    /// </para>
    /// <para>
    /// 這不會重新打開 CN 陷阱：仍然只看解析出來的 <c>O=</c> 欄位，
    /// <c>CN=NCSOFT-Free-Launcher, O=Evil Ltd</c> 照樣判定為非官方。
    /// 要讓 <c>O=</c> 含有 NCSOFT，攻擊者必須讓公開信任的 CA 簽發憑證給一個
    /// 法定名稱含 NCSOFT 的公司，而 CA 會查驗公司登記文件。
    /// </para>
    /// </summary>
    public static SignerVerdict Classify(string? organization)
    {
        if (string.IsNullOrWhiteSpace(organization))
        {
            return SignerVerdict.NotOfficial;
        }

        var trimmed = organization.Trim();

        // 大小寫不納入判斷 —— 已觀察到 NCsoft 與 NCSOFT 兩種寫法，
        // 而大小寫本來就不構成安全邊界。
        if (KnownOfficialOrganizations.Any(known =>
                string.Equals(trimmed, known, StringComparison.OrdinalIgnoreCase)))
        {
            return SignerVerdict.Official;
        }

        return IsNcGroupName(trimmed) ? SignerVerdict.LikelyOfficial : SignerVerdict.NotOfficial;
    }

    /// <summary>
    /// 組織名稱看起來屬於 NC 集團。
    /// <para>
    /// 比對<b>第一個字詞</b>是否為 <c>NC</c> 或以 <c>NCSOFT</c> 開頭，
    /// 而非用 <c>Contains</c>。集團旗下有多個法人（NC Corporation、NC Taiwan、
    /// NCsoft Corp.…），但用 Contains 會讓 <c>Encoding Ltd</c> 這種含 "nc" 的
    /// 無關公司通過。
    /// </para>
    /// <para>
    /// 以字詞邊界比對可正確排除 <c>NCR Corporation</c>、<c>NCC Group</c> 這類
    /// 前綴相近但無關的公司。
    /// </para>
    /// </summary>
    private static bool IsNcGroupName(string organization)
    {
        var firstToken = organization
            .Split([' ', ',', '.'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();

        if (string.IsNullOrEmpty(firstToken))
        {
            return false;
        }

        return firstToken.Equals("NC", StringComparison.OrdinalIgnoreCase)
               || firstToken.StartsWith("NCSOFT", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>判斷 DN 的簽章者身分。</summary>
    public static SignerVerdict Classify(X500DistinguishedName subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return Classify(GetOrganization(subject));
    }

    /// <summary>判斷憑證的簽章者身分。</summary>
    public static SignerVerdict Classify(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Classify(certificate.SubjectName);
    }
}
