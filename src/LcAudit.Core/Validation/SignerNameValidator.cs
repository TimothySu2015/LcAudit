using System.Security.Cryptography.X509Certificates;

namespace LcAudit.Core.Validation;

/// <summary>
/// M1-02 簽章者身分比對（技術設計 §4.3）。
/// <para>
/// <b>必須解析 DN 後比對 O= 欄位。</b><c>cert.Subject.Contains("NCSOFT")</c> 會讓
/// <c>CN=NCSOFT-Free-Launcher, O=Evil Ltd</c> 通過 —— 攻擊者只要把字串塞進 CN 就能繞過。
/// </para>
/// </summary>
public static class SignerNameValidator
{
    /// <summary>官方簽章者的組織名稱，需完全相符（區分大小寫）。</summary>
    public const string ExpectedOrganization = "NCSOFT Corporation";

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

    /// <summary>比對組織名稱是否為官方值。分離出來讓測試不必準備真實憑證。</summary>
    public static bool IsExpectedOrganization(string? organization)
        => string.Equals(organization, ExpectedOrganization, StringComparison.Ordinal);

    /// <summary>判斷憑證的簽章者是否為 NCSOFT 官方。</summary>
    public static bool IsNcsoftSigner(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return IsExpectedOrganization(GetOrganization(certificate.SubjectName));
    }
}
