using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Validation;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-02 簽章者身分。
/// <para>
/// 功能規格：簽章者非 NCSOFT → <c>Fail</c>，Severity <b>Critical</b>。
/// 比對走 DN 的 O= 欄位，不可用 <c>Subject.Contains("NCSOFT")</c>。
/// </para>
/// </summary>
public sealed class M1_02_SignerIdentityCheck(IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M1-02";

    public string Module => "M1";

    public string Title => "簽章者身分";

    public Severity Severity => Severity.Critical;

    public string Source => "CryptQueryObject / PKCS7_SIGNED_EMBED";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "未取得紫P 主程式路徑，無法比對簽章者。",
                "可用 --purple-path 手動指定安裝目錄後重新執行。",
                []));
        }

        return ValueTask.FromResult(Evaluate(verifier.Verify(executable)));
    }

    /// <summary>純判定邏輯，可用 fake verifier 單元測試。</summary>
    internal Finding Evaluate(SignatureVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        Evidence[] evidence =
        [
            new Evidence("檔案路徑", verdict.FilePath),
            new Evidence("簽章者 O=", verdict.SignerOrganization ?? "(無)"),
            new Evidence("完整 Subject", verdict.SignerSubject ?? "(無)"),
        ];

        // 檔案讀不到是環境問題，不是身分不符 —— 不可判 Fail。
        if (verdict.Trust == SignatureTrust.FileNotReadable)
        {
            return Build(CheckStatus.Inconclusive, "主程式無法讀取，無法比對簽章者。", null, evidence);
        }

        // 沒有簽章者可比對就是不符。M1-01 會另外報告「未簽章」這件事本身。
        if (verdict.SignerOrganization is null)
        {
            return Build(
                CheckStatus.Fail,
                "無法從主程式取得簽章者資訊 —— 檔案未經簽章，或簽章結構不合法。",
                "刪除現有安裝，從官方網站重新下載。",
                evidence);
        }

        if (!SignerNameValidator.IsExpectedOrganization(verdict.SignerOrganization))
        {
            return Build(
                CheckStatus.Fail,
                $"簽章者組織為「{verdict.SignerOrganization}」，非官方的「{SignerNameValidator.ExpectedOrganization}」。"
                + "這是假紫P 最明確的特徵。",
                "立即停止使用此電腦登入遊戲，保存本報告後重灌系統，並在乾淨裝置上更改密碼。",
                evidence);
        }

        // 簽章者對了，但簽章本身無效 —— 憑證可能是從官方檔案抽出來重用的。
        if (verdict.Trust != SignatureTrust.Valid)
        {
            return Build(
                CheckStatus.Fail,
                $"簽章者組織相符，但簽章狀態為 {verdict.Trust} —— 憑證正確不代表簽章有效，"
                + "這正是把官方憑證塞進偽造檔案的手法會呈現的樣子。",
                "視同假紫P 處理，刪除現有安裝並重新下載。",
                evidence);
        }

        return Build(CheckStatus.Pass, "簽章者為 NCSOFT 官方，且簽章有效。", null, evidence);
    }

    private Finding Build(CheckStatus status, string description, string? recommendation, Evidence[] evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Recommendation = recommendation,
        Evidence = evidence,
    };
}
