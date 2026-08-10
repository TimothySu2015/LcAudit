using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-01 主程式數位簽章狀態。
/// <para>功能規格：<c>Status ≠ Valid</c> → <c>Fail</c>，Severity <b>Critical</b>。</para>
/// </summary>
public sealed class M1_01_SignatureStatusCheck(IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M1-01";

    public string Module => "M1";

    public string Title => "主程式數位簽章狀態";

    public Severity Severity => Severity.Critical;

    public string Source => "WinVerifyTrust / WINTRUST_ACTION_GENERIC_VERIFY_V2";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Inconclusive(context.PurpleInstallPath));
        }

        var verdict = verifier.Verify(executable);
        return ValueTask.FromResult(Evaluate(verdict));
    }

    /// <summary>純判定邏輯，可用 fake verifier 單元測試。</summary>
    internal Finding Evaluate(SignatureVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        var (status, description, recommendation) = verdict.Trust switch
        {
            SignatureTrust.Valid =>
                (CheckStatus.Pass, "主程式具備有效的內嵌數位簽章。", (string?)null),

            SignatureTrust.BadDigest =>
                (CheckStatus.Fail,
                 "主程式已簽章但雜湊不符 —— 檔案在簽章後被竄改。這是最明確的入侵跡證之一。",
                 "立即停止使用此電腦登入遊戲，保存本報告後重灌系統。"),

            SignatureTrust.NoSignature =>
                (CheckStatus.Fail,
                 "主程式完全沒有內嵌數位簽章。官方紫P 一律經過簽章，未簽章即代表這不是官方版本。",
                 "刪除現有安裝，從官方網站重新下載。在確認端點乾淨前不要登入遊戲。"),

            SignatureTrust.ExplicitDistrust =>
                (CheckStatus.Fail, "簽章憑證已被系統明確列為不信任。", "視同惡意程式處理。"),

            SignatureTrust.SubjectNotTrusted =>
                (CheckStatus.Fail, "簽章主體不受信任。", "確認來源，不要執行。"),

            SignatureTrust.ChainIncomplete =>
                (CheckStatus.Fail,
                 "憑證鏈不完整，通常代表使用自簽憑證 —— 偽造程式的典型特徵。",
                 "刪除現有安裝，從官方網站重新下載。"),

            SignatureTrust.Expired =>
                (CheckStatus.Warning,
                 "簽章憑證已過期。若簽章當下附有時間戳，仍可能是正常的舊版本（見 M1-03）。",
                 "確認紫P 版本是否過舊，建議更新至最新版。"),

            SignatureTrust.SecuritySettings =>
                (CheckStatus.Warning,
                 "本機安全性原則阻擋了簽章驗證，無法確認簽章狀態。這不是簽章本身的問題。",
                 "檢查群組原則或防毒軟體是否干擾憑證驗證。"),

            SignatureTrust.FileNotReadable =>
                (CheckStatus.Inconclusive, "主程式無法讀取，或不是有效的 PE 檔案。", null),

            _ => (CheckStatus.Inconclusive,
                  $"未預期的驗證結果（HRESULT 0x{verdict.HResult:X8}）。", null),
        };

        return new Finding
        {
            Id = Id,
            Module = Module,
            Title = Title,
            Severity = Severity,
            Status = status,
            Source = Source,
            Description = description,
            Recommendation = recommendation,
            Evidence =
            [
                new Evidence("檔案路徑", verdict.FilePath),
                new Evidence("HRESULT", $"0x{verdict.HResult:X8}"),
                new Evidence("判定", verdict.Trust.ToString()),
            ],
        };
    }

    private Finding Inconclusive(string? installPath) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = CheckStatus.Inconclusive,
        Source = Source,
        Description = installPath is null
            ? "未探測到紫P 安裝路徑（M1-00），無法驗證主程式簽章。"
            : $"在安裝路徑中找不到主程式（已嘗試 {string.Join("、", PurpleExecutableLocator.CandidateNames)}）。",
        Recommendation = "可用 --purple-path 手動指定安裝目錄後重新執行。",
        Evidence = installPath is null ? [] : [new Evidence("安裝路徑", installPath)],
    };
}
