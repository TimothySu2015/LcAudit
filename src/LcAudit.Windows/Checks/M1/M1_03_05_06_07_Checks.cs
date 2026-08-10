using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// M1-03 憑證鏈與時間戳。
/// <para>功能規格：憑證過期且無時間戳 → <c>Warning</c>。Severity Medium。</para>
/// <para>
/// <b>時間戳的有無不需要另外抽取</b>：Authenticode 的規則就是「憑證過期但簽章當下有
/// 合法時間戳 → 仍視為有效」。所以 <c>WinVerifyTrust</c> 回 <c>Valid</c> 但憑證
/// <c>NotAfter</c> 已過，就代表有時間戳；回 <c>CERT_E_EXPIRED</c> 就代表沒有。
/// 省下一整套 counter-signature 的 Crypt32 剖析。
/// </para>
/// </summary>
public sealed class M1_03_CertificateChainCheck(IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M1-03";

    public string Module => "M1";

    public string Title => "憑證鏈與時間戳";

    public Severity Severity => Severity.Medium;

    public string Source => "簽章者憑證的 NotBefore / NotAfter";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var executable = PurpleExecutableLocator.FindMainExecutable(context.PurpleInstallPath);
        if (executable is null)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive, "未取得紫P 主程式路徑。", null, []));
        }

        return ValueTask.FromResult(Evaluate(verifier.Verify(executable), DateTimeOffset.Now));
    }

    internal Finding Evaluate(SignatureVerdict verdict, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        if (verdict.NotAfter is null)
        {
            return Build(CheckStatus.Inconclusive, "取不到簽章者憑證的有效期間。", null, []);
        }

        var evidence = new Evidence[]
        {
            new("憑證有效期起", verdict.NotBefore?.ToString("yyyy-MM-dd") ?? "(未知)"),
            new("憑證有效期迄", verdict.NotAfter.Value.ToString("yyyy-MM-dd")),
            new("簽章驗證結果", verdict.Trust.ToString()),
        };

        var expired = verdict.NotAfter.Value < now;

        if (!expired)
        {
            return Build(CheckStatus.Pass, "簽章者憑證在有效期間內。", null, evidence);
        }

        // 憑證過期但 WinVerifyTrust 仍判有效 → 簽章當下有合法時間戳，這是正常的舊版本
        if (verdict.Trust == SignatureTrust.Valid)
        {
            return Build(
                CheckStatus.Pass,
                "簽章者憑證已過期，但簽章當下附有合法時間戳，簽章仍然有效。這是舊版本程式的正常狀態。",
                null,
                evidence);
        }

        return Build(
            CheckStatus.Warning,
            "簽章者憑證已過期，且沒有合法的簽章時間戳可佐證簽章時間點。"
            + "無法確認這個簽章是在憑證有效期內產生的。",
            "建議從官網下載並安裝最新版本。",
            evidence);
    }

    private Finding Build(
        CheckStatus status, string description, string? recommendation, IReadOnlyList<Evidence> evidence)
        => new()
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

/// <summary>
/// M1-05 安裝目錄未簽章模組。
/// <para>功能規格：遞迴掃描 <c>*.exe</c>／<c>*.dll</c>，存在未簽章檔案 → <c>Warning</c>。Severity High。</para>
/// <para>
/// 開檔一律用 <c>FileShare.ReadWrite | FileShare.Delete</c> —— share mode 給不夠會
/// 反過來害執行中的 launcher 檔案操作失敗。唯讀原則不只是不寫，也包含不干擾。
/// </para>
/// </summary>
public sealed class M1_05_UnsignedModulesCheck(IAuthenticodeVerifier verifier) : ICheck
{
    /// <summary>掃描筆數上限，避免安裝目錄異常龐大時吃掉整個時間預算（NFR-01）。</summary>
    internal const int MaxFilesToScan = 2000;

    public string Id => "M1-05";

    public string Module => "M1";

    public string Title => "安裝目錄未簽章模組";

    public Severity Severity => Severity.High;

    public string Source => "紫P 安裝目錄遞迴掃描（*.exe、*.dll）";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(context.PurpleInstallPath) || !Directory.Exists(context.PurpleInstallPath))
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive, "未取得紫P 安裝目錄。", null, []));
        }

        var unsigned = new List<(string Path, SignatureTrust Trust)>();
        var scanned = 0;

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,   // 權限不足的子目錄跳過，不中斷整體掃描
            AttributesToSkip = FileAttributes.ReparsePoint,   // 不跟隨連結點，避免無限遞迴
        };

        foreach (var file in Directory.EnumerateFiles(context.PurpleInstallPath, "*", options))
        {
            ct.ThrowIfCancellationRequested();

            var extension = Path.GetExtension(file);
            if (!extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                && !extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (++scanned > MaxFilesToScan)
            {
                break;
            }

            var trust = verifier.Verify(file).Trust;
            if (trust != SignatureTrust.Valid)
            {
                unsigned.Add((file, trust));
            }
        }

        return ValueTask.FromResult(Evaluate(unsigned, scanned));
    }

    internal Finding Evaluate(IReadOnlyList<(string Path, SignatureTrust Trust)> unsigned, int scanned)
    {
        ArgumentNullException.ThrowIfNull(unsigned);

        if (scanned == 0)
        {
            return Build(CheckStatus.Inconclusive, "安裝目錄中沒有可掃描的執行檔或模組。", null, []);
        }

        if (unsigned.Count == 0)
        {
            return Build(CheckStatus.Pass, $"掃描 {scanned} 個模組，全部具備有效簽章。", null, []);
        }

        var tampered = unsigned.Count(u => u.Trust == SignatureTrust.BadDigest);

        return Build(
            CheckStatus.Warning,
            $"掃描 {scanned} 個模組，其中 {unsigned.Count} 個未簽章或簽章無效"
            + (tampered > 0 ? $"，並有 {tampered} 個**檔案內容與簽章不符（已被竄改）**" : string.Empty)
            + "。官方紫P 的模組應全數具備 NCSOFT 簽章。",
            tampered > 0
                ? "有模組被竄改，立即停止使用此電腦登入遊戲，保存本報告後重灌系統。"
                : "確認這些模組的來源。不認得的請保存本報告後從官網重新安裝。",
            [
                .. unsigned.OrderByDescending(u => u.Trust == SignatureTrust.BadDigest)
                           .Take(50)
                           .Select(u => new Evidence(
                               u.Trust == SignatureTrust.BadDigest ? "⚠ 已竄改" : "未簽章",
                               $"{u.Path}（{u.Trust}）")),
            ]);
    }

    private Finding Build(
        CheckStatus status, string description, string? recommendation, IReadOnlyList<Evidence> evidence)
        => new()
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

/// <summary>
/// M1-06 可疑檔名相似度。
/// <para>功能規格：出現 <c>Purple*.exe</c> 的變體（如 <c>PurpIe</c>、<c>Purple_new</c>）→ <c>Warning</c>。Severity High。</para>
/// </summary>
public sealed class M1_06_SuspiciousFileNameCheck : ICheck
{
    public string Id => "M1-06";

    public string Module => "M1";

    public string Title => "可疑的相似檔名";

    public Severity Severity => Severity.High;

    public string Source => "紫P 安裝目錄檔名比對";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(context.PurpleInstallPath) || !Directory.Exists(context.PurpleInstallPath))
        {
            return ValueTask.FromResult(Build(CheckStatus.Inconclusive, "未取得紫P 安裝目錄。", null, []));
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        var fileNames = Directory
            .EnumerateFiles(context.PurpleInstallPath, "*.exe", options)
            .Select(Path.GetFileName)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n!)
            .ToList();

        return ValueTask.FromResult(Evaluate(
            FileNameSimilarity.FindSuspicious(fileNames, PurpleExecutableLocator.CandidateNames),
            fileNames.Count));
    }

    internal Finding Evaluate(IReadOnlyList<SimilarFileName> suspicious, int scanned)
    {
        ArgumentNullException.ThrowIfNull(suspicious);

        if (suspicious.Count == 0)
        {
            return Build(CheckStatus.Pass, $"檢查 {scanned} 個執行檔，沒有與主程式相似的可疑檔名。", null, []);
        }

        return Build(
            CheckStatus.Warning,
            $"發現 {suspicious.Count} 個與紫P 主程式相似但不相同的檔名。"
            + "用視覺上難以分辨的檔名冒充正版程式，是釣魚安裝檔的常見手法 ——"
            + "例如把小寫 l 換成大寫 I，肉眼幾乎看不出來。",
            "逐一確認這些檔案的來源與簽章。不認得的請保存本報告後移除。",
            [
                .. suspicious.Select(s => new Evidence(
                    $"⚠ {s.FileName}",
                    $"與「{s.SimilarTo}」相似（{Describe(s.Reason)}）")),
            ]);
    }

    private static string Describe(SimilarityReason reason) => reason switch
    {
        SimilarityReason.Homoglyph => "同形字元替換，視覺上難以分辨",
        SimilarityReason.CopySuffix => "正版名稱加上複製或版本後綴",
        SimilarityReason.NearMiss => "拼字極為接近",
        _ => "相似",
    };

    private Finding Build(
        CheckStatus status, string description, string? recommendation, IReadOnlyList<Evidence> evidence)
        => new()
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

/// <summary>
/// M1-07 安裝目錄位置合理性。
/// <para>功能規格：位於 <c>%TEMP%</c>、<c>Downloads</c>、<c>%APPDATA%</c> 等非標準位置 → <c>Warning</c>。Severity High。</para>
/// </summary>
public sealed class M1_07_InstallLocationCheck : ICheck
{
    public string Id => "M1-07";

    public string Module => "M1";

    public string Title => "安裝目錄位置合理性";

    public Severity Severity => Severity.High;

    public string Source => "紫P 安裝路徑";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(context.PurpleInstallPath));
    }

    internal Finding Evaluate(string? installPath)
    {
        if (string.IsNullOrWhiteSpace(installPath))
        {
            return Build(CheckStatus.Inconclusive, "未取得紫P 安裝目錄。", null, []);
        }

        var evidence = new Evidence[] { new("安裝路徑", installPath) };

        if (!CommandLineParser.IsSuspiciousLocation(installPath))
        {
            return Build(CheckStatus.Pass, "紫P 安裝在正常的程式目錄。", null, evidence);
        }

        return Build(
            CheckStatus.Warning,
            $"紫P 安裝在「{installPath}」—— 這是暫存或使用者資料目錄，不是正常的程式安裝位置。"
            + "正規安裝程式會裝到 Program Files；裝在這些位置通常代表是綠色版、破解版，或直接從壓縮檔解開來執行的。",
            "從官網重新下載安裝到預設位置，並移除目前這份。",
            evidence);
    }

    private Finding Build(
        CheckStatus status, string description, string? recommendation, IReadOnlyList<Evidence> evidence)
        => new()
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
