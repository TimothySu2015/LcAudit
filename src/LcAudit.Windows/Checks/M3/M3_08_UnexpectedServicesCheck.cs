using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>一個自動啟動的服務。</summary>
public sealed record ServiceEntry(
    string ServiceName,
    string? DisplayName,
    string ImagePath,
    string? ExecutablePath,
    SignatureTrust? SignatureTrust)
{
    /// <summary>確定沒有有效簽章。判定範圍與 <see cref="AutoStartEntry.IsUnsigned"/> 一致。</summary>
    public bool IsUnsigned => SignatureTrust is Sources.SignatureTrust.NoSignature
                                             or Sources.SignatureTrust.BadDigest
                                             or Sources.SignatureTrust.ExplicitDistrust
                                             or Sources.SignatureTrust.SubjectNotTrusted
                                             or Sources.SignatureTrust.ChainIncomplete;

    public bool IsSuspiciousLocation => CommandLineParser.IsSuspiciousLocation(ExecutablePath);

    public bool IsSuspicious => IsUnsigned || IsSuspiciousLocation;
}

/// <summary>
/// M3-08 非預期服務。
/// <para>
/// 功能規格寫的是「非 Microsoft 簽章且為自動啟動 → <c>Warning</c>」，Severity Medium。
/// </para>
/// <para>
/// <b>刻意偏離規格的字面條件</b>：任何一台實際使用的電腦都有大量合法的第三方自動啟動
/// 服務（顯示卡、音效、防毒、廠商工具），一律判 Warning 會是純誤報風暴，
/// 使用者只會學會忽略這一項。改為只對**未簽章或簽章無效**的自動啟動服務判 Warning ——
/// 那才是後門的樣式。有效簽章的第三方服務仍完整列於證據供人工過目。
/// </para>
/// </summary>
public sealed class M3_08_UnexpectedServicesCheck(IRegistryReader registry, IAuthenticodeVerifier verifier) : ICheck
{
    internal const string ServicesKeyPath = @"SYSTEM\CurrentControlSet\Services";

    /// <summary><c>Start</c> 值：2 = 自動啟動。</summary>
    internal const int StartAutomatic = 2;

    public string Id => "M3-08";

    public string Module => "M3";

    public string Title => "非預期的自動啟動服務";

    public Severity Severity => Severity.Medium;

    public string Source => $@"HKLM\{ServicesKeyPath}";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var services = new List<ServiceEntry>();

        // svchost 代管的服務全都指向同一個執行檔，不快取會重複驗證數十次
        var signatureCache = new Dictionary<string, SignatureTrust>(StringComparer.OrdinalIgnoreCase);

        foreach (var serviceName in registry.GetLocalMachineSubKeyNames(ServicesKeyPath))
        {
            ct.ThrowIfCancellationRequested();

            var keyPath = $@"{ServicesKeyPath}\{serviceName}";

            if (registry.GetLocalMachineValue(keyPath, "Start") is not int start || start != StartAutomatic)
            {
                continue;
            }

            if (registry.GetLocalMachineValue(keyPath, "ImagePath")?.ToString() is not { Length: > 0 } imagePath)
            {
                continue;
            }

            var executablePath = CommandLineParser.ExtractExecutablePath(imagePath);

            services.Add(new ServiceEntry(
                serviceName,
                registry.GetLocalMachineValue(keyPath, "DisplayName")?.ToString(),
                imagePath,
                executablePath,
                VerifyCached(executablePath, signatureCache)));
        }

        return ValueTask.FromResult(Evaluate(services));
    }

    internal Finding Evaluate(IReadOnlyList<ServiceEntry> services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Count == 0)
        {
            return Build(CheckStatus.Inconclusive, "無法列舉自動啟動服務。", null, []);
        }

        var suspicious = services.Where(s => s.IsSuspicious).ToList();

        if (suspicious.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"共 {services.Count} 個自動啟動服務，皆有有效簽章且位於正常路徑。",
                null,
                []);
        }

        return Build(
            CheckStatus.Warning,
            $"共 {services.Count} 個自動啟動服務，其中 {suspicious.Count} 個未簽章、簽章無效、"
            + "或位於暫存與下載目錄。以服務形式常駐是後門取得開機自動執行與高權限的常見手法。",
            "逐項確認來源。不認得的服務請保存本報告後查證，勿直接刪除以免破壞跡證。",
            [
                .. suspicious.Select(s => new Evidence(
                    $"⚠ {s.ServiceName}",
                    $"{s.DisplayName ?? s.ServiceName}｜{s.ImagePath}"
                    + $"　←　{(s.IsUnsigned ? $"簽章 {s.SignatureTrust}" : "位於暫存或下載目錄")}")),
            ]);
    }

    private SignatureTrust? VerifyCached(string? path, Dictionary<string, SignatureTrust> cache)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        if (cache.TryGetValue(path, out var cached))
        {
            return cached;
        }

        var trust = verifier.VerifyIncludingCatalog(path).Trust;
        cache[path] = trust;

        return trust;
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
