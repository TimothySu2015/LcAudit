using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>一筆開機自動啟動項目。</summary>
/// <param name="Location">來源位置描述，如 <c>HKLM\...\Run</c> 或「啟動資料夾」。</param>
/// <param name="Name">項目名稱。</param>
/// <param name="CommandLine">原始命令列。</param>
/// <param name="ExecutablePath">抽出的執行檔路徑；抽不出來為 <c>null</c>。</param>
/// <param name="SignatureTrust">簽章判定；未驗證為 <c>null</c>。</param>
public sealed record AutoStartEntry(
    string Location,
    string Name,
    string CommandLine,
    string? ExecutablePath,
    SignatureTrust? SignatureTrust)
{
    public bool IsUnsigned => SignatureTrust is not null and not Sources.SignatureTrust.Valid;

    public bool IsSuspiciousLocation => CommandLineParser.IsSuspiciousLocation(ExecutablePath);
}

/// <summary>
/// M3-06 開機自動啟動。
/// <para>
/// 功能規格：Run / RunOnce（HKLM + HKCU）與啟動資料夾中，
/// 未簽章或路徑位於 <c>%TEMP%</c>／<c>%APPDATA%</c> 者 → <c>Warning</c>。Severity High。
/// </para>
/// </summary>
public sealed class M3_06_AutoStartCheck(IRegistryReader registry, IAuthenticodeVerifier verifier) : ICheck
{
    internal static readonly IReadOnlyList<string> MachineRunKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    internal static readonly IReadOnlyList<string> UserRunKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public string Id => "M3-06";

    public string Module => "M3";

    public string Title => "開機自動啟動項目";

    public Severity Severity => Severity.High;

    public string Source => @"HKLM+HKCU\...\Run、RunOnce、啟動資料夾";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var entries = new List<AutoStartEntry>();

        // 同一個執行檔可能出現在多個位置，驗過的就別重複驗（WinVerifyTrust 不便宜）
        var signatureCache = new Dictionary<string, SignatureTrust>(StringComparer.OrdinalIgnoreCase);

        foreach (var keyPath in MachineRunKeys)
        {
            entries.AddRange(ReadRunKey($@"HKLM\{keyPath}", registry.GetLocalMachineValues(keyPath), signatureCache));
        }

        foreach (var keyPath in UserRunKeys)
        {
            entries.AddRange(ReadRunKey($@"HKCU\{keyPath}", registry.GetCurrentUserValues(keyPath), signatureCache));
        }

        entries.AddRange(ReadStartupFolders(signatureCache));

        return ValueTask.FromResult(Evaluate(entries));
    }

    internal Finding Evaluate(IReadOnlyList<AutoStartEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var suspicious = entries.Where(e => e.IsUnsigned || e.IsSuspiciousLocation).ToList();

        if (suspicious.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"共 {entries.Count} 個開機自動啟動項目，皆有有效簽章且位於正常路徑。",
                null,
                [.. entries.Select(ToEvidence)]);
        }

        var unsigned = suspicious.Count(e => e.IsUnsigned);
        var badLocation = suspicious.Count(e => e.IsSuspiciousLocation);

        var parts = new List<string>();
        if (unsigned > 0)
        {
            parts.Add($"{unsigned} 個未簽章或簽章無效");
        }

        if (badLocation > 0)
        {
            parts.Add($"{badLocation} 個位於暫存或使用者資料目錄");
        }

        return Build(
            CheckStatus.Warning,
            $"共 {entries.Count} 個開機自動啟動項目，其中 {string.Join("、", parts)}。"
            + "開機自動啟動是後門最典型的落腳處 —— 未簽章、又裝在 %TEMP% 或 %APPDATA% 的項目特別可疑。"
            + "（注意 Discord、Spotify 這類正規軟體也會裝在 %APPDATA%，需搭配簽章一起判斷。）",
            "逐項確認來源。不認得的、或未簽章又位於暫存目錄的，請保存本報告後移除。",
            [.. suspicious.Select(ToEvidence), .. entries.Except(suspicious).Select(ToEvidence)]);
    }

    private static Evidence ToEvidence(AutoStartEntry entry)
    {
        var flags = new List<string>();
        if (entry.IsUnsigned)
        {
            flags.Add($"簽章 {entry.SignatureTrust}");
        }

        if (entry.IsSuspiciousLocation)
        {
            flags.Add("位於暫存或使用者資料目錄");
        }

        var marker = flags.Count > 0 ? "⚠ " : string.Empty;

        return new Evidence(
            $"{marker}{entry.Location}｜{entry.Name}",
            entry.CommandLine + (flags.Count > 0 ? $"　←　{string.Join("、", flags)}" : string.Empty));
    }

    private IEnumerable<AutoStartEntry> ReadRunKey(
        string location,
        IReadOnlyDictionary<string, object?> values,
        Dictionary<string, SignatureTrust> cache)
    {
        foreach (var (name, value) in values)
        {
            if (value?.ToString() is not { Length: > 0 } commandLine)
            {
                continue;
            }

            var executablePath = CommandLineParser.ExtractExecutablePath(commandLine);

            yield return new AutoStartEntry(
                location, name, commandLine, executablePath, VerifyCached(executablePath, cache));
        }
    }

    private IEnumerable<AutoStartEntry> ReadStartupFolders(Dictionary<string, SignatureTrust> cache)
    {
        Environment.SpecialFolder[] folders = [Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup];

        foreach (var folder in folders)
        {
            var path = Environment.GetFolderPath(folder);
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(path))
            {
                // 捷徑不解析目標 —— 那需要 COM，且捷徑本身位於啟動資料夾就足以列出供人工判斷
                var isShortcut = Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase);

                yield return new AutoStartEntry(
                    folder == Environment.SpecialFolder.Startup ? "使用者啟動資料夾" : "全機啟動資料夾",
                    Path.GetFileName(file),
                    file,
                    isShortcut ? null : file,
                    isShortcut ? null : VerifyCached(file, cache));
            }
        }
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
