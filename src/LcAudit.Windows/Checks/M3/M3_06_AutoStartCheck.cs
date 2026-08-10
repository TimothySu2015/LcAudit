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
    /// <summary>
    /// 確定沒有有效簽章。
    /// <para>
    /// <c>Unknown</c>（未列於對照表的 HRESULT）、<c>SecuritySettings</c>（政策阻擋）、
    /// <c>FileNotReadable</c> 代表「**驗不出來**」而非「沒簽章」，不可算進來。
    /// <c>Expired</c> 也不算 —— Azure Trusted Signing 的憑證只有幾天效期，
    /// 「憑證過期但簽章有效」是常態。
    /// </para>
    /// </summary>
    public bool IsUnsigned => SignatureTrust is Sources.SignatureTrust.NoSignature
                                             or Sources.SignatureTrust.BadDigest
                                             or Sources.SignatureTrust.ExplicitDistrust
                                             or Sources.SignatureTrust.SubjectNotTrusted
                                             or Sources.SignatureTrust.ChainIncomplete;

    /// <summary>位於 %TEMP% 或下載資料夾 —— 常駐程式在這裡沒有正當理由。</summary>
    public bool IsSuspiciousLocation => CommandLineParser.IsSuspiciousLocation(ExecutablePath);

    /// <summary>位於使用者可寫入的位置。單獨出現不構成可疑，僅供人工過目。</summary>
    public bool IsUserWritable => CommandLineParser.IsUserWritableLocation(ExecutablePath);

    /// <summary>是否需要標記。未簽章、或位於高風險位置才算。</summary>
    public bool IsSuspicious => IsUnsigned || IsSuspiciousLocation;
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

    /// <summary>啟動資料夾中真正會被執行的副檔名。</summary>
    internal static readonly IReadOnlySet<string> StartupExtensions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".lnk", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", ".ps1", ".url",
        };

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

        var suspicious = entries.Where(e => e.IsSuspicious).ToList();

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
            parts.Add($"{badLocation} 個位於暫存或下載目錄");
        }

        return Build(
            CheckStatus.Warning,
            $"共 {entries.Count} 個開機自動啟動項目，其中 {string.Join("、", parts)}。"
            + "開機自動啟動是後門最典型的落腳處。",
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
            flags.Add("位於暫存或下載目錄");
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
                // desktop.ini 是資料夾外觀設定檔，不會被執行 —— 每個啟動資料夾都有一份，
                // 不排除的話每台機器都會多兩個假的「可疑啟動項」。
                if (!StartupExtensions.Contains(Path.GetExtension(file)))
                {
                    continue;
                }

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
