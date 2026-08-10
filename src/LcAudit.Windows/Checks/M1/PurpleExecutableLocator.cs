namespace LcAudit.Windows.Checks.M1;

/// <summary>
/// 在紫P 安裝目錄中找出主程式。
/// <para>
/// 候選檔名清單是暫定的 —— 實際檔名需以真實安裝環境確認（見 CLAUDE.md「仍待定案」）。
/// 找不到時回 <c>null</c>，由呼叫端判為 Inconclusive，不可自行猜一個路徑去驗。
/// </para>
/// </summary>
internal static class PurpleExecutableLocator
{
    /// <summary>依優先序排列的主程式候選檔名。</summary>
    internal static readonly IReadOnlyList<string> CandidateNames =
    [
        "Purple.exe",
        "PurpleLauncher.exe",
        "NCLauncher.exe",
        "NCLauncherU.exe",
    ];

    internal static string? FindMainExecutable(string? installPath)
    {
        if (string.IsNullOrWhiteSpace(installPath) || !Directory.Exists(installPath))
        {
            return null;
        }

        foreach (var name in CandidateNames)
        {
            var candidate = Path.Combine(installPath, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
