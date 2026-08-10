namespace LcAudit.Windows.Sources;

/// <summary>
/// Pre-flight：偵測遊戲與反作弊程序是否執行中。
/// <para>
/// 只比對處理程序名稱，不開任何 handle。比對出的 PID 存入
/// <c>AuditContext.ProtectedPids</c>，M4-03 必須排除它們。
/// </para>
/// </summary>
public static class GameProcessDetector
{
    /// <summary>
    /// 遊戲與反作弊的處理程序名稱（不分大小寫，不含副檔名）。
    /// <para>暫定清單，需以實機確認補完（見 CLAUDE.md「仍待定案」）。</para>
    /// </summary>
    public static readonly IReadOnlyList<string> KnownNames =
    [
        // 紫P 與遊戲本體
        "Purple",
        "PurpleLauncher",
        "NCLauncher",
        "NCLauncherU",
        "Lineage",
        "LineageClassic",

        // nProtect GameGuard
        "GameMon",
        "GameGuard",
        "npggNT",

        // XIGNCODE
        "xhunter1",
        "XIGNCODE",
    ];

    /// <summary>回傳執行中的遊戲／反作弊程序 PID 集合。空集合代表可安全執行全部檢查。</summary>
    public static IReadOnlySet<int> DetectProtectedPids(IProcessInspector inspector)
    {
        ArgumentNullException.ThrowIfNull(inspector);

        var known = KnownNames.ToHashSet(StringComparer.OrdinalIgnoreCase);

        return inspector.ListProcesses()
                        .Where(p => known.Contains(p.Name))
                        .Select(p => p.ProcessId)
                        .ToHashSet();
    }
}
