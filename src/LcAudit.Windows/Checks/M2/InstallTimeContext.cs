using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>安裝時間點的周邊情境。</summary>
/// <param name="RemoteSessionsNearby">安裝時間前後出現的遠端工作階段事件數。</param>
/// <param name="NearestRemoteSession">距離安裝時間最近的遠端工作階段。</param>
/// <param name="ScreenWasLocked">安裝當下螢幕是否處於鎖定狀態；無法判斷為 <c>null</c>。</param>
/// <param name="PurpleInstalledAt">
/// 紫P 的安裝時間。
/// <para>
/// 若遠端工具與紫P 在同一時段被裝上，那通常不是巧合而是同一次事件 ——
/// 受害者被誘導安裝遠端工具「協助處理」，對方接手後順道換掉紫P，
/// 或反過來：對方連進來之後才安裝遠端工具好長期留守。
/// </para>
/// </param>
public sealed record InstallTimeContext(
    int RemoteSessionsNearby,
    DateTimeOffset? NearestRemoteSession,
    bool? ScreenWasLocked,
    DateTimeOffset? PurpleInstalledAt = null)
{
    /// <summary>有任何一項可以佐證「不是本人裝的」。</summary>
    public bool HasEvidence => RemoteSessionsNearby > 0 || ScreenWasLocked == true;
}

/// <summary>
/// 回答「這個程式是什麼時候、在什麼情況下被裝上去的」。
/// <para>
/// <b>使用者往往根本不知道電腦上有這個遠端程式</b>，所以「請核對是否為你本人所為」
/// 這種問法他答不出來。但如果工具能說出「它是在你螢幕鎖定期間、而且當時正好有人
/// 從 1.2.3.4 遠端連著的時候裝上去的」，那就不需要他回想任何事情。
/// </para>
/// <para>
/// 兩份資料我們本來就都有 —— 終端服務工作階段（M2-04）與螢幕鎖定時間軸（M2-10），
/// 只是先前沒拿來交叉比對。
/// </para>
/// </summary>
internal static class InstallTimeCorrelator
{
    /// <summary>「安裝當下」的容許誤差。目錄建立時間與實際安裝完成會有落差。</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromHours(2);

    /// <summary>「同一時段安裝」的認定範圍。</summary>
    internal static readonly TimeSpan SameSessionWindow = TimeSpan.FromHours(24);

    internal static InstallTimeContext? Correlate(
        IWindowsEventLog eventLog,
        DateTimeOffset? installedAt,
        int lookbackDays,
        string? purpleInstallPath = null)
    {
        ArgumentNullException.ThrowIfNull(eventLog);

        if (installedAt is not { } installTime)
        {
            return null;
        }

        var sessions = QuerySessions(eventLog, lookbackDays);
        var nearby = sessions
            .Where(t => (t - installTime).Duration() <= Window)
            .OrderBy(t => (t - installTime).Duration())
            .ToList();

        return new InstallTimeContext(
            nearby.Count,
            nearby.Count > 0 ? nearby[0] : null,
            WasScreenLocked(eventLog, installTime, lookbackDays),
            EstimatePurpleInstallTime(purpleInstallPath));
    }

    /// <summary>
    /// 推估紫P 的安裝時間 —— 優先取主程式的建立時間，取不到則退回安裝目錄。
    /// <para>
    /// <c>PurpleInstallPath</c> 是本工具唯一允許跨模組共享的狀態（由 M1-00 寫入），
    /// 所以這裡不需要引入新的相依就能拿到。
    /// </para>
    /// </summary>
    internal static DateTimeOffset? EstimatePurpleInstallTime(string? purpleInstallPath)
    {
        if (string.IsNullOrWhiteSpace(purpleInstallPath) || !Directory.Exists(purpleInstallPath))
        {
            return null;
        }

        try
        {
            var executable = M1.PurpleExecutableLocator.FindMainExecutable(purpleInstallPath);

            return new DateTimeOffset(executable is not null
                ? File.GetCreationTime(executable)
                : Directory.GetCreationTime(purpleInstallPath));
        }
        catch (SystemException)
        {
            return null;
        }
    }

    private static IReadOnlyList<DateTimeOffset> QuerySessions(IWindowsEventLog eventLog, int lookbackDays)
    {
        // 這個記錄檔不需提權即可讀取，未提權時仍能完成比對
        if (!eventLog.LogExists(M2_04_TerminalServicesSessionCheck.LogName))
        {
            return [];
        }

        return
        [
            .. eventLog.Query(
                M2_04_TerminalServicesSessionCheck.LogName,
                EventQueries.ByEventIds(M2_04_TerminalServicesSessionCheck.SessionEventIds, lookbackDays),
                [],
                WindowsEventLog.DefaultMaxEvents)
            .Select(r => r.TimeCreated),
        ];
    }

    /// <summary>
    /// 安裝當下螢幕是否鎖定 —— 取安裝時間之前最近的一筆 4800(鎖定)/4801(解鎖)。
    /// <para>讀 Security 記錄需提權，未提權時回 <c>null</c> 而非誤判。</para>
    /// </summary>
    private static bool? WasScreenLocked(IWindowsEventLog eventLog, DateTimeOffset installTime, int lookbackDays)
    {
        try
        {
            var events = eventLog.Query(
                EventQueries.SecurityLog,
                EventQueries.ByEventIds(
                    [EventQueries.EventIdWorkstationLocked, EventQueries.EventIdWorkstationUnlocked],
                    lookbackDays),
                [],
                WindowsEventLog.DefaultMaxEvents);

            var previous = events
                .Where(e => e.TimeCreated <= installTime)
                .OrderByDescending(e => e.TimeCreated)
                .FirstOrDefault();

            return previous is null ? null : previous.EventId == EventQueries.EventIdWorkstationLocked;
        }
        catch (UnauthorizedAccessException)
        {
            // 未提權讀不到 Security 記錄。這是預期情況，不該讓整個檢查變成 Inconclusive ——
            // 安裝時間本身與遠端工作階段的比對仍然有效。
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>組出給使用者看的說明。沒有任何可說的時回 <c>null</c>。</summary>
    internal static string? Describe(DateTimeOffset installedAt, InstallTimeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var sentences = new List<string>();

        if (context.HasEvidence)
        {
            var parts = new List<string>();

            if (context.ScreenWasLocked == true)
            {
                parts.Add("**當時你的螢幕是鎖定的**");
            }

            if (context.RemoteSessionsNearby > 0)
            {
                parts.Add($"**當時前後 {Window.TotalHours:0} 小時內有 {context.RemoteSessionsNearby} 筆遠端連線事件**"
                          + (context.NearestRemoteSession is { } nearest
                              ? $"（最接近的一筆在 {nearest:yyyy-MM-dd HH:mm}）"
                              : string.Empty));
            }

            sentences.Add($"它是在 {installedAt:yyyy-MM-dd HH:mm} 被安裝的，{string.Join("，且", parts)}"
                          + " —— 這代表安裝很可能不是你本人在電腦前操作的。");
        }

        if (DescribePurpleProximity(installedAt, context) is { } proximity)
        {
            sentences.Add(proximity);
        }

        return sentences.Count > 0 ? string.Concat(sentences) : null;
    }

    /// <summary>
    /// 與紫P 安裝時間的距離。
    /// <para>
    /// 兩者若在同一時段裝上，通常是同一次事件而非巧合 —— 受害者被誘導安裝遠端工具
    /// 「協助處理」，對方接手後順道換掉紫P；或反過來，對方連進來之後才裝遠端工具留守。
    /// </para>
    /// </summary>
    private static string? DescribePurpleProximity(DateTimeOffset installedAt, InstallTimeContext context)
    {
        if (context.PurpleInstalledAt is not { } purpleTime)
        {
            return null;
        }

        var gap = (installedAt - purpleTime).Duration();

        // 先後順序有意義：先裝遠端工具再換紫P，是「被誘導安裝後由對方接手」的典型順序
        var order = installedAt >= purpleTime
            ? "先裝紫P，再裝這個遠端工具"
            : "先裝這個遠端工具，再裝紫P";

        if (gap > SameSessionWindow)
        {
            // 相隔很久仍然值得說 —— 使用者可以據此判斷哪一個才是異常的那次
            return $"（紫P 是在 {purpleTime:yyyy-MM-dd HH:mm} 安裝的，兩者相隔約 {gap.TotalDays:0} 天。）";
        }

        var gapText = gap.TotalHours < 1
            ? $"{gap.TotalMinutes:0} 分鐘"
            : $"{gap.TotalHours:0.#} 小時";

        return $"**它與紫P 幾乎是同一時段裝上的** —— 紫P 安裝於 {purpleTime:yyyy-MM-dd HH:mm}，"
               + $"兩者只差 {gapText}（順序是{order}）。"
               + "同一時段出現這兩件事通常不是巧合，而是同一次入侵過程的兩個步驟。";
    }
}
