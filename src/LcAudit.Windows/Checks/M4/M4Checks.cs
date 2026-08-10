using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Validation;
using LcAudit.Windows.Interop;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M4;

/// <summary>連線加上其處理程序資訊。</summary>
/// <param name="Connection">原始連線。</param>
/// <param name="ProcessName">處理程序名稱；取不到為 <c>null</c>。</param>
/// <param name="ImagePath">執行檔路徑；權限不足或受保護程序為 <c>null</c>。</param>
/// <param name="SignatureTrust">簽章判定；未驗證為 <c>null</c>。</param>
public sealed record ConnectionWithProcess(
    TcpConnectionRow Connection,
    string? ProcessName,
    string? ImagePath,
    SignatureTrust? SignatureTrust)
{
    public bool IsUnsigned => SignatureTrust is not null and not Sources.SignatureTrust.Valid;

    public string Describe()
        => $"{ProcessName ?? "(未知)"} (PID {Connection.OwningProcessId})"
           + $" → {Connection.RemoteAddress}:{Connection.RemotePort}";
}

/// <summary>
/// M4 共用：把連線對應到處理程序。
/// <para>
/// <b>反作弊共存規則</b>：取執行檔路徑只用 <c>PROCESS_QUERY_LIMITED_INFORMATION</c>
/// （見 <see cref="IProcessInspector"/>），且一律跳過 <c>AuditContext.ProtectedPids</c>
/// 中的遊戲與反作弊程序 —— 對受保護程序開 handle 會踩線。
/// </para>
/// </summary>
internal static class ConnectionResolver
{
    internal static IReadOnlyList<ConnectionWithProcess> Resolve(
        IReadOnlyList<TcpConnectionRow> connections,
        IProcessInspector processes,
        IAuthenticodeVerifier verifier,
        IReadOnlySet<int> protectedPids,
        bool verifySignatures)
    {
        var namesByPid = processes.ListProcesses().ToDictionary(p => p.ProcessId, p => p.Name);
        var pathCache = new Dictionary<int, string?>();
        var signatureCache = new Dictionary<string, SignatureTrust>(StringComparer.OrdinalIgnoreCase);

        var results = new List<ConnectionWithProcess>(connections.Count);

        foreach (var connection in connections)
        {
            var pid = connection.OwningProcessId;
            namesByPid.TryGetValue(pid, out var name);

            string? imagePath = null;
            SignatureTrust? trust = null;

            // 受保護的遊戲／反作弊程序：只留名稱，絕不開 handle 取路徑
            if (!protectedPids.Contains(pid) && pid > 4)
            {
                if (!pathCache.TryGetValue(pid, out imagePath))
                {
                    imagePath = processes.TryGetImagePath(pid);
                    pathCache[pid] = imagePath;
                }

                if (verifySignatures && imagePath is not null)
                {
                    if (!signatureCache.TryGetValue(imagePath, out var cached))
                    {
                        cached = verifier.VerifyIncludingCatalog(imagePath).Trust;
                        signatureCache[imagePath] = cached;
                    }

                    trust = cached;
                }
            }

            results.Add(new ConnectionWithProcess(connection, name, imagePath, trust));
        }

        return results;
    }
}

/// <summary>
/// M4-01 紫P 相關處理程序連線。
/// <para>功能規格：列出遠端 IP / Port。Severity <b>Info</b>（0 分，不影響評分）。</para>
/// <para>遊戲關閉時本項必然無資料，判 <c>Inconclusive</c> —— 這是預期且無代價的。</para>
/// </summary>
public sealed class M4_01_PurpleConnectionsCheck(
    ITcpConnectionSource connections,
    IProcessInspector processes) : ICheck
{
    public string Id => "M4-01";

    public string Module => "M4";

    public string Title => "紫P 相關處理程序連線";

    public Severity Severity => Severity.Info;

    public string Source => "GetExtendedTcpTable (TCP_TABLE_OWNER_PID_ALL)";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        if (context.ProtectedPids.Count == 0)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "未偵測到紫P 或遊戲程序執行中，無連線可列出。"
                + "這是關閉遊戲後執行的正常結果，本項為 Info 級不影響評分。",
                []));
        }

        var rows = connections.GetConnections()
            .Where(c => context.ProtectedPids.Contains(c.OwningProcessId))
            .ToList();

        var namesByPid = processes.ListProcesses().ToDictionary(p => p.ProcessId, p => p.Name);

        return ValueTask.FromResult(Build(
            CheckStatus.Pass,
            $"紫P 或遊戲程序目前有 {rows.Count} 條 TCP 連線。",
            [
                .. rows.Take(50).Select(c => new Evidence(
                    $"{namesByPid.GetValueOrDefault(c.OwningProcessId, "(未知)")} (PID {c.OwningProcessId})",
                    $"{c.RemoteAddress}:{c.RemotePort}　狀態 {c.State}")),
            ]));
    }

    private Finding Build(CheckStatus status, string description, IReadOnlyList<Evidence> evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Evidence = evidence,
    };
}

/// <summary>
/// M4-02 監聽中的通訊埠。
/// <para>功能規格：存在遠端工具常用埠 → <c>Warning</c>。Severity Medium。</para>
/// <para>監聽代表「這台電腦在等別人連進來」，方向與 M4-04 相反。</para>
/// </summary>
public sealed class M4_02_ListeningPortsCheck(
    ITcpConnectionSource connections,
    IProcessInspector processes,
    IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M4-02";

    public string Module => "M4";

    public string Title => "監聽中的遠端存取通訊埠";

    public Severity Severity => Severity.Medium;

    public string Source => "GetExtendedTcpTable (State = LISTEN)";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var listening = connections.GetConnections()
            .Where(c => c.State == TcpState.Listen)
            .ToList();

        var resolved = ConnectionResolver.Resolve(
            listening, processes, verifier, context.ProtectedPids, verifySignatures: false);

        return ValueTask.FromResult(Evaluate(resolved));
    }

    internal Finding Evaluate(IReadOnlyList<ConnectionWithProcess> listening)
    {
        ArgumentNullException.ThrowIfNull(listening);

        var remoteAccess = listening
            .Where(c => RemoteAccessPorts.Describe(c.Connection.LocalPort) is not null)
            .ToList();

        if (remoteAccess.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"共 {listening.Count} 個監聽中的通訊埠，沒有遠端存取工具常用的埠。",
                []);
        }

        var services = string.Join("、", remoteAccess
            .Select(c => RemoteAccessPorts.Describe(c.Connection.LocalPort)!)
            .Distinct(StringComparer.Ordinal));

        return Build(
            CheckStatus.Warning,
            $"偵測到 {remoteAccess.Count} 個遠端存取工具常用的監聽埠（{services}）。"
            + "監聽代表這台電腦正在等待他人連入。",
            [
                .. remoteAccess.Select(c => new Evidence(
                    $"⚠ 埠 {c.Connection.LocalPort}（{RemoteAccessPorts.Describe(c.Connection.LocalPort)}）",
                    $"{c.ProcessName ?? "(未知)"} (PID {c.Connection.OwningProcessId})"
                    + $"　監聽於 {c.Connection.LocalAddress}")),
            ]);
    }

    private Finding Build(CheckStatus status, string description, IReadOnlyList<Evidence> evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Recommendation = status == CheckStatus.Warning
            ? "確認每個監聽埠對應的程式是你認可的。不需要的遠端存取功能請關閉。"
            : null,
        Evidence = evidence,
    };
}

/// <summary>
/// M4-03 未簽章處理程序的對外連線。
/// <para>功能規格：有 → <c>Warning</c>。Severity High。</para>
/// <para>
/// 遊戲執行中時仍照常執行，只跳過 <c>ProtectedPids</c> —— 這項要抓的是後門與竊資
/// 程式，與遊戲程序無關，不該整項放棄（見 CLAUDE.md 反作弊共存規則）。
/// </para>
/// </summary>
public sealed class M4_03_UnsignedOutboundCheck(
    ITcpConnectionSource connections,
    IProcessInspector processes,
    IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M4-03";

    public string Module => "M4";

    public string Title => "未簽章程序的對外連線";

    public Severity Severity => Severity.High;

    public string Source => "GetExtendedTcpTable + Authenticode 驗證";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var outbound = connections.GetConnections()
            .Where(c => c.State == TcpState.Established)
            .Where(c => PrivateAddressClassifier.Classify(c.RemoteAddress) == AddressScope.Public)
            .ToList();

        var resolved = ConnectionResolver.Resolve(
            outbound, processes, verifier, context.ProtectedPids, verifySignatures: true);

        return ValueTask.FromResult(Evaluate(resolved, context.ProtectedPids.Count > 0));
    }

    internal Finding Evaluate(IReadOnlyList<ConnectionWithProcess> outbound, bool gameRunning)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        var note = gameRunning
            ? "（已排除遊戲與反作弊程序，避免干擾其運作。）"
            : string.Empty;

        var unsigned = outbound.Where(c => c.IsUnsigned).ToList();

        if (unsigned.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"共 {outbound.Count} 條對外連線，發起連線的程式都有有效簽章。{note}",
                []);
        }

        var processCount = unsigned.Select(c => c.Connection.OwningProcessId).Distinct().Count();

        return Build(
            CheckStatus.Warning,
            $"有 {processCount} 個未簽章或簽章無效的程式正在對外連線（共 {unsigned.Count} 條）。"
            + $"竊資程式必須連回攻擊者才能把帳密送出去，這是它最藏不住的行為。{note}",
            [
                .. unsigned.GroupBy(c => c.Connection.OwningProcessId)
                           .Select(g => new Evidence(
                               $"⚠ {g.First().ProcessName ?? "(未知)"} (PID {g.Key})",
                               $"{g.First().ImagePath ?? "(路徑未知)"}"
                               + $"｜簽章 {g.First().SignatureTrust}"
                               + $"｜連線 {string.Join("、", g.Take(5).Select(c => $"{c.Connection.RemoteAddress}:{c.Connection.RemotePort}"))}")),
            ]);
    }

    private Finding Build(CheckStatus status, string description, IReadOnlyList<Evidence> evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Recommendation = status == CheckStatus.Warning
            ? "確認這些程式的來源。不認得的請保存本報告後斷網查證，勿直接刪除以免破壞跡證。"
            : null,
        Evidence = evidence,
    };
}

/// <summary>
/// M4-04 對外連線至已知遠端服務。
/// <para>
/// <b>刻意偏離規格</b>：規格寫的是「反查已知遠端服務**網域**，對照內建靜態清單」。
/// 但不做 DNS 就無法把 IP 反查成網域，而這類服務全部架在雲端、IP 段變動頻繁，
/// 內建 IP 清單無法負責任地維護 —— 給一份過期的清單只會製造「檢查過了」的假象。
/// </para>
/// <para>
/// 改為判定「對外連線的**目標埠**是否為已知遠端存取服務」，加上發起程序名稱比對。
/// 這是離線可靠判定的部分，方向與 M4-02（監聽）相反：這裡抓的是本機主動連出去
/// 向中繼伺服器報到 —— 正是 AnyDesk／TeamViewer 這類工具待機時的行為。
/// </para>
/// </summary>
public sealed class M4_04_KnownRemoteServiceCheck(
    ITcpConnectionSource connections,
    IProcessInspector processes,
    IAuthenticodeVerifier verifier) : ICheck
{
    public string Id => "M4-04";

    public string Module => "M4";

    public string Title => "對外連線至已知遠端服務";

    public Severity Severity => Severity.Medium;

    public string Source => "GetExtendedTcpTable（對外連線的目標埠與程序名稱比對）";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var outbound = connections.GetConnections()
            .Where(c => c.State == TcpState.Established)
            .Where(c => PrivateAddressClassifier.Classify(c.RemoteAddress) == AddressScope.Public)
            .ToList();

        var resolved = ConnectionResolver.Resolve(
            outbound, processes, verifier, context.ProtectedPids, verifySignatures: false);

        return ValueTask.FromResult(Evaluate(resolved));
    }

    internal Finding Evaluate(IReadOnlyList<ConnectionWithProcess> outbound)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        var knownToolNames = GameProcessDetector.KnownNames
            .Concat(Sources.RemoteTools.RemoteToolCatalog.All.Select(t => t.DisplayName))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var hits = outbound
            .Where(c => RemoteAccessPorts.Describe(c.Connection.RemotePort) is not null
                        || (c.ProcessName is not null && knownToolNames.Contains(c.ProcessName)))
            .ToList();

        if (hits.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"共 {outbound.Count} 條對外連線，沒有連向已知遠端存取服務的跡象。",
                []);
        }

        return Build(
            CheckStatus.Warning,
            $"有 {hits.Count} 條對外連線指向已知的遠端存取服務。"
            + "遠端工具待機時會主動連向中繼伺服器報到 —— 這代表該工具正在執行且隨時可被連入。",
            [
                .. hits.Take(30).Select(c => new Evidence(
                    $"⚠ {c.ProcessName ?? "(未知)"} (PID {c.Connection.OwningProcessId})",
                    $"→ {c.Connection.RemoteAddress}:{c.Connection.RemotePort}"
                    + (RemoteAccessPorts.Describe(c.Connection.RemotePort) is { } svc ? $"（{svc}）" : string.Empty))),
            ]);
    }

    private Finding Build(CheckStatus status, string description, IReadOnlyList<Evidence> evidence) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = status,
        Source = Source,
        Description = description,
        Recommendation = status == CheckStatus.Warning
            ? "確認這些遠端工具是你自己安裝並仍在使用的。不需要的請移除。"
            : null,
        Evidence = evidence,
    };
}
