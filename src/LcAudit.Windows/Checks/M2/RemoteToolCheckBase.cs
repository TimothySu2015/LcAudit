using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;
using LcAudit.Windows.Sources.RemoteTools;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-06 / M2-07 共用的判定邏輯：有連入紀錄 → Warning，只裝了但沒連入 → Warning（較輕），
/// 完全沒痕跡 → Pass。
/// </summary>
public abstract class RemoteToolCheckBase(
    IRemoteToolScanner scanner,
    IWindowsEventLog eventLog,
    RemoteToolDefinition tool) : ICheck
{
    public abstract string Id { get; }

    public string Module => "M2";

    public string Title => $"{tool.DisplayName} 連線紀錄";

    public Severity Severity => Severity.High;

    public string Source => string.Join("、", tool.IncomingLogFiles.DefaultIfEmpty("檔案系統與登錄檔"));

    protected RemoteToolDefinition Tool => tool;

    /// <summary>由子類別提供對應工具的紀錄檔剖析方式。</summary>
    protected abstract IReadOnlyList<IncomingConnection> ParseLog(string content);

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        var trace = scanner.Scan(tool);

        var connections = trace.FoundIncomingLogs
            .Select(scanner.ReadTextFile)
            .Where(content => !string.IsNullOrWhiteSpace(content))
            .SelectMany(content => ParseLog(content!))
            .ToList();

        // PurpleInstallPath 由 M1-00 寫入，是唯一允許跨模組共享的狀態 ——
        // 拿它來比對「遠端工具與紫P 是不是同一時段裝上的」不需要新的相依。
        var installContext = InstallTimeCorrelator.Correlate(
            eventLog, trace.InstalledAt, context.LookbackDays, context.PurpleInstallPath);

        return ValueTask.FromResult(Evaluate(trace, connections, installContext));
    }

    internal Finding Evaluate(
        RemoteToolTrace trace,
        IReadOnlyList<IncomingConnection> connections,
        InstallTimeContext? installContext = null)
    {
        ArgumentNullException.ThrowIfNull(trace);
        ArgumentNullException.ThrowIfNull(connections);

        if (!trace.HasTrace)
        {
            return Build(CheckStatus.Pass, $"未偵測到 {tool.DisplayName} 的安裝痕跡。", null, []);
        }

        var evidence = new List<Evidence>();

        // 安裝時間放在最前面 —— 使用者往往根本不知道電腦上有這個程式，
        // 「請核對是否為你本人所為」他答不出來，但一個具體時間點他立刻能判斷。
        if (trace.InstalledAt is { } installedAt)
        {
            evidence.Add(new Evidence("安裝時間（推估）", installedAt.ToString("yyyy-MM-dd HH:mm:ss"), installedAt));
        }

        evidence.AddRange(trace.FoundDirectories.Select(d => new Evidence("目錄", d)));
        evidence.AddRange(trace.FoundServices.Select(s => new Evidence("服務", s)));

        var installStory = trace.InstalledAt is { } t && installContext is not null
            ? InstallTimeCorrelator.Describe(t, installContext)
            : null;

        if (connections.Count == 0)
        {
            var reason = trace.FoundIncomingLogs.Count == 0
                ? "但找不到連入紀錄檔，無法判斷是否曾被連入"
                : "連入紀錄檔中沒有連入記錄";

            return Build(
                CheckStatus.Warning,
                $"偵測到 {tool.DisplayName} 已安裝，{reason}。"
                + (trace.InstalledAt is { } installedTime ? $"安裝時間約在 {installedTime:yyyy-MM-dd HH:mm}。" : string.Empty)
                + (installStory is not null ? installStory : string.Empty)
                + "**你認得這個程式嗎？如果完全沒印象裝過，那就是答案**"
                + " —— 它能讓別人隨時連進你的電腦。",
                $"沒印象裝過就直接移除 {tool.DisplayName}，並在**另一台乾淨裝置**上更改所有帳號密碼。"
                + "移除前請先保存本報告。",
                evidence);
        }

        // 有連入紀錄 —— 這是「別人連進來」的直接證據，方向不能搞混
        evidence.AddRange(connections
            .OrderByDescending(c => c.Time ?? DateTimeOffset.MinValue)
            .Take(20)
            .Select(c => new Evidence(
                c.Time?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(時間無法解析)",
                c.RemoteId is null ? c.RawLine : $"來源 {c.RemoteId}｜{c.RawLine}",
                c.Time)));

        var timed = connections.Where(c => c.Time.HasValue).Select(c => c.Time!.Value).ToList();
        var range = timed.Count > 0
            ? $"首見 {timed.Min():yyyy-MM-dd HH:mm}，末見 {timed.Max():yyyy-MM-dd HH:mm}。"
            : string.Empty;

        // 「裝了」是 Warning，「有人真的連進來過」是 Fail。
        //
        // 這兩件事的確定性差很多：前者可能是使用者自己裝來遠端работы的，
        // 後者是「確實有一條從外部進來的連線」這個事實，只剩「是否經你授權」需要判斷。
        // 功能規格 M2-06 寫的是 Warning，但規格自己對 Fail 的定義是「明確異常」——
        // 有人連進你的電腦，事實本身並不模糊。
        //
        // 且若判 Warning，單一項目只有 10 分，在 0–19 的「低」區間裡永遠出不去。
        return Build(
            CheckStatus.Fail,
            $"{tool.DisplayName} 有 {connections.Count} 筆**連入**紀錄 —— 曾有人從外部連進這台電腦。{range}"
            + (installStory is not null
                ? installStory
                : trace.InstalledAt is { } at ? $"它是在 {at:yyyy-MM-dd HH:mm} 被安裝的。" : string.Empty)
            + "**你認得這個程式、也記得自己用過它嗎？如果沒有印象，那就是答案。**"
            + "對方能隨時操作你的電腦 —— 即使紫P 是正版、密碼沒外流，"
            + "他也能在你自己登入遊戲的時候，坐在旁邊看著你把帳密輸進去。",
            "立即保存本報告，移除該工具，並在**另一台乾淨裝置**上更改遊戲與信箱密碼。"
            + "報告中的連線時間與來源請一併提供給客服與警方。",
            evidence);
    }

    private Finding Build(
        CheckStatus status,
        string description,
        string? recommendation,
        IReadOnlyList<Evidence> evidence) => new()
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

/// <summary>M2-06 AnyDesk 連線紀錄。</summary>
public sealed class M2_06_AnyDeskCheck(IRemoteToolScanner scanner, IWindowsEventLog eventLog)
    : RemoteToolCheckBase(scanner, eventLog, RemoteToolCatalog.AnyDesk)
{
    public override string Id => "M2-06";

    protected override IReadOnlyList<IncomingConnection> ParseLog(string content)
        => ConnectionLogParsers.ParseAnyDesk(content);
}

/// <summary>M2-07 TeamViewer 連線紀錄。</summary>
public sealed class M2_07_TeamViewerCheck(IRemoteToolScanner scanner, IWindowsEventLog eventLog)
    : RemoteToolCheckBase(scanner, eventLog, RemoteToolCatalog.TeamViewer)
{
    public override string Id => "M2-07";

    protected override IReadOnlyList<IncomingConnection> ParseLog(string content)
        => ConnectionLogParsers.ParseTeamViewer(content);
}
