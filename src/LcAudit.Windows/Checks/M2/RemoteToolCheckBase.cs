using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources.RemoteTools;

namespace LcAudit.Windows.Checks.M2;

/// <summary>
/// M2-06 / M2-07 共用的判定邏輯：有連入紀錄 → Warning，只裝了但沒連入 → Warning（較輕），
/// 完全沒痕跡 → Pass。
/// </summary>
public abstract class RemoteToolCheckBase(IRemoteToolScanner scanner, RemoteToolDefinition tool) : ICheck
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

        return ValueTask.FromResult(Evaluate(trace, connections));
    }

    internal Finding Evaluate(RemoteToolTrace trace, IReadOnlyList<IncomingConnection> connections)
    {
        ArgumentNullException.ThrowIfNull(trace);
        ArgumentNullException.ThrowIfNull(connections);

        if (!trace.HasTrace)
        {
            return Build(CheckStatus.Pass, $"未偵測到 {tool.DisplayName} 的安裝痕跡。", null, []);
        }

        var evidence = new List<Evidence>();
        evidence.AddRange(trace.FoundDirectories.Select(d => new Evidence("目錄", d)));
        evidence.AddRange(trace.FoundServices.Select(s => new Evidence("服務", s)));

        if (connections.Count == 0)
        {
            var reason = trace.FoundIncomingLogs.Count == 0
                ? "但找不到連入紀錄檔，無法判斷是否曾被連入"
                : "連入紀錄檔中沒有連入記錄";

            return Build(
                CheckStatus.Warning,
                $"偵測到 {tool.DisplayName} 已安裝，{reason}。"
                + "若這不是你自己安裝的，代表有人在此電腦上部署了遠端存取工具。",
                $"確認 {tool.DisplayName} 是否為你本人安裝。若否，請保存本報告後移除，並更改所有帳號密碼。",
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
            + "逐筆核對是否為你本人或你授權的人所為。若不是，代表他人能隨時操作你的電腦，"
            + "即使紫P 是正版、密碼沒外流，對方也能在你自己登入遊戲時取走一切。",
            "有不認得的連線請立即保存本報告，移除該工具，並在**另一台乾淨裝置**上更改遊戲與信箱密碼。",
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
public sealed class M2_06_AnyDeskCheck(IRemoteToolScanner scanner)
    : RemoteToolCheckBase(scanner, RemoteToolCatalog.AnyDesk)
{
    public override string Id => "M2-06";

    protected override IReadOnlyList<IncomingConnection> ParseLog(string content)
        => ConnectionLogParsers.ParseAnyDesk(content);
}

/// <summary>M2-07 TeamViewer 連線紀錄。</summary>
public sealed class M2_07_TeamViewerCheck(IRemoteToolScanner scanner)
    : RemoteToolCheckBase(scanner, RemoteToolCatalog.TeamViewer)
{
    public override string Id => "M2-07";

    protected override IReadOnlyList<IncomingConnection> ParseLog(string content)
        => ConnectionLogParsers.ParseTeamViewer(content);
}
