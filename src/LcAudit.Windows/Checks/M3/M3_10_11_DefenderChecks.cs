using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>
/// M3-10 Defender 排除清單。
/// <para>功能規格：存在排除路徑 → <c>Warning</c>（惡意程式常見手法）。Severity High。</para>
/// <para>
/// 排除清單是惡意程式落地後的標準動作 —— 把自己的目錄加進排除，Defender 就不再掃它。
/// 與 M3-11 同時命中會觸發推論引擎的 R2 規則（防毒遭主動停用）。
/// </para>
/// <para>
/// <b>讀取排除清單需要系統管理員權限</b>（該登錄檔鍵有 ACL 保護），未提權會判 Inconclusive。
/// </para>
/// </summary>
public sealed class M3_10_DefenderExclusionsCheck(IRegistryReader registry) : ICheck
{
    internal const string ExclusionsKeyRoot = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";

    /// <summary>排除類型：路徑、副檔名、處理程序。</summary>
    internal static readonly IReadOnlyList<string> ExclusionKinds = ["Paths", "Extensions", "Processes"];

    public string Id => "M3-10";

    public string Module => "M3";

    public string Title => "Defender 排除清單";

    public Severity Severity => Severity.High;

    public string Source => $@"HKLM\{ExclusionsKeyRoot}";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        if (!context.IsElevated)
        {
            return ValueTask.FromResult(Build(
                CheckStatus.Inconclusive,
                "讀取 Defender 排除清單需要系統管理員權限。",
                "請以系統管理員身分重新執行。",
                []));
        }

        var exclusions = ExclusionKinds
            .SelectMany(kind => registry
                .GetLocalMachineValues($@"{ExclusionsKeyRoot}\{kind}")
                .Keys
                .Select(value => (Kind: kind, Value: value)))
            .ToList();

        return ValueTask.FromResult(Evaluate(exclusions));
    }

    internal Finding Evaluate(IReadOnlyList<(string Kind, string Value)> exclusions)
    {
        ArgumentNullException.ThrowIfNull(exclusions);

        if (exclusions.Count == 0)
        {
            return Build(CheckStatus.Pass, "Defender 沒有任何排除項目。", null, []);
        }

        return Build(
            CheckStatus.Warning,
            $"Defender 有 {exclusions.Count} 個排除項目。"
            + "被排除的路徑、副檔名或處理程序不會被掃描 —— 惡意程式落地後常做的第一件事就是把自己加進排除清單。",
            "逐項確認是否為你或防毒軟體自行設定。不認得的請移除排除並執行完整掃描。",
            [.. exclusions.Select(e => new Evidence($"排除{TranslateKind(e.Kind)}", e.Value))]);
    }

    private static string TranslateKind(string kind) => kind switch
    {
        "Paths" => "路徑",
        "Extensions" => "副檔名",
        "Processes" => "處理程序",
        _ => kind,
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
/// M3-11 Defender 保護狀態。
/// <para>功能規格：即時防護關閉 → <c>Fail</c>。Severity High。</para>
/// <para>
/// 讀登錄檔而非 WMI —— 免去 <c>System.Management</c> 相依，也避開它的 AOT 相容性問題。
/// 注意「有第三方防毒」與「防護被惡意關閉」在登錄檔上看起來一樣，文案必須讓使用者能區分。
/// </para>
/// </summary>
public sealed class M3_11_DefenderStatusCheck(IRegistryReader registry) : ICheck
{
    internal const string RealTimeKeyPath = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    internal const string PolicyKeyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender";

    public string Id => "M3-11";

    public string Module => "M3";

    public string Title => "Defender 即時防護狀態";

    public Severity Severity => Severity.High;

    public string Source => $@"HKLM\{RealTimeKeyPath}、HKLM\{PolicyKeyPath}";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(
            registry.GetLocalMachineValue(RealTimeKeyPath, "DisableRealtimeMonitoring") as int?,
            registry.GetLocalMachineValue(PolicyKeyPath, "DisableAntiSpyware") as int?));
    }

    internal Finding Evaluate(int? disableRealtimeMonitoring, int? disableAntiSpyware)
    {
        var evidence = new List<Evidence>
        {
            new("DisableRealtimeMonitoring", disableRealtimeMonitoring?.ToString() ?? "(未設定)"),
            new("DisableAntiSpyware", disableAntiSpyware?.ToString() ?? "(未設定)"),
        };

        var realtimeDisabled = disableRealtimeMonitoring == 1;
        var antiSpywareDisabled = disableAntiSpyware == 1;

        if (!realtimeDisabled && !antiSpywareDisabled)
        {
            return Build(CheckStatus.Pass, "Defender 即時防護未被關閉。", null, evidence);
        }

        var what = realtimeDisabled && antiSpywareDisabled
            ? "即時防護與 Defender 本身"
            : realtimeDisabled ? "即時防護" : "Defender 本身";

        return Build(
            CheckStatus.Fail,
            $"Defender 的{what}已被關閉。"
            + "若你有安裝第三方防毒軟體，這是正常的（安裝時會自動停用 Defender）；"
            + "若沒有，代表防護被人為關閉 —— 這是惡意程式落地後的典型動作。",
            "確認是否安裝了其他防毒軟體。若沒有，立即重新啟用 Defender 並執行完整掃描。",
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
