using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>
/// M3-01 RDP 服務是否啟用。
/// <para>功能規格：<c>fDenyTSConnections = 0</c>（已啟用）→ <c>Warning</c>。Severity High。</para>
/// </summary>
public sealed class M3_01_RdpEnabledCheck(IRegistryReader registry) : ICheck
{
    internal const string KeyPath = @"System\CurrentControlSet\Control\Terminal Server";
    internal const string ValueName = "fDenyTSConnections";

    public string Id => "M3-01";

    public string Module => "M3";

    public string Title => "遠端桌面是否啟用";

    public Severity Severity => Severity.High;

    public string Source => $@"HKLM\{KeyPath}\{ValueName}";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(registry.GetLocalMachineValue(KeyPath, ValueName)));
    }

    internal Finding Evaluate(object? rawValue)
    {
        if (rawValue is not int denyConnections)
        {
            return Build(CheckStatus.Inconclusive, "讀不到遠端桌面設定值。", null, []);
        }

        var evidence = new Evidence[] { new(ValueName, denyConnections.ToString()) };

        // 0 = 不拒絕連線 = 遠端桌面已啟用
        return denyConnections == 0
            ? Build(
                CheckStatus.Warning,
                "遠端桌面功能目前為**啟用**狀態，其他電腦可以連進這台主機。"
                + "家用電腦通常不需要開啟這個功能。",
                "若沒有遠端使用需求，建議關閉：設定 → 系統 → 遠端桌面 → 關閉。",
                evidence)
            : Build(CheckStatus.Pass, "遠端桌面功能為停用狀態。", null, evidence);
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

/// <summary>
/// M3-02 RDP 通訊埠是否被改。
/// <para>功能規格：≠ 3389 → <c>Fail</c>。Severity High。</para>
/// <para>
/// 改埠號本身是常見的「安全強化」做法，但攻擊者也會改埠來規避偵測與防火牆規則。
/// 規格判 Fail，這裡照辦，但說明文字要讓使用者能自行判斷是哪一種。
/// </para>
/// </summary>
public sealed class M3_02_RdpPortCheck(IRegistryReader registry) : ICheck
{
    internal const string KeyPath = @"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    internal const string ValueName = "PortNumber";
    internal const int DefaultPort = 3389;

    public string Id => "M3-02";

    public string Module => "M3";

    public string Title => "遠端桌面通訊埠";

    public Severity Severity => Severity.High;

    public string Source => $@"HKLM\{KeyPath}\{ValueName}";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(registry.GetLocalMachineValue(KeyPath, ValueName)));
    }

    internal Finding Evaluate(object? rawValue)
    {
        if (rawValue is not int port)
        {
            return Build(CheckStatus.Inconclusive, "讀不到遠端桌面通訊埠設定。", null, []);
        }

        var evidence = new Evidence[] { new(ValueName, port.ToString()) };

        return port == DefaultPort
            ? Build(CheckStatus.Pass, $"遠端桌面使用預設通訊埠 {DefaultPort}。", null, evidence)
            : Build(
                CheckStatus.Fail,
                $"遠端桌面通訊埠已被改為 {port}（預設為 {DefaultPort}）。"
                + "改埠可能是為了規避偵測與防火牆規則，也可能是你或 IT 人員刻意的安全設定。",
                "若不是你或公司 IT 改的，視同入侵跡證處理，保存本報告後檢查其他持久化項目。",
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
