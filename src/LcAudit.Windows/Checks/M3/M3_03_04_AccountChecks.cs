using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>
/// M3-03 遠端桌面使用者群組。
/// <para>功能規格：非預期成員 → <c>Warning</c>。Severity High。</para>
/// <para>
/// 注意：系統管理員本來就能遠端登入而不需列在此群組，所以這個群組是空的很正常 ——
/// 有成員才需要留意。
/// </para>
/// </summary>
public sealed class M3_03_RemoteDesktopUsersCheck(ILocalAccountSource accounts) : ICheck
{
    public string Id => "M3-03";

    public string Module => "M3";

    public string Title => "遠端桌面使用者群組";

    public Severity Severity => Severity.High;

    public string Source => "本機群組 S-1-5-32-555（Remote Desktop Users）";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(accounts.GetRemoteDesktopUsers()));
    }

    internal Finding Evaluate(IReadOnlyList<GroupMember> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        if (members.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                "遠端桌面使用者群組沒有成員。（系統管理員不需列在此群組也能遠端登入，空的是常態。）",
                null,
                []);
        }

        return Build(
            CheckStatus.Warning,
            $"遠端桌面使用者群組有 {members.Count} 位成員："
            + string.Join("、", members.Select(m => m.DomainAndName))
            + "。這些帳號可以遠端登入這台電腦。",
            "確認每一位都是你認可的。不需要的請移除，並考慮直接關閉遠端桌面功能。",
            [.. members.Select(m => new Evidence("成員", $"{m.DomainAndName}（SID {m.Sid ?? "未知"}）"))]);
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
/// M3-04 本機帳號清單。
/// <para>功能規格：存在啟用中的非預期帳號、或近期建立的帳號 → <c>Warning</c>。Severity High。</para>
/// <para>
/// <b>「建立時間」是推估值</b>：本機帳號沒有可靠的建立時間來源，這裡用使用者設定檔
/// 目錄的建立時間推估，報告中已註明。不可當成鑑識級證據。
/// </para>
/// </summary>
public sealed class M3_04_LocalAccountsCheck(ILocalAccountSource accounts) : ICheck
{
    /// <summary>Windows 內建帳號，出現是正常的。</summary>
    internal static readonly IReadOnlySet<string> BuiltInAccounts =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount",
        };

    /// <summary>設定檔建立時間落在回溯期內即視為「近期建立」。</summary>
    public string Id => "M3-04";

    public string Module => "M3";

    public string Title => "本機帳號清單";

    public Severity Severity => Severity.High;

    public string Source => "NetUserEnum";

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(
            accounts.GetLocalUsers(), accounts.CurrentUserName, context.LookbackDays));
    }

    internal Finding Evaluate(IReadOnlyList<LocalUser> users, string currentUserName, int lookbackDays)
    {
        ArgumentNullException.ThrowIfNull(users);

        var cutoff = DateTimeOffset.Now.AddDays(-lookbackDays);

        var suspicious = users
            .Where(u => u.IsEnabled)
            .Where(u => !BuiltInAccounts.Contains(u.Name))
            .Where(u => !string.Equals(u.Name, currentUserName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var recent = users
            .Where(u => u.ProfileCreatedAt.HasValue && u.ProfileCreatedAt.Value >= cutoff)
            .Where(u => !string.Equals(u.Name, currentUserName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var evidence = users
            .Select(u => new Evidence(
                u.IsEnabled ? "啟用中" : "已停用",
                $"{u.Name}"
                + (u.ProfileCreatedAt is { } created ? $"（設定檔建立於 {created:yyyy-MM-dd}，推估值）" : "（無設定檔）")
                + (u.PasswordNeverExpires ? "，密碼永不過期" : string.Empty),
                u.ProfileCreatedAt))
            .ToList();

        if (suspicious.Count == 0 && recent.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"本機共 {users.Count} 個帳號，啟用中的只有內建帳號與你自己的帳號。",
                null,
                evidence);
        }

        var parts = new List<string>();
        if (suspicious.Count > 0)
        {
            parts.Add($"{suspicious.Count} 個非預期的啟用中帳號（{string.Join("、", suspicious.Select(u => u.Name))}）");
        }

        if (recent.Count > 0)
        {
            parts.Add($"{recent.Count} 個在過去 {lookbackDays} 天內建立的帳號"
                      + $"（{string.Join("、", recent.Select(u => u.Name))}）");
        }

        return Build(
            CheckStatus.Warning,
            $"偵測到 {string.Join("，以及 ", parts)}。"
            + "攻擊者常另建帳號作為後門，好在你改密碼後仍能登入。"
            + "（建立時間為設定檔目錄推估值，非精確的帳號建立時間。）",
            "確認每個帳號都是你自己建立的。不認得的請停用並保存本報告。",
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
