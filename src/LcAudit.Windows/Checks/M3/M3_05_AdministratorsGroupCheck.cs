using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M3;

/// <summary>
/// M3-05 系統管理員群組成員。
/// <para>功能規格：非預期成員 → <c>Fail</c>，Severity <b>Critical</b>。</para>
/// <para>
/// <b>這是全工具誤報風險最高的檢查項</b> —— Critical 命中會直接強制風險等級為「極高」。
/// 規格從未定義「預期成員」是什麼，若一律判 Fail，任何有第二個管理員帳號、
/// 裝過 SQL Server／Docker、或在公司網域下的機器都會噴極高風險，工具的可信度會被誤報吃光。
/// </para>
/// <para>因此分三級判定，見 <see cref="Evaluate"/>。</para>
/// </summary>
public sealed class M3_05_AdministratorsGroupCheck(ILocalAccountSource accounts) : ICheck
{
    public string Id => "M3-05";

    public string Module => "M3";

    public string Title => "系統管理員群組成員";

    public Severity Severity => Severity.Critical;

    public string Source => "本機群組 S-1-5-32-544（Administrators）";

    /// <summary>使用者以 <c>--expect-admin</c> 宣告的預期成員。</summary>
    public IReadOnlySet<string> ExpectedMembers { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ct.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Evaluate(accounts.GetAdministrators(), accounts.CurrentUserName));
    }

    /// <summary>
    /// 三級判定：
    /// <list type="bullet">
    /// <item>內建管理員（RID 500/512/518/519）、目前使用者、<c>--expect-admin</c> 指定者 → 預期成員</item>
    /// <item>非預期的**網域**帳號或群組 → <c>Warning</c>（企業環境常態，不該計 40 分）</item>
    /// <item>非預期的**本機**帳號 → <c>Fail</c>（家用機出現這個確實高度可疑，符合規格）</item>
    /// </list>
    /// </summary>
    internal Finding Evaluate(IReadOnlyList<GroupMember> members, string currentUserName)
    {
        ArgumentNullException.ThrowIfNull(members);

        if (members.Count == 0)
        {
            return Build(
                CheckStatus.Inconclusive,
                "無法列舉系統管理員群組成員。",
                "請以系統管理員身分重新執行。",
                []);
        }

        var unexpected = members
            .Where(m => !m.IsWellKnownAdministrator)
            .Where(m => !string.Equals(m.AccountName, currentUserName, StringComparison.OrdinalIgnoreCase))
            .Where(m => !ExpectedMembers.Contains(m.AccountName) && !ExpectedMembers.Contains(m.DomainAndName))
            .ToList();

        var evidence = members
            .Select(m => new Evidence(
                m.IsWellKnownAdministrator ? "內建成員" : m.IsLocalAccount ? "本機成員" : "網域成員",
                $"{m.DomainAndName}（SID {m.Sid ?? "未知"}）"))
            .ToList();

        if (unexpected.Count == 0)
        {
            return Build(
                CheckStatus.Pass,
                $"系統管理員群組共 {members.Count} 位成員，皆為內建帳號或目前使用者。",
                null,
                evidence);
        }

        var unexpectedLocal = unexpected.Where(m => m.IsLocalAccount).ToList();

        if (unexpectedLocal.Count > 0)
        {
            var names = string.Join("、", unexpectedLocal.Select(m => m.DomainAndName));

            return Build(
                CheckStatus.Fail,
                $"系統管理員群組中有 {unexpectedLocal.Count} 個非預期的**本機**帳號：{names}。"
                + "攻擊者取得權限後建立管理員帳號，是為了在你改密碼後仍能回來。",
                $"若這是你自己建立的帳號，請以 --expect-admin \"{unexpectedLocal[0].AccountName}\" 重新執行以排除；"
                + "若不是，立即保存本報告、斷網、並考慮重灌。",
                evidence);
        }

        var domainNames = string.Join("、", unexpected.Select(m => m.DomainAndName));

        return Build(
            CheckStatus.Warning,
            $"系統管理員群組中有 {unexpected.Count} 個非預期的網域帳號或群組：{domainNames}。"
            + "公司配發的電腦有這些是正常的；個人電腦不應該有。",
            "若這是個人電腦而非公司配發，請確認這些成員的來源。",
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
