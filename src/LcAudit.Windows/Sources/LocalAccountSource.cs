using System.Security.Principal;
using LcAudit.Windows.Interop;

namespace LcAudit.Windows.Sources;

/// <inheritdoc cref="ILocalAccountSource"/>
public sealed class LocalAccountSource : ILocalAccountSource
{
    /// <summary>
    /// 這些帳號出現在系統管理員群組是正常的，不應報異常。
    /// <para>
    /// 以 SID 的 RID 判斷而非名稱 —— 名稱會被改（攻擊者常把後門帳號改叫
    /// <c>Administrator</c>），SID 不會。
    /// </para>
    /// </summary>
    private static readonly int[] ExpectedAdministratorRids =
    [
        500,  // 內建 Administrator
        512,  // Domain Admins
        519,  // Enterprise Admins
        518,  // Schema Admins
    ];

    public string CurrentUserName => Environment.UserName;

    public IReadOnlyList<GroupMember> GetAdministrators()
        => GetGroupMembers(WellKnownSidType.BuiltinAdministratorsSid);

    public IReadOnlyList<GroupMember> GetRemoteDesktopUsers()
        => GetGroupMembers(WellKnownSidType.BuiltinRemoteDesktopUsersSid);

    public IReadOnlyList<LocalUser> GetLocalUsers()
        => [.. NetApi32.GetLocalUsers().Select(u => new LocalUser(
            u.Name,
            u.Comment,
            u.IsEnabled,
            u.PasswordNeverExpires,
            TryGetProfileCreationTime(u.Name)))];

    /// <summary>解析 well-known SID 為在地化群組名稱；解析不到回 <c>null</c>。</summary>
    public static string? ResolveGroupName(WellKnownSidType sidType)
    {
        try
        {
            var sid = new SecurityIdentifier(sidType, null);
            var account = (NTAccount)sid.Translate(typeof(NTAccount));

            // Translate 回傳 "BUILTIN\Administrators"（或在地化版本），
            // NetLocalGroupGetMembers 只吃不含網域前綴的名稱。
            var index = account.Value.LastIndexOf('\\');
            return index >= 0 ? account.Value[(index + 1)..] : account.Value;
        }
        catch (IdentityNotMappedException)
        {
            return null;
        }
        catch (SystemException)
        {
            return null;
        }
    }

    private static IReadOnlyList<GroupMember> GetGroupMembers(WellKnownSidType sidType)
    {
        var groupName = ResolveGroupName(sidType);
        if (groupName is null)
        {
            return [];
        }

        return [.. NetApi32.GetLocalGroupMembers(groupName).Select(ToGroupMember)];
    }

    private static GroupMember ToGroupMember(LocalGroupMember member)
    {
        var sid = member.Sid;

        return new GroupMember(
            member.DomainAndName,
            sid?.Value,
            IsExpectedAdministrator(sid),
            IsLocalAccount(sid));
    }

    private static bool IsExpectedAdministrator(SecurityIdentifier? sid)
    {
        if (sid is null)
        {
            return false;
        }

        // SID 的最後一段是 RID。內建帳號的 RID 是固定的，與名稱無關。
        var parts = sid.Value.Split('-');
        return int.TryParse(parts[^1], out var rid) && ExpectedAdministratorRids.Contains(rid);
    }

    /// <summary>
    /// 是否為本機帳號。網域帳號與網域群組出現在本機 Administrators 是企業環境的常態，
    /// 嚴重度應與「本機多了一個管理員帳號」區分開來。
    /// </summary>
    private static bool IsLocalAccount(SecurityIdentifier? sid)
    {
        if (sid is null)
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var machineSid = identity.User?.AccountDomainSid;

            return machineSid is not null && sid.IsEqualDomainSid(machineSid);
        }
        catch (SystemException)
        {
            return false;
        }
    }

    /// <summary>
    /// 以使用者設定檔目錄的建立時間推估帳號建立時間。
    /// <para>
    /// <b>這是推估值。</b>本機帳號沒有可靠的建立時間來源 —— 登錄檔與 NetUserGetInfo
    /// 都不提供。報告中必須註明是推估，不可當成鑑識級證據。
    /// </para>
    /// </summary>
    private static DateTimeOffset? TryGetProfileCreationTime(string userName)
    {
        try
        {
            var profilePath = Path.Combine(
                Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users",
                userName);

            return Directory.Exists(profilePath)
                ? new DateTimeOffset(Directory.GetCreationTime(profilePath))
                : null;
        }
        catch (SystemException)
        {
            return null;
        }
    }
}
