using System.Security.Principal;

namespace LcAudit.Windows.Sources;

/// <summary>群組成員。</summary>
/// <param name="DomainAndName">如 <c>DESKTOP-01\timothy</c>。</param>
/// <param name="Sid">SID 字串；取不到為 <c>null</c>。</param>
/// <param name="IsWellKnownAdministrator">是否為內建管理員／網域管理員等預期成員。</param>
/// <param name="IsLocalAccount">是否為本機帳號（相對於網域帳號或群組）。</param>
public sealed record GroupMember(
    string DomainAndName,
    string? Sid,
    bool IsWellKnownAdministrator,
    bool IsLocalAccount)
{
    /// <summary>取出不含網域前綴的帳號名稱。</summary>
    public string AccountName
    {
        get
        {
            var index = DomainAndName.LastIndexOf('\\');
            return index >= 0 ? DomainAndName[(index + 1)..] : DomainAndName;
        }
    }
}

/// <summary>本機使用者帳號。</summary>
public sealed record LocalUser(
    string Name,
    string? Comment,
    bool IsEnabled,
    bool PasswordNeverExpires,
    DateTimeOffset? ProfileCreatedAt);

/// <summary>
/// 本機帳號與群組查詢（M3-03 / M3-04 / M3-05）。
/// <para>
/// <b>群組一律以 well-known SID 定位，不可硬寫名稱。</b>
/// 「Administrators」在部分語系的 Windows 上是在地化的，硬寫名稱會查不到群組而讓
/// 整個檢查失效 —— 而且失效方式是「找不到成員」，看起來就像「沒有異常」。
/// </para>
/// </summary>
public interface ILocalAccountSource
{
    /// <summary>系統管理員群組成員（<c>S-1-5-32-544</c>）。</summary>
    IReadOnlyList<GroupMember> GetAdministrators();

    /// <summary>遠端桌面使用者群組成員（<c>S-1-5-32-555</c>）；群組不存在回空集合。</summary>
    IReadOnlyList<GroupMember> GetRemoteDesktopUsers();

    IReadOnlyList<LocalUser> GetLocalUsers();

    /// <summary>目前執行本工具的使用者，用來判斷「這是我自己的帳號」。</summary>
    string CurrentUserName { get; }
}
