using System.Runtime.InteropServices;

namespace LcAudit.Windows.Interop;

/// <summary>
/// <c>netapi32.dll</c> —— 本機帳號與群組成員列舉（M3-03 / M3-04 / M3-05）。
/// <para>
/// 全部是唯讀查詢 API，不修改任何帳號。回傳的緩衝區必須以
/// <c>NetApiBufferFree</c> 釋放，否則洩漏非受控記憶體。
/// </para>
/// </summary>
internal static partial class NetApi32
{
    internal const int NERR_Success = 0;

    /// <summary>帳號已停用（<c>USER_INFO_1.usri1_flags</c> 的 <c>UF_ACCOUNTDISABLE</c>）。</summary>
    internal const uint UF_ACCOUNTDISABLE = 0x0002;

    /// <summary>密碼永不過期。</summary>
    internal const uint UF_DONT_EXPIRE_PASSWD = 0x10000;

    private const int MAX_PREFERRED_LENGTH = -1;
    private const uint FILTER_NORMAL_ACCOUNT = 0x0002;

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetLocalGroupGetMembers(
        string? serverName,
        string localGroupName,
        uint level,
        out IntPtr bufptr,
        int prefmaxlen,
        out uint entriesRead,
        out uint totalEntries,
        IntPtr resumeHandle);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetUserEnum(
        string? serverName,
        uint level,
        uint filter,
        out IntPtr bufptr,
        int prefmaxlen,
        out uint entriesRead,
        out uint totalEntries,
        ref uint resumeHandle);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    /// <summary>列舉本機群組成員。<paramref name="localGroupName"/> 必須是在地化後的實際名稱。</summary>
    internal static IReadOnlyList<LocalGroupMember> GetLocalGroupMembers(string localGroupName)
    {
        var status = NetLocalGroupGetMembers(
            null, localGroupName, 2, out var buffer, MAX_PREFERRED_LENGTH,
            out var entriesRead, out _, IntPtr.Zero);

        if (status != NERR_Success)
        {
            throw new InvalidOperationException($"NetLocalGroupGetMembers 失敗（狀態碼 {status}）。");
        }

        // 空群組合法地會回 entriesRead = 0 且 buffer = null。
        // 這是「群組沒有成員」而非「查詢失敗」—— 當成例外會讓 M3-03 把正常狀態誤報為無法判定。
        if (buffer == IntPtr.Zero || entriesRead == 0)
        {
            if (buffer != IntPtr.Zero)
            {
                _ = NetApiBufferFree(buffer);
            }

            return [];
        }

        try
        {
            var results = new List<LocalGroupMember>((int)entriesRead);
            var size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();

            for (var i = 0; i < entriesRead; i++)
            {
                var entry = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buffer + (i * size));

                results.Add(new LocalGroupMember(
                    Marshal.PtrToStringUni(entry.lgrmi2_domainandname) ?? string.Empty,
                    entry.lgrmi2_sid == IntPtr.Zero
                        ? null
                        : new System.Security.Principal.SecurityIdentifier(entry.lgrmi2_sid)));
            }

            return results;
        }
        finally
        {
            _ = NetApiBufferFree(buffer);
        }
    }

    /// <summary>列舉本機使用者帳號（不含電腦帳號與信任帳號）。</summary>
    internal static IReadOnlyList<LocalUserAccount> GetLocalUsers()
    {
        var results = new List<LocalUserAccount>();
        uint resume = 0;

        do
        {
            var status = NetUserEnum(
                null, 1, FILTER_NORMAL_ACCOUNT, out var buffer, MAX_PREFERRED_LENGTH,
                out var entriesRead, out _, ref resume);

            // ERROR_MORE_DATA (234) 代表還有下一批，仍需處理本批。
            if (status is not (NERR_Success or 234))
            {
                throw new InvalidOperationException($"NetUserEnum 失敗（狀態碼 {status}）。");
            }

            if (buffer == IntPtr.Zero)
            {
                break;
            }

            try
            {
                var size = Marshal.SizeOf<USER_INFO_1>();

                for (var i = 0; i < entriesRead; i++)
                {
                    var entry = Marshal.PtrToStructure<USER_INFO_1>(buffer + (i * size));

                    results.Add(new LocalUserAccount(
                        Marshal.PtrToStringUni(entry.usri1_name) ?? string.Empty,
                        Marshal.PtrToStringUni(entry.usri1_comment),
                        (entry.usri1_flags & UF_ACCOUNTDISABLE) == 0,
                        (entry.usri1_flags & UF_DONT_EXPIRE_PASSWD) != 0));
                }
            }
            finally
            {
                _ = NetApiBufferFree(buffer);
            }
        }
        while (resume != 0);

        return results;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public IntPtr lgrmi2_domainandname;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_1
    {
        public IntPtr usri1_name;
        public IntPtr usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public IntPtr usri1_home_dir;
        public IntPtr usri1_comment;
        public uint usri1_flags;
        public IntPtr usri1_script_path;
    }
}

/// <summary>本機群組的一位成員。</summary>
/// <param name="DomainAndName">如 <c>DESKTOP-01\timothy</c> 或 <c>CONTOSO\Domain Admins</c>。</param>
/// <param name="Sid">成員 SID；無法取得時為 <c>null</c>。</param>
internal sealed record LocalGroupMember(
    string DomainAndName,
    System.Security.Principal.SecurityIdentifier? Sid);

/// <summary>本機使用者帳號。</summary>
internal sealed record LocalUserAccount(
    string Name,
    string? Comment,
    bool IsEnabled,
    bool PasswordNeverExpires);
