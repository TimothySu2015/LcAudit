using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LcAudit.Windows.Interop;

/// <summary>
/// 取得執行中處理程序的執行檔路徑。
/// <para>
/// <b>權限旗標只能是 <c>PROCESS_QUERY_LIMITED_INFORMATION</c>。</b>
/// .NET 的 <c>Process.MainModule.FileName</c> 底層會帶
/// <c>PROCESS_QUERY_INFORMATION | PROCESS_VM_READ</c>，而 VM_READ 正是外掛讀取遊戲
/// 記憶體用的旗標 —— 反作弊會剝權限、記錄，部分版本直接讓遊戲跳錯誤結束。
/// LIMITED_INFORMATION 是為最小化情境設計的，最可能被放行；被拒也只是 Access Denied。
/// </para>
/// </summary>
internal static partial class Kernel32
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwProcessId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW",
                   StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(
        SafeProcessHandle hProcess,
        uint dwFlags,
        [Out] char[] lpExeName,
        ref uint lpdwSize);

    /// <summary>
    /// 取得指定 PID 的執行檔完整路徑；權限不足或程序已結束時回 <c>null</c>。
    /// <para>回 <c>null</c> 是正常結果，呼叫端應轉為 Inconclusive，不可視為異常。</para>
    /// </summary>
    internal static string? TryGetProcessImagePath(int processId)
    {
        using var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);
        if (handle.IsInvalid)
        {
            return null;
        }

        var capacity = 1024u;
        var buffer = new char[capacity];

        return QueryFullProcessImageName(handle, 0, buffer, ref capacity)
            ? new string(buffer, 0, (int)capacity)
            : null;
    }
}
