using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LcAudit.Cli;

/// <summary>
/// 判斷程式是怎麼被啟動的，以及在必要時以系統管理員身分重新執行。
/// <para>
/// 目標使用者是被盜帳號的玩家，不是工程師 —— 多數人會直接雙擊執行檔，
/// 而不會開命令提示字元打參數。雙擊時必須自己把該問的問完、該提權的提權，
/// 最後停住讓人看得到結果。
/// </para>
/// </summary>
internal static partial class ConsoleLaunch
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetConsoleProcessList([Out] uint[] lpdwProcessList, uint dwProcessCount);

    /// <summary>
    /// 是否由檔案總管雙擊啟動（而非從既有的命令列視窗執行）。
    /// <para>
    /// 判斷方式：雙擊時 Windows 會建立一個新的主控台，只有本行程附著在上面；
    /// 從 cmd／PowerShell 執行時，那個 shell 也附著在同一個主控台上。
    /// 所以「附著行程數 == 1」就代表是雙擊。
    /// </para>
    /// </summary>
    internal static bool IsOwnConsole()
    {
        try
        {
            var buffer = new uint[4];
            var count = GetConsoleProcessList(buffer, (uint)buffer.Length);

            return count == 1;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// 以系統管理員身分重新啟動自己。
    /// <para>
    /// 使用者在 UAC 對話框按取消時會拋 <c>Win32Exception</c>，那是正常選擇，
    /// 不是錯誤 —— 回 <c>false</c> 讓呼叫端以未提權模式繼續。
    /// </para>
    /// </summary>
    internal static bool TryRelaunchElevated(IReadOnlyList<string> args)
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return false;
        }

        try
        {
            var info = new ProcessStartInfo(executable)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.CurrentDirectory,
            };

            foreach (var arg in args)
            {
                info.ArgumentList.Add(arg);
            }

            return Process.Start(info) is not null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }
}
