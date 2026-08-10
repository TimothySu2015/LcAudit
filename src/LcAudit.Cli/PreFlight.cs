using System.Security.Principal;
using LcAudit.Windows.Sources;
using Spectre.Console;

namespace LcAudit.Cli;

/// <summary>執行前的環境檢查與警示（功能規格 §3.1、CLAUDE.md 反作弊共存規則）。</summary>
public static class PreFlight
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// 輸出首行警示。
    /// <para>
    /// 兩種警示的強度刻意不同：未提權會讓約 8 個檢查項失效（最高可差 100+ 分），
    /// 遊戲執行中只影響 M4-01（Info 級、0 分）。措辭要反映這個差距。
    /// </para>
    /// </summary>
    public static void WriteWarnings(IAnsiConsole console, bool isElevated, IReadOnlySet<int> protectedPids)
    {
        ArgumentNullException.ThrowIfNull(console);
        ArgumentNullException.ThrowIfNull(protectedPids);

        if (!isElevated)
        {
            console.MarkupLine(
                "[bold yellow]⚠ 未以系統管理員身分執行[/] —— "
                + "Security 事件記錄、Defender 設定、WMI 訂閱等檢查項將無法判定，"
                + "覆蓋率會明顯下降。建議以系統管理員重新執行。");
        }

        if (protectedPids.Count > 0)
        {
            console.MarkupLine(
                $"[yellow]提醒：偵測到遊戲或反作弊程序執行中（{protectedPids.Count} 個）[/] —— "
                + "建議關閉天堂與紫P 後再執行。本工具會自動排除這些程序，"
                + "僅 M4-01 會因此無法判定（Info 級，不影響評分）。");
        }

        if (isElevated && protectedPids.Count == 0)
        {
            console.MarkupLine("[green]✓ 已提權，且未偵測到遊戲執行中 —— 可進行完整掃描。[/]");
        }

        console.WriteLine();
    }
}
