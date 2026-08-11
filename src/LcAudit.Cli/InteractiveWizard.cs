using System.Globalization;
using LcAudit.Core.Model;
using Spectre.Console;

namespace LcAudit.Cli;

/// <summary>
/// 雙擊執行時的引導流程。
/// <para>
/// 使用者是被盜帳號的玩家，多半不會開命令提示字元打參數。雙擊時由工具主動把
/// 該問的問完 —— 要不要提權、什麼時候出事、要不要把報告寄出去 —— 最後停住
/// 讓人看得到結果，而不是黑窗閃一下就關掉。
/// </para>
/// </summary>
internal static class InteractiveWizard
{
    internal static void WriteIntro(IAnsiConsole console)
    {
        console.Write(new Panel(new Markup(string.Join(Environment.NewLine,
            "這個工具會檢查你的電腦，判斷遊戲帳號可能是怎麼被盜的。",
            string.Empty,
            "[green]• 全程唯讀[/] —— 不會修改、刪除或修復你電腦上的任何東西",
            "[green]• 不會自動連網[/] —— 只有你自己選擇上傳報告時才會",
            "[green]• 檢查完可以直接刪掉[/] —— 不需要安裝")))
        {
            Header = new PanelHeader("[bold]這是什麼[/]"),
            Border = BoxBorder.Rounded,
        });
        console.WriteLine();
    }

    /// <summary>
    /// 未提權時詢問是否重新以系統管理員執行。
    /// <para>
    /// 差別很大：未提權會少掉約 8 個檢查項（事件記錄、Defender 設定等），
    /// 而事發時段的登入紀錄正好在那裡面。所以預設為「是」。
    /// </para>
    /// </summary>
    /// <returns>已重新啟動（呼叫端應結束）時回 <c>true</c>。</returns>
    internal static bool OfferElevation(IAnsiConsole console, IReadOnlyList<string> args)
    {
        console.MarkupLine("[yellow]⚠ 目前不是以系統管理員身分執行[/]");
        console.MarkupLine("[grey]  這樣會少檢查約 8 個項目（登入紀錄、防毒設定等），[/]");
        console.MarkupLine("[grey]  而帳號被盜當下的登入紀錄正好在那裡面。[/]");
        console.WriteLine();

        if (!console.Confirm("要用系統管理員身分重新執行嗎？", defaultValue: true))
        {
            console.MarkupLine("[grey]好，以目前權限繼續 —— 部分項目會顯示「無法判定」。[/]");
            console.WriteLine();
            return false;
        }

        if (ConsoleLaunch.TryRelaunchElevated(args))
        {
            console.MarkupLine("[green]已開啟新視窗，請在那邊繼續。[/]");
            return true;
        }

        console.MarkupLine("[yellow]沒有取得系統管理員權限，以目前權限繼續。[/]");
        console.WriteLine();
        return false;
    }

    /// <summary>
    /// 詢問事發區間。
    /// <para>
    /// 問「最後正常」與「發現被盜」兩個時間，而不是「什麼時候被盜」——
    /// 受害者給得出的是前者，後者只能用猜的。
    /// </para>
    /// </summary>
    internal static IncidentWindow? AskIncidentWindow(IAnsiConsole console)
    {
        console.Write(new Rule("[bold]帳號是什麼時候被盜的？[/]").LeftJustified());
        console.MarkupLine("[grey]告訴工具大概的時間，報告就會把那段期間發生的事挑出來排在最前面。[/]");
        console.MarkupLine("[grey]不知道的話直接按 Enter 跳過，其他檢查照常進行。[/]");
        console.WriteLine();

        var lastOk = AskTime(console, "你最後一次確認帳號正常是什麼時候？");
        var found = AskTime(console, "什麼時候發現東西不見／登不進去？");

        console.WriteLine();

        if (lastOk is { } from && found is { } to)
        {
            return IncidentWindow.Between(from, to);
        }

        return (lastOk ?? found) is { } single ? IncidentWindow.At(single) : null;
    }

    /// <summary>結束前停住，否則雙擊執行時視窗會直接關掉，使用者什麼都看不到。</summary>
    internal static void WaitBeforeExit(IAnsiConsole console)
    {
        console.WriteLine();
        console.MarkupLine("[grey]按 Enter 鍵結束…[/]");

        try
        {
            Console.ReadLine();
        }
        catch (IOException)
        {
            // 沒有可讀的輸入（罕見），直接結束即可
        }
    }

    private static DateTimeOffset? AskTime(IAnsiConsole console, string question)
    {
        console.MarkupLine($"[bold]{Markup.Escape(question)}[/]");
        console.MarkupLine("[grey]  格式：2026-08-09 02:00　（不知道就直接按 Enter）[/]");

        while (true)
        {
            console.Markup("  > ");
            var input = Console.ReadLine()?.Trim();

            if (string.IsNullOrWhiteSpace(input))
            {
                console.WriteLine();
                return null;
            }

            if (TryParse(input, out var parsed))
            {
                console.MarkupLine($"[green]  ✓ {Markup.Escape(parsed.ToString("yyyy-MM-dd HH:mm"))}[/]");
                console.WriteLine();
                return parsed;
            }

            console.MarkupLine("[yellow]  看不懂這個時間，請用類似 2026-08-09 02:00 的寫法，或按 Enter 跳過。[/]");
        }
    }

    private static bool TryParse(string value, out DateTimeOffset result)
        => DateTimeOffset.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out result)
           || DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out result);
}
