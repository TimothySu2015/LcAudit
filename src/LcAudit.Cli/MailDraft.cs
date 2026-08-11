using System.Diagnostics;
using Spectre.Console;

namespace LcAudit.Cli;

/// <summary>
/// 準備一封寄送報告的郵件草稿。
/// <para>
/// <b>本工具不會、也不能自己把郵件寄出去。</b>要從程式端送信，必須在執行檔裡帶著
/// SMTP 密碼、Gmail API 金鑰、或郵件服務的 API key —— 但這是一個**公開下載**的
/// 執行檔，任何人都能把金鑰挖出來，拿去冒名寄信、發垃圾郵件，那個信箱幾天內就會被
/// 服務商停用。
/// </para>
/// <para>
/// 更嚴重的是：這個工具是設計來在**可能已被入侵的電腦**上執行的。把可用的寄信憑證
/// 放進去，等於直接送給攻擊者。
/// </para>
/// <para>
/// 而且「未簽章的執行檔，會列舉處理程序、讀取安全性事件記錄，然後**自動把蒐集到的
/// 資料送到外部信箱**」——這是 infostealer 的教科書定義，防毒幾乎必定攔截。
/// </para>
/// <para>
/// 因此改為：打包好 zip、開啟使用者自己的郵件程式並填好收件者與主旨，
/// 由**使用者按下傳送**。工具全程不連網，使用者也清楚知道自己送出了什麼。
/// 若日後真要做到自動上傳，唯一安全的架構是自架後端服務持有憑證，客戶端只跟它說話。
/// </para>
/// </summary>
public static class MailDraft
{
    /// <summary>報告收件信箱。</summary>
    public const string Recipient = "lcaudit2026@gmail.com";

    /// <summary>
    /// 開啟郵件草稿並在檔案總管中選取壓縮檔。
    /// <para>失敗不影響掃描結果 —— 檔案已經產生，使用者仍可自行寄送。</para>
    /// </summary>
    public static void Open(IAnsiConsole console, string zipPath, string reportId)
    {
        ArgumentNullException.ThrowIfNull(console);
        ArgumentException.ThrowIfNullOrWhiteSpace(zipPath);

        var subject = $"LcAudit 稽核報告 {reportId}";
        var body = string.Join("\r\n",
            "（請將下列檔案附加到這封信後傳送）",
            string.Empty,
            zipPath,
            string.Empty,
            $"報告識別碼：{reportId}",
            string.Empty,
            "若方便的話，請一併說明：",
            "1. 大約什麼時候發現帳號被盜？",
            "2. 有沒有印象自己安裝過遠端遙控程式（AnyDesk、TeamViewer 等）？");

        console.WriteLine();
        console.MarkupLine("[bold]報告已打包完成[/]");
        console.MarkupLine($"  壓縮檔　：{Markup.Escape(zipPath)}");
        console.MarkupLine($"  識別碼　：[bold]{Markup.Escape(reportId)}[/]");
        console.MarkupLine($"  收件信箱：[bold]{Recipient}[/]");
        console.WriteLine();
        console.MarkupLine(
            "[yellow]本工具不會自動寄出 —— 全程不連網，也不會在背景傳送任何資料。[/]");
        console.MarkupLine(
            "[grey]接下來會開啟你的郵件程式並填好收件者，請把上面那個 zip 檔附加進去後傳送。[/]");

        TryStart($"mailto:{Recipient}?subject={Uri.EscapeDataString(subject)}&body={Uri.EscapeDataString(body)}");

        // 同時開啟檔案總管並選取壓縮檔，方便直接拖進郵件
        TryStart("explorer.exe", $"/select,\"{zipPath}\"");
    }

    private static void TryStart(string fileName, string? arguments = null)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(fileName)
            {
                Arguments = arguments ?? string.Empty,
                UseShellExecute = true,
            });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            // 沒有預設郵件程式、或在無 GUI 的環境執行 —— 都不影響已產生的報告檔
        }
    }
}
