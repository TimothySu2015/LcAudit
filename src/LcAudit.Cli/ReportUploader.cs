using System.Net.Http.Json;
using System.Text.Json;
using Spectre.Console;

namespace LcAudit.Cli;

/// <summary>
/// 把報告上傳到接收端（Google Apps Script Web App）。
/// <para>
/// <b>這是本工具唯一一處會發出網路請求的地方，且只在使用者明確指定
/// <c>--email</c> 並在提示中確認後才執行。</b>其餘所有檢查全程離線。
/// </para>
/// <para>
/// 接收端以指令碼擁有者的身分執行，所以這裡不需要、也沒有任何憑證 ——
/// 若在公開下載的執行檔中內嵌 Gmail 應用程式密碼，拿到的人不只能冒名寄信，
/// 還能讀取信箱裡所有已收到的報告。部署方式見 <c>tools/apps-script/</c>。
/// </para>
/// </summary>
public static class ReportUploader
{
    /// <summary>接收端網址。公開資訊，就像網頁表單的送出網址一樣。</summary>
    public const string EndpointUrl =
        "https://script.google.com/macros/s/AKfycbwTp8ZZ_dgJ6uiOigZ6hSYmeVcnVcnvzWedASk7YVlGlD5cLXzXl_INkimnQDWi9JRkjg/exec";

    /// <summary>
    /// 與接收端共用的識別字串。
    /// <para>
    /// <b>這不是機密。</b>它就在這個公開下載的執行檔裡，任何人用文字編輯器都看得到。
    /// 它唯一的作用是擋掉隨機掃描網際網路的機器人，不是存取控制。
    /// 遭濫用時的處置是重新部署接收端換新網址，而非「保護」這個字串。
    /// </para>
    /// </summary>
    private const string SharedToken =
        "b03ccd8630494f49ab9756294c9158eae2ad05657cb74de9acda00012242885e";

    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    /// <summary>
    /// 列出將要送出的內容並請使用者確認。
    /// <para>
    /// 使用者未必清楚報告裡有什麼 —— 那是他自己電腦的鑑識剖析。
    /// 送出去之前必須讓他知道自己送了什麼。
    /// </para>
    /// </summary>
    public static bool Confirm(IAnsiConsole console, string zipPath, string reportId)
    {
        ArgumentNullException.ThrowIfNull(console);

        console.WriteLine();
        console.Write(new Rule("[bold yellow]上傳報告前請確認[/]").LeftJustified());
        console.MarkupLine($"  檔案　：{Markup.Escape(zipPath)}");
        console.MarkupLine($"  識別碼：[bold]{Markup.Escape(reportId)}[/]");
        console.MarkupLine($"  送往　：{Markup.Escape(MailDraft.Recipient)} 的雲端空間");
        console.WriteLine();
        console.MarkupLine("[yellow]報告中包含以下你電腦上的資訊：[/]");
        console.MarkupLine("  · 電腦名稱與 Windows 版本");
        console.MarkupLine("  · 本機使用者帳號名稱");
        console.MarkupLine("  · 曾遠端連入的來源 IP 位址與時間");
        console.MarkupLine("  · 已安裝的程式、服務與開機啟動項目的路徑");
        console.MarkupLine("  · 紫P 的安裝位置與簽章資訊");
        console.WriteLine();
        console.MarkupLine("[grey]不含密碼、金鑰或遊戲帳號內容。若這台是公司電腦，送出前請先確認公司規定。[/]");
        console.WriteLine();

        // 非互動環境（輸出被導向、排程執行）不應自行決定送出他人的個資
        if (Console.IsInputRedirected)
        {
            console.MarkupLine(
                "[yellow]目前不是互動式執行環境，無法取得你的確認，已略過上傳。[/]");
            console.MarkupLine($"[grey]報告仍已存在：{Markup.Escape(zipPath)}[/]");
            return false;
        }

        return console.Confirm("確定要上傳嗎？", defaultValue: false);
    }

    /// <summary>上傳報告。成功回 <c>true</c>。</summary>
    public static async Task<bool> UploadAsync(
        IAnsiConsole console,
        string zipPath,
        string reportId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(console);
        ArgumentException.ThrowIfNullOrWhiteSpace(zipPath);

        try
        {
            var payload = new
            {
                token = SharedToken,
                reportId,
                fileName = Path.GetFileName(zipPath),
                contentBase64 = Convert.ToBase64String(await File.ReadAllBytesAsync(zipPath, ct)),
            };

            using var http = new HttpClient { Timeout = Timeout };
            using var response = await http.PostAsJsonAsync(EndpointUrl, payload, ct);

            if (!response.IsSuccessStatusCode)
            {
                return Failed(console, zipPath, $"伺服器回應 HTTP {(int)response.StatusCode}");
            }

            // Apps Script 即使邏輯失敗也會回 200，狀態在內容裡
            var body = await response.Content.ReadAsStringAsync(ct);
            using var json = JsonDocument.Parse(body);

            if (json.RootElement.TryGetProperty("status", out var status) && status.GetInt32() != 200)
            {
                var message = json.RootElement.TryGetProperty("message", out var m)
                    ? m.GetString()
                    : "未知錯誤";

                return Failed(console, zipPath, $"伺服器拒絕：{message}");
            }

            console.WriteLine();
            console.MarkupLine("[green]報告已上傳完成。[/]");
            console.MarkupLine($"[grey]請把識別碼 [/][bold]{Markup.Escape(reportId)}[/][grey] 告知協助你的人，方便對照。[/]");

            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            return Failed(console, zipPath, ex.Message);
        }
    }

    /// <summary>上傳失敗不是致命錯誤 —— 報告檔已經產生，使用者仍可自行寄送。</summary>
    private static bool Failed(IAnsiConsole console, string zipPath, string reason)
    {
        console.WriteLine();
        console.MarkupLine($"[red]上傳失敗：[/]{Markup.Escape(reason)}");
        console.MarkupLine($"[grey]報告仍已存在：{Markup.Escape(zipPath)}[/]");
        console.MarkupLine($"[grey]你可以自行把它寄到 {Markup.Escape(MailDraft.Recipient)}。[/]");

        return false;
    }
}
