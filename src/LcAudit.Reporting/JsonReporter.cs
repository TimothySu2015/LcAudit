using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using LcAudit.Core.Model;

namespace LcAudit.Reporting;

/// <summary>JSON 報告（功能規格 §8.2）。</summary>
public sealed class JsonReporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,

        // 功能規格 §8.2 定義的欄位名稱是 camelCase。
        // 命名原則放在這裡而非用屬性標註 Core 的模型 —— 序列化是輸出層的事，
        // 不該讓領域模型去遷就某一種報告格式。
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,

        Converters = { new JsonStringEnumConverter() },
        // 保留繁中可讀性（不轉成 \uXXXX），但仍跳脫 HTML 敏感字元 ——
        // 這份 JSON 有可能被貼進網頁或工單系統。
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    public string Render(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, Options);
    }
}
