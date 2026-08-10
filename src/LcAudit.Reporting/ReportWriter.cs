using System.Text;
using LcAudit.Core.Model;

namespace LcAudit.Reporting;

/// <summary>
/// 把報告寫成檔案。
/// <para>
/// <b>這是本工具唯一允許寫入磁碟的地方</b>（NFR-03）—— 且只能寫在 <c>--output</c>
/// 指定的目錄底下。任何新增的寫檔行為都應該經過這裡。
/// </para>
/// </summary>
public sealed class ReportWriter(HtmlReporter htmlReporter, JsonReporter jsonReporter)
{
    /// <summary>UTF-8 with BOM（NFR-08）—— 舊版工具與 Excel 開啟繁中檔案才不會亂碼。</summary>
    private static readonly Encoding Utf8WithBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    /// <summary>寫出報告檔，回傳實際寫出的完整路徑。</summary>
    public IReadOnlyList<string> Write(AuditReport report, DirectoryInfo outputDirectory, ReportFormat format)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(outputDirectory);

        var written = new List<string>();
        if ((format & (ReportFormat.Json | ReportFormat.Html)) == 0)
        {
            return written;
        }

        outputDirectory.Create();

        var baseName = BuildBaseName(report);

        if (format.HasFlag(ReportFormat.Html))
        {
            written.Add(WriteFile(outputDirectory, $"{baseName}.html", htmlReporter.Render(report)));
        }

        if (format.HasFlag(ReportFormat.Json))
        {
            written.Add(WriteFile(outputDirectory, $"{baseName}.json", jsonReporter.Render(report)));
        }

        return written;
    }

    /// <summary><c>LcAudit-{COMPUTERNAME}-{yyyyMMdd-HHmmss}</c>（功能規格 §8.2）。</summary>
    internal static string BuildBaseName(AuditReport report)
        => $"LcAudit-{Sanitise(report.Host.ComputerName)}-{report.ScannedAt:yyyyMMdd-HHmmss}";

    /// <summary>電腦名稱理論上不含非法字元，但報告檔名不值得為此冒險。</summary>
    private static string Sanitise(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "UNKNOWN";
        }

        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string([.. value.Select(c => invalid.Contains(c) ? '_' : c)]);

        return cleaned.Trim().TrimEnd('.') is { Length: > 0 } trimmed ? trimmed : "UNKNOWN";
    }

    private static string WriteFile(DirectoryInfo directory, string fileName, string content)
    {
        var path = Path.Combine(directory.FullName, fileName);
        File.WriteAllText(path, content, Utf8WithBom);
        return path;
    }
}
