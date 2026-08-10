namespace LcAudit.Reporting;

/// <summary>報告輸出格式（功能規格 §7 的 <c>--format</c>）。</summary>
[Flags]
public enum ReportFormat
{
    None = 0,
    Console = 1,
    Json = 2,
    Html = 4,
    All = Console | Json | Html,
}
