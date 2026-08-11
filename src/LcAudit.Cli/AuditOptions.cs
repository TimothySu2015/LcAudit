using LcAudit.Reporting;

namespace LcAudit.Cli;

/// <summary>CLI 參數（功能規格 §7）。</summary>
public sealed record AuditOptions
{
    public required int LookbackDays { get; init; }

    public string? PurplePath { get; init; }

    public required DirectoryInfo OutputPath { get; init; }

    public required IReadOnlySet<string> SkipModules { get; init; }

    public required ReportFormat Format { get; init; }

    /// <summary>使用者提供的事發時間（帳號被盜、收到通知的時間點）。</summary>
    public DateTimeOffset? IncidentTime { get; init; }
}
