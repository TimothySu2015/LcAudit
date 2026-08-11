using LcAudit.Core.Model;
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

    /// <summary>使用者提供的事發區間。</summary>
    public IncidentWindow? IncidentWindow { get; init; }

    /// <summary>打包成 zip 並開啟郵件草稿。工具本身不會傳送任何資料。</summary>
    public bool Email { get; init; }
}
