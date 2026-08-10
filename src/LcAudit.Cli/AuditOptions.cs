namespace LcAudit.Cli;

/// <summary>CLI 參數（功能規格 §7）。</summary>
public sealed record AuditOptions
{
    public required int LookbackDays { get; init; }

    public string? PurplePath { get; init; }

    public required DirectoryInfo OutputPath { get; init; }

    public required IReadOnlySet<string> SkipModules { get; init; }
}
