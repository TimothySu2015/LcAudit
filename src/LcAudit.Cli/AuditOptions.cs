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

    /// <summary>打包成 zip 並上傳給協助者（會先請使用者確認）。</summary>
    public bool Email { get; init; }

    /// <summary>
    /// 使用者沒有指定任何影響行為的參數。
    /// <para>
    /// 搭配「由檔案總管雙擊啟動」判斷是否要走引導流程 —— 有打參數就代表
    /// 使用者知道自己在做什麼，不該再用問答打斷他。
    /// </para>
    /// </summary>
    public bool IsDefaultRun =>
        IncidentWindow is null && !Email && PurplePath is null && SkipModules.Count == 0;
}
