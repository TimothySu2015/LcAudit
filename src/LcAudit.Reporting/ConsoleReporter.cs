using LcAudit.Core.Model;
using Spectre.Console;

namespace LcAudit.Reporting;

/// <summary>Console 報告（功能規格 §8.1）：依模組分區塊、分色，結尾輸出等級與推論。</summary>
public sealed class ConsoleReporter(IAnsiConsole console)
{
    public void Write(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        WriteFindings(report.Findings);
        WriteSummary(report.Summary);
        WriteIncidentTimeline(report);
        WriteForensicNotice(report);
    }

    private void WriteFindings(IReadOnlyList<Finding> findings)
    {
        foreach (var group in findings.GroupBy(f => f.Module).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .Title($"[bold]模組 {group.Key}[/]")
                .AddColumn("項目")
                .AddColumn("檢查內容")
                .AddColumn("結果")
                .AddColumn("分數", c => c.RightAligned());

            foreach (var finding in group.OrderBy(f => f.Id, StringComparer.Ordinal))
            {
                var colour = ReportPresentation.StatusColour(finding.Status);

                table.AddRow(
                    Markup.Escape(finding.Id),
                    Markup.Escape(finding.Title),
                    $"[{colour}]{Markup.Escape(ReportPresentation.StatusText(finding.Status))}[/]",
                    finding.Score == 0 ? "-" : finding.Score.ToString());
            }

            console.Write(table);

            // 有問題的項目才展開說明，避免乾淨主機刷一整螢幕。
            foreach (var finding in group.Where(f => f.Status is not CheckStatus.Pass)
                                         .OrderBy(f => f.Id, StringComparer.Ordinal))
            {
                WriteDetail(finding);
            }
        }
    }

    private void WriteDetail(Finding finding)
    {
        var colour = ReportPresentation.StatusColour(finding.Status);
        console.MarkupLine($"  [{colour}]▸ {Markup.Escape(finding.Id)} {Markup.Escape(finding.Title)}[/]");

        if (!string.IsNullOrWhiteSpace(finding.Description))
        {
            console.MarkupLine($"    {Markup.Escape(finding.Description)}");
        }

        foreach (var evidence in finding.Evidence)
        {
            console.MarkupLine($"    [grey]· {Markup.Escape(evidence.Key)}：{Markup.Escape(evidence.Value)}[/]");
        }

        if (!string.IsNullOrWhiteSpace(finding.Recommendation))
        {
            console.MarkupLine($"    [blue]建議：{Markup.Escape(finding.Recommendation)}[/]");
        }

        console.WriteLine();
    }

    private void WriteSummary(AuditSummary summary)
    {
        var colour = ReportPresentation.LevelColour(summary.Level);
        var levelText = ReportPresentation.LevelText(summary.Level);

        var panel = new Panel(new Markup(BuildSummaryBody(summary)))
            .Header($"[bold {colour}]風險等級：{levelText}（{summary.Score} 分）[/]")
            .BorderColor(ParseColour(colour));

        console.Write(panel);
    }

    private static string BuildSummaryBody(AuditSummary summary)
    {
        var lines = new List<string>();

        // 分數低但等級高時，一定要解釋原因，否則使用者會覺得工具在亂報
        if (summary.LevelRaisedBy is { } reason)
        {
            lines.Add($"[red]{Markup.Escape(reason)}，等級已強制為「"
                      + $"{Markup.Escape(ReportPresentation.LevelText(summary.Level))}」——"
                      + "不受總分影響。[/]");
        }

        if (summary.RawScore > summary.Score)
        {
            lines.Add($"[grey]原始加總 {summary.RawScore} 分，已套用 100 分上限。[/]");
        }

        foreach (var inference in summary.Inferences)
        {
            var matched = inference.MatchedCheckIds.Count > 0
                ? $"（{string.Join("、", inference.MatchedCheckIds)}）"
                : string.Empty;
            lines.Add($"[bold]最可能途徑：[/]{Markup.Escape(inference.Conclusion)}{Markup.Escape(matched)}");
        }

        if (summary.CoverageNote is not null)
        {
            lines.Add($"[yellow]{Markup.Escape(summary.CoverageNote)}[/]");
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>事發時間錨點比對。有提供事發時間時，這是使用者最想看的一段。</summary>
    private void WriteIncidentTimeline(AuditReport report)
    {
        if (report.IncidentTime is not { } incidentTime)
        {
            return;
        }

        var matches = IncidentTimeline.Build(report.Findings, incidentTime);

        console.WriteLine();
        console.MarkupLine($"[bold]事發時間比對（{Markup.Escape(incidentTime.ToString("yyyy-MM-dd HH:mm"))}）[/]");

        if (matches.Count == 0)
        {
            console.MarkupLine(
                "[grey]前後 3 天內沒有找到任何帶時間點的跡證。"
                + "可能是入侵發生得更早，也可能是相關紀錄已被清除或超過保留期。[/]");
            return;
        }

        foreach (var match in matches.Take(15))
        {
            var isClose = match.Offset.Duration() <= IncidentTimeline.CloseWindow;
            var colour = isClose ? "red" : "grey";
            var marker = isClose ? "⚠ " : "  ";

            console.MarkupLine(
                $"[{colour}]{marker}{Markup.Escape(match.Describe())}[/]"
                + $"　{Markup.Escape(match.Evidence.Timestamp!.Value.ToString("yyyy-MM-dd HH:mm:ss"))}"
                + $"　{Markup.Escape(match.Finding.Id)} {Markup.Escape(match.Label)}"
                + $"：{Markup.Escape(match.Evidence.Value)}");
        }
    }

    private void WriteForensicNotice(AuditReport report)
    {
        console.WriteLine();
        console.MarkupLine("[bold]取證保存提醒[/]");
        console.MarkupLine("[grey]1. 在執行任何清除或重灌前，先完整保存本報告的 JSON 與 HTML。[/]");
        console.MarkupLine("[grey]2. 建議另行匯出原始事件記錄：[/]");
        console.MarkupLine("[grey]   wevtutil epl Security .\\Security-backup.evtx[/]");
        console.MarkupLine("[grey]3. 報案時需提供：時間點、來源 IP、遊戲內損失清單、官方 1:1 客服單號。[/]");

        console.WriteLine();
        console.MarkupLine(
            $"[grey]LcAudit v{Markup.Escape(report.ToolVersion)}"
            + $"　掃描於 {Markup.Escape(report.ScannedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"))}"
            + $"　主機 {Markup.Escape(report.Host.ComputerName)}[/]");
    }

    private static Color ParseColour(string name) => name switch
    {
        "green" => Color.Green,
        "yellow" => Color.Yellow,
        "darkorange" => Color.DarkOrange,
        "red" => Color.Red,
        _ => Color.Default,
    };
}
