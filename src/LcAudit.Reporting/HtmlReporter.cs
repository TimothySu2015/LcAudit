using System.Net;
using System.Text;
using LcAudit.Core.Model;

namespace LcAudit.Reporting;

/// <summary>
/// HTML 報告（功能規格 §8.3）：單一自包含檔案，CSS 全部 inline，無任何外部資源。
/// <para>
/// <b>所有插入 HTML 的值都必須經過 <see cref="Esc"/>。</b>
/// 報告內容大量來自攻擊者可控的資料 —— Security 4625 的帳號名稱是嘗試登入者自己填的、
/// 檔名可以任意命名。若不跳脫，一個叫 <c>&lt;script&gt;…&lt;/script&gt;.exe</c> 的檔案
/// 就能在被害者開啟報告時執行指令碼。稽核工具產出的報告本身變成攻擊載體，是最難看的失敗。
/// </para>
/// <para>
/// 折疊用 <c>&lt;details&gt;</c> 原生元素，不寫 JavaScript —— 沒有腳本就沒有腳本漏洞，
/// 也符合「完全離線、自包含」的要求。
/// </para>
/// </summary>
public sealed class HtmlReporter
{
    public string Render(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var sb = new StringBuilder(16 * 1024);

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"zh-Hant\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine($"<title>LcAudit 稽核報告 - {Esc(report.Host.ComputerName)}</title>");
        AppendStyle(sb);
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        AppendHeader(sb, report);
        AppendSummaryCard(sb, report.Summary);
        AppendHostInfo(sb, report);
        AppendTimeline(sb, report.Findings);
        AppendFindings(sb, report.Findings);
        AppendForensicNotice(sb, report);

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static void AppendStyle(StringBuilder sb)
    {
        sb.AppendLine("""
            <style>
            :root { color-scheme: light dark; }
            * { box-sizing: border-box; }
            body { font-family: "Segoe UI", "Microsoft JhengHei", system-ui, sans-serif;
                   margin: 0; padding: 2rem 1rem; background: #f5f6f8; color: #1a1a1a; line-height: 1.6; }
            .wrap { max-width: 1100px; margin: 0 auto; }
            h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
            h2 { font-size: 1.2rem; margin: 2rem 0 .75rem; padding-bottom: .35rem; border-bottom: 2px solid #d9dce1; }
            .meta { color: #5a6068; font-size: .9rem; margin-bottom: 1.5rem; }
            .card { border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1rem;
                    border: 1px solid #d9dce1; background: #fff; }
            .level { color: #fff; border: none; }
            .level h2 { border: none; margin: 0; color: #fff; font-size: 1.05rem; }
            .level .score { font-size: 2.4rem; font-weight: 700; line-height: 1.2; }
            .level-low { background: #2e7d32; }
            .level-medium { background: #d68910; }
            .level-high { background: #d35400; }
            .level-extreme { background: #b71c1c; }
            .inference { margin-top: .75rem; padding-top: .75rem; border-top: 1px solid rgba(255,255,255,.35); }
            .notice { background: #fff8e1; border-color: #f0c36d; }
            table { width: 100%; border-collapse: collapse; background: #fff; font-size: .92rem; }
            th, td { padding: .5rem .7rem; text-align: left; border-bottom: 1px solid #e3e6ea; vertical-align: top; }
            th { background: #eceef1; font-weight: 600; white-space: nowrap; }
            td.num { text-align: right; white-space: nowrap; }
            .tag { display: inline-block; padding: .1rem .55rem; border-radius: 999px;
                   font-size: .82rem; font-weight: 600; white-space: nowrap; color: #fff; }
            .tag-pass { background: #2e7d32; }
            .tag-warning { background: #d68910; }
            .tag-fail { background: #c62828; }
            .tag-inconclusive { background: #78838f; }
            .tag-skipped { background: #9aa3ac; }
            details { background: #fff; border: 1px solid #d9dce1; border-radius: 8px;
                      padding: .6rem 1rem; margin-bottom: .5rem; }
            details[open] { padding-bottom: 1rem; }
            summary { cursor: pointer; font-weight: 600; }
            .desc { margin: .6rem 0; }
            .rec { background: #e8f1fb; border-left: 4px solid #2a6fb5; padding: .5rem .8rem; margin: .6rem 0; }
            .ev { font-family: Consolas, "Cascadia Mono", monospace; font-size: .85rem;
                  background: #f2f4f6; border-radius: 6px; padding: .5rem .8rem; margin-top: .5rem;
                  overflow-x: auto; }
            .ev div { padding: .1rem 0; }
            .ev .k { color: #5a6068; }
            .empty { color: #78838f; font-style: italic; }
            footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #d9dce1;
                     color: #5a6068; font-size: .85rem; }
            @media (prefers-color-scheme: dark) {
              body { background: #16181c; color: #e6e8ea; }
              .card, table, details, .ev { background: #21242a; }
              th { background: #2b2f36; }
              th, td { border-bottom-color: #343941; }
              .card, details { border-color: #343941; }
              h2 { border-bottom-color: #343941; }
              .ev { background: #1a1d22; }
              .rec { background: #1c2c3d; }
              .notice { background: #302a15; border-color: #6b5a2a; }
              .meta, .ev .k, footer, .empty { color: #9aa3ac; }
            }
            @media print { body { background: #fff; } details { break-inside: avoid; } }
            </style>
            """);
    }

    private static void AppendHeader(StringBuilder sb, AuditReport report)
    {
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("<h1>天堂：經典版 帳號安全稽核報告</h1>");
        sb.AppendLine($"""
            <div class="meta">掃描時間 {Esc(report.ScannedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"))}
            ｜主機 {Esc(report.Host.ComputerName)}
            ｜{(report.IsElevated ? "已以系統管理員執行" : "未提權執行（部分項目無法判定）")}
            ｜LcAudit v{Esc(report.ToolVersion)}</div>
            """);
    }

    private static void AppendSummaryCard(StringBuilder sb, AuditSummary summary)
    {
        var levelClass = summary.Level switch
        {
            RiskLevel.Low => "level-low",
            RiskLevel.Medium => "level-medium",
            RiskLevel.High => "level-high",
            _ => "level-extreme",
        };

        sb.AppendLine($"<div class=\"card level {levelClass}\">");
        sb.AppendLine($"<h2>風險等級</h2>");
        sb.AppendLine($"<div class=\"score\">{Esc(ReportPresentation.LevelText(summary.Level))}　{summary.Score} / 100</div>");

        if (summary.CriticalHits > 0)
        {
            sb.AppendLine($"<div>命中 {summary.CriticalHits} 項 Critical，等級已強制為「極高」。</div>");
        }

        if (summary.RawScore > summary.Score)
        {
            sb.AppendLine($"<div>原始加總 {summary.RawScore} 分，已套用 100 分上限。</div>");
        }

        foreach (var inference in summary.Inferences)
        {
            var matched = inference.MatchedCheckIds.Count > 0
                ? $"（{string.Join("、", inference.MatchedCheckIds)}）"
                : string.Empty;
            sb.AppendLine($"<div class=\"inference\"><strong>最可能途徑：</strong>{Esc(inference.Conclusion)}{Esc(matched)}</div>");
        }

        sb.AppendLine("</div>");

        if (summary.CoverageNote is not null)
        {
            sb.AppendLine($"<div class=\"card notice\">{Esc(summary.CoverageNote)}</div>");
        }
    }

    private static void AppendHostInfo(StringBuilder sb, AuditReport report)
    {
        sb.AppendLine("<h2>受檢主機</h2>");
        sb.AppendLine("<table><tbody>");
        AppendRow(sb, "電腦名稱", report.Host.ComputerName);
        AppendRow(sb, "作業系統", report.Host.OsVersion);
        AppendRow(sb, "時區", report.Host.TimeZone);
        AppendRow(sb, "報告格式版本", report.SchemaVersion);
        sb.AppendLine("</tbody></table>");

        static void AppendRow(StringBuilder sb, string key, string value)
            => sb.AppendLine($"<tr><th>{Esc(key)}</th><td>{Esc(value)}</td></tr>");
    }

    /// <summary>中段：遠端存取時間軸（功能規格 §8.3）。取所有帶時間戳的證據，依時間排序。</summary>
    private static void AppendTimeline(StringBuilder sb, IReadOnlyList<Finding> findings)
    {
        var entries = findings
            .SelectMany(f => f.Evidence
                .Where(e => e.Timestamp.HasValue)
                .Select(e => (Finding: f, Evidence: e)))
            .OrderByDescending(x => x.Evidence.Timestamp!.Value)
            .Take(200)
            .ToList();

        sb.AppendLine("<h2>時間軸</h2>");

        if (entries.Count == 0)
        {
            sb.AppendLine("<p class=\"empty\">沒有帶時間點的跡證。</p>");
            return;
        }

        sb.AppendLine("<table><thead><tr><th>時間</th><th>來源項目</th><th>內容</th></tr></thead><tbody>");

        foreach (var (finding, evidence) in entries)
        {
            sb.AppendLine("<tr>"
                + $"<td>{Esc(evidence.Timestamp!.Value.ToString("yyyy-MM-dd HH:mm:ss"))}</td>"
                + $"<td>{Esc(finding.Id)} {Esc(finding.Title)}</td>"
                + $"<td>{Esc(evidence.Key)}：{Esc(evidence.Value)}</td>"
                + "</tr>");
        }

        sb.AppendLine("</tbody></table>");
    }

    private static void AppendFindings(StringBuilder sb, IReadOnlyList<Finding> findings)
    {
        foreach (var group in findings.GroupBy(f => f.Module).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            sb.AppendLine($"<h2>模組 {Esc(group.Key)}</h2>");
            sb.AppendLine("<table><thead><tr><th>項目</th><th>檢查內容</th><th>結果</th><th>分數</th></tr></thead><tbody>");

            foreach (var finding in group.OrderBy(f => f.Id, StringComparer.Ordinal))
            {
                sb.AppendLine("<tr>"
                    + $"<td>{Esc(finding.Id)}</td>"
                    + $"<td>{Esc(finding.Title)}</td>"
                    + $"<td>{StatusTag(finding.Status)}</td>"
                    + $"<td class=\"num\">{(finding.Score == 0 ? "–" : finding.Score.ToString())}</td>"
                    + "</tr>");
            }

            sb.AppendLine("</tbody></table>");

            // 明細可折疊。有問題的項目預設展開，通過的收合。
            foreach (var finding in group.OrderBy(f => f.Id, StringComparer.Ordinal))
            {
                AppendFindingDetail(sb, finding);
            }
        }
    }

    private static void AppendFindingDetail(StringBuilder sb, Finding finding)
    {
        var open = finding.Status is CheckStatus.Fail or CheckStatus.Warning ? " open" : string.Empty;

        sb.AppendLine($"<details{open}>");
        sb.AppendLine($"<summary>{Esc(finding.Id)}　{Esc(finding.Title)}　{StatusTag(finding.Status)}</summary>");

        if (!string.IsNullOrWhiteSpace(finding.Description))
        {
            sb.AppendLine($"<div class=\"desc\">{Esc(finding.Description)}</div>");
        }

        if (!string.IsNullOrWhiteSpace(finding.Recommendation))
        {
            sb.AppendLine($"<div class=\"rec\"><strong>建議：</strong>{Esc(finding.Recommendation)}</div>");
        }

        if (finding.Evidence.Count > 0)
        {
            sb.AppendLine("<div class=\"ev\">");
            foreach (var evidence in finding.Evidence)
            {
                sb.AppendLine($"<div><span class=\"k\">{Esc(evidence.Key)}：</span>{Esc(evidence.Value)}</div>");
            }
            sb.AppendLine("</div>");
        }

        sb.AppendLine($"<div class=\"meta\">資料來源：{Esc(finding.Source)}"
                      + $"｜嚴重度：{Esc(finding.Severity.ToString())}"
                      + $"｜擷取時間：{Esc(finding.CollectedAt.ToString("yyyy-MM-dd HH:mm:ss"))}</div>");
        sb.AppendLine("</details>");
    }

    /// <summary>底部固定區塊：取證保存提醒（功能規格 §10）。</summary>
    private static void AppendForensicNotice(StringBuilder sb, AuditReport report)
    {
        sb.AppendLine("""
            <h2>取證保存提醒</h2>
            <div class="card notice">
            <ol>
            <li>在執行任何清除、隔離或重灌前，先完整保存本報告的 JSON 與 HTML。</li>
            <li>建議另行匯出原始事件記錄：
            <div class="ev"><div>wevtutil epl Security .\Security-backup.evtx</div>
            <div>wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" .\TS-backup.evtx</div></div>
            </li>
            <li>報案時需一併提供：時間點、來源 IP、遊戲內損失清單、官方 1:1 客服單號。</li>
            </ol>
            </div>
            """);

        sb.AppendLine($"""
            <footer>
            本報告由 <strong>LcAudit v{Esc(report.ToolVersion)}</strong> 於
            {Esc(report.ScannedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"))} 產生
            （報告格式版本 {Esc(report.SchemaVersion)}）。全程唯讀蒐證，未對受檢系統做任何修改。<br>
            檢查項目判定為「通過」不代表未被入侵 —— 具管理員權限的攻擊者可清除事件記錄，
            rootkit 等級的隱藏也無法以使用者模式 API 偵測。
            </footer>
            </div>
            """);
    }

    private static string StatusTag(CheckStatus status)
    {
        var cls = status switch
        {
            CheckStatus.Pass => "tag-pass",
            CheckStatus.Warning => "tag-warning",
            CheckStatus.Fail => "tag-fail",
            CheckStatus.Inconclusive => "tag-inconclusive",
            _ => "tag-skipped",
        };

        return $"<span class=\"tag {cls}\">{Esc(ReportPresentation.StatusText(status))}</span>";
    }

    /// <summary>HTML 跳脫。所有插入文件的外部資料都必須經過這裡，無一例外。</summary>
    private static string Esc(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
