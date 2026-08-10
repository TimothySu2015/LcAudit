using System.Text;
using LcAudit.Core.Model;
using LcAudit.Reporting;
using Xunit;

namespace LcAudit.Core.Tests;

public sealed class ReportWriterTests : IDisposable
{
    private readonly DirectoryInfo _output = new(
        Path.Combine(Path.GetTempPath(), $"LcAuditTest-{Guid.NewGuid():N}"));

    private readonly ReportWriter _writer = new(new HtmlReporter(), new JsonReporter());

    private static AuditReport Report(string computerName = "PC-01") => new()
    {
        ScannedAt = new DateTimeOffset(2026, 8, 10, 14, 30, 5, TimeSpan.FromHours(8)),
        IsElevated = true,
        Host = new HostInfo { ComputerName = computerName, OsVersion = "Windows 11", TimeZone = "Taipei" },
        Summary = new AuditSummary
        {
            Score = 0,
            RawScore = 0,
            Level = RiskLevel.Low,
            CriticalHits = 0,
            Inferences = [],
            SkippedModules = new HashSet<string>(),
        },
        Findings =
        [
            new Finding
            {
                Id = "M1-01",
                Module = "M1",
                Title = "主程式數位簽章狀態",
                Severity = Severity.Critical,
                Status = CheckStatus.Pass,
                Source = "WinVerifyTrust",
            },
        ],
    };

    public void Dispose()
    {
        if (_output.Exists)
        {
            _output.Delete(recursive: true);
        }
    }

    [Fact]
    public void 檔名符合功能規格8_2()
        => Assert.Equal("LcAudit-PC-01-20260810-143005", ReportWriter.BuildBaseName(Report()));

    [Fact]
    public void 電腦名稱的非法字元會被取代()
    {
        var name = ReportWriter.BuildBaseName(Report("PC:/\\*?01"));

        Assert.DoesNotContain(':', name);
        Assert.DoesNotContain('/', name);
        Assert.DoesNotContain('*', name);
    }

    [Fact]
    public void Html格式只寫出html檔()
    {
        var written = _writer.Write(Report(), _output, ReportFormat.Html);

        var path = Assert.Single(written);
        Assert.EndsWith(".html", path, StringComparison.Ordinal);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void All格式寫出html與json()
    {
        var written = _writer.Write(Report(), _output, ReportFormat.All);

        Assert.Equal(2, written.Count);
        Assert.Contains(written, p => p.EndsWith(".html", StringComparison.Ordinal));
        Assert.Contains(written, p => p.EndsWith(".json", StringComparison.Ordinal));
    }

    [Fact]
    public void 只選Console時不寫出任何檔案()
    {
        var written = _writer.Write(Report(), _output, ReportFormat.Console);

        Assert.Empty(written);
        // NFR-03：不需要輸出檔時，連目錄都不該建立
        Assert.False(_output.Exists);
    }

    [Fact]
    public void 輸出目錄不存在時自動建立()
    {
        Assert.False(_output.Exists);

        _writer.Write(Report(), _output, ReportFormat.Html);

        Assert.True(Directory.Exists(_output.FullName));
    }

    [Fact]
    public void 輸出為UTF8含BOM()
    {
        // NFR-08：舊版工具與 Excel 開啟繁中檔案才不會亂碼
        var path = _writer.Write(Report(), _output, ReportFormat.Html).Single();

        var head = new byte[3];
        using (var stream = File.OpenRead(path))
        {
            _ = stream.Read(head, 0, 3);
        }

        Assert.Equal(Encoding.UTF8.GetPreamble(), head);
    }

    [Fact]
    public void 繁體中文內容不會亂碼()
    {
        var path = _writer.Write(Report(), _output, ReportFormat.Html).Single();

        Assert.Contains("主程式數位簽章狀態", File.ReadAllText(path, Encoding.UTF8), StringComparison.Ordinal);
    }

    [Fact]
    public void Json保留繁中可讀性且跳脫HTML敏感字元()
    {
        var json = new JsonReporter().Render(Report());

        Assert.Contains("主程式數位簽章狀態", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\\u4E3B", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Json以字串輸出列舉而非數字()
    {
        var json = new JsonReporter().Render(Report());

        Assert.Contains("\"Critical\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Pass\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void 只寫入指定的輸出目錄()
    {
        // NFR-03：除 --output 外不得寫入任何路徑
        var written = _writer.Write(Report(), _output, ReportFormat.All);

        Assert.All(written, p =>
            Assert.StartsWith(_output.FullName, Path.GetFullPath(p), StringComparison.OrdinalIgnoreCase));
    }
}
