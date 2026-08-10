using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Pipeline;
using LcAudit.Core.Scoring;
using Xunit;

namespace LcAudit.Core.Tests;

public sealed class AuditRunnerTests
{
    private static AuditRunner Runner(params ICheck[] checks)
        => new(checks, new RiskScorer(), new InferenceEngine());

    private static AuditContext Context(params string[] skippedModules) => new()
    {
        IsElevated = true,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(skippedModules, StringComparer.OrdinalIgnoreCase),
    };

    [Fact]
    public async Task 依檢查項編號排序執行()
    {
        var result = await Runner(
            FakeCheck.Returning("M4-01"),
            FakeCheck.Returning("M1-00"),
            FakeCheck.Returning("M2-03"),
            FakeCheck.Returning("M1-01")).RunAsync(Context());

        Assert.Equal(["M1-00", "M1-01", "M2-03", "M4-01"], result.Findings.Select(f => f.Id));
    }

    [Fact]
    public async Task 跳過的模組不執行但仍產生Skipped紀錄()
    {
        var m3 = FakeCheck.Returning("M3-01", CheckStatus.Fail, Severity.High);
        var m1 = FakeCheck.Returning("M1-01", CheckStatus.Fail, Severity.High);

        var result = await Runner(m1, m3).RunAsync(Context("M3"));

        Assert.Equal(0, m3.ExecutionCount);
        Assert.Equal(1, m1.ExecutionCount);

        var skipped = Assert.Single(result.Findings, f => f.Id == "M3-01");
        Assert.Equal(CheckStatus.Skipped, skipped.Status);
        Assert.Equal(0, skipped.Score);
    }

    [Fact]
    public async Task 跳過模組時總分維持絕對100分制()
    {
        // TC-08：跳過的項目計 0 分，而非重新計算滿分比例。
        // 若採相對計分，這裡的 M3-01 被跳過後 M1-01 會變成「滿分的 100%」，
        // 反而拉高分數 —— 那才是危險的誤導。
        var result = await Runner(
            FakeCheck.Returning("M1-01", CheckStatus.Fail, Severity.High),
            FakeCheck.Returning("M3-01", CheckStatus.Fail, Severity.Critical)).RunAsync(Context("M3"));

        Assert.Equal(20, result.Summary.Score);
        Assert.Equal(RiskLevel.Medium, result.Summary.Level);
        Assert.Equal(0, result.Summary.CriticalHits);
    }

    [Fact]
    public async Task 跳過模組時摘要必須帶覆蓋率註記()
    {
        var result = await Runner(FakeCheck.Returning("M3-01")).RunAsync(Context("M3", "M4"));

        Assert.NotNull(result.Summary.CoverageNote);
        Assert.Contains("M3", result.Summary.CoverageNote);
        Assert.Contains("M4", result.Summary.CoverageNote);
        Assert.Contains("不代表這些面向安全", result.Summary.CoverageNote);
    }

    [Fact]
    public async Task 未跳過任何模組時不帶覆蓋率註記()
    {
        var result = await Runner(FakeCheck.Returning("M1-01")).RunAsync(Context());

        Assert.Null(result.Summary.CoverageNote);
    }

    [Fact]
    public async Task 摘要帶入推論結論()
    {
        var result = await Runner(
            FakeCheck.Returning("M1-01", CheckStatus.Fail, Severity.Critical)).RunAsync(Context());

        Assert.Equal("R1", result.Summary.Inferences[0].RuleId);
        Assert.Contains("端點已不可信", result.Summary.PrimaryInference);
        Assert.Equal(RiskLevel.Extreme, result.Summary.Level);
    }

    [Fact]
    public async Task 沒有任何檢查項時不拋例外()
    {
        var result = await Runner().RunAsync(Context());

        Assert.Empty(result.Findings);
        Assert.Equal(RiskLevel.Low, result.Summary.Level);
    }

    [Fact]
    public async Task 取消會中止流程()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Runner(FakeCheck.Returning("M1-01")).RunAsync(Context(), cts.Token));
    }
}
