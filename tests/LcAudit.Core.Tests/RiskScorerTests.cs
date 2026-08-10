using LcAudit.Core.Model;
using LcAudit.Core.Scoring;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>功能規格 S-03 / S-04 / S-05。</summary>
public sealed class RiskScorerTests
{
    private readonly RiskScorer _scorer = new();

    [Theory]
    [InlineData(0, RiskLevel.Low)]
    [InlineData(19, RiskLevel.Low)]
    [InlineData(20, RiskLevel.Medium)]
    [InlineData(49, RiskLevel.Medium)]
    [InlineData(50, RiskLevel.High)]
    [InlineData(79, RiskLevel.High)]
    [InlineData(80, RiskLevel.Extreme)]
    [InlineData(100, RiskLevel.Extreme)]
    public void 等級邊界符合S04(int score, RiskLevel expected)
        => Assert.Equal(expected, RiskScorer.LevelFor(score));

    [Fact]
    public void 風險等級底值即結束代碼()
    {
        Assert.Equal(0, (int)RiskLevel.Low);
        Assert.Equal(1, (int)RiskLevel.Medium);
        Assert.Equal(2, (int)RiskLevel.High);
        Assert.Equal(3, (int)RiskLevel.Extreme);
    }

    [Fact]
    public void 總分上限為100且保留原始加總()
    {
        // 5 × High Fail = 100，再加 3 項應被上限截斷
        var findings = Enumerable.Range(1, 8)
            .Select(i => TestFindings.Fail($"M2-{i:00}", Severity.High))
            .ToList();

        var result = _scorer.Score(findings);

        Assert.Equal(100, result.Score);
        Assert.Equal(160, result.RawScore);
    }

    [Fact]
    public void 空清單為零分且等級為低()
    {
        var result = _scorer.Score([]);

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Equal(0, result.CriticalHits);
    }

    [Fact]
    public void CriticalFail強制升等為極高即使總分很低()
    {
        // 單一 Critical Fail = 40 分，本應為「中」，但 S-05 強制升等
        var result = _scorer.Score([TestFindings.Fail("M1-01", Severity.Critical)]);

        Assert.Equal(40, result.Score);
        Assert.Equal(RiskLevel.Extreme, result.Level);
        Assert.Equal(1, result.CriticalHits);
    }

    [Fact]
    public void CriticalWarning不強制升等()
    {
        // 刻意的判定：Warning 意為「需人工研判」，強制升等會產生大量誤報。
        // 20 分落在「中」，符合 S-04 的分數對應。
        var result = _scorer.Score([TestFindings.Warning("M1-03", Severity.Critical)]);

        Assert.Equal(20, result.Score);
        Assert.Equal(RiskLevel.Medium, result.Level);
        Assert.Equal(0, result.CriticalHits);
    }

    [Theory]
    [InlineData(CheckStatus.Pass)]
    [InlineData(CheckStatus.Inconclusive)]
    [InlineData(CheckStatus.Skipped)]
    public void 未命中的Critical不觸發強制升等(CheckStatus status)
    {
        var result = _scorer.Score([TestFindings.Create("M1-01", Severity.Critical, status)]);

        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Equal(0, result.CriticalHits);
    }

    [Fact]
    public void 多個CriticalFail全部計入CriticalHits()
    {
        var result = _scorer.Score(
        [
            TestFindings.Fail("M1-01", Severity.Critical),
            TestFindings.Fail("M1-02", Severity.Critical),
            TestFindings.Warning("M1-04", Severity.Critical),
        ]);

        Assert.Equal(2, result.CriticalHits);
        Assert.Equal(RiskLevel.Extreme, result.Level);
    }

    [Fact]
    public void 負分會拋出例外()
        => Assert.Throws<ArgumentOutOfRangeException>(() => RiskScorer.LevelFor(-1));
}
