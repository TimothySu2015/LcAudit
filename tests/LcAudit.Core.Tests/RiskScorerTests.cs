using LcAudit.Core.Model;
using LcAudit.Core.Scoring;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>功能規格 S-03 / S-04 / S-05。</summary>
public sealed class RiskScorerTests
{
    private readonly RiskScorer _scorer = new();

    /// <summary>大多數測試只關心加總與等級對應，不涉及推論下限。</summary>
    private ScoreResult Score(IReadOnlyList<Finding> findings) => _scorer.Score(findings, []);

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

        var result = Score(findings);

        Assert.Equal(100, result.Score);
        Assert.Equal(160, result.RawScore);
    }

    [Fact]
    public void 空清單為零分且等級為低()
    {
        var result = Score([]);

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Equal(0, result.CriticalHits);
    }

    [Fact]
    public void CriticalFail強制升等為極高即使總分很低()
    {
        // 單一 Critical Fail = 40 分，本應為「中」，但 S-05 強制升等
        var result = Score([TestFindings.Fail("M1-01", Severity.Critical)]);

        Assert.Equal(40, result.Score);
        Assert.Equal(RiskLevel.Extreme, result.Level);
        Assert.Equal(1, result.CriticalHits);
    }

    [Fact]
    public void CriticalWarning不強制升等()
    {
        // 刻意的判定：Warning 意為「需人工研判」，強制升等會產生大量誤報。
        // 20 分落在「中」，符合 S-04 的分數對應。
        var result = Score([TestFindings.Warning("M1-03", Severity.Critical)]);

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
        var result = Score([TestFindings.Create("M1-01", Severity.Critical, status)]);

        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Equal(0, result.CriticalHits);
    }

    [Fact]
    public void 多個CriticalFail全部計入CriticalHits()
    {
        var result = Score(
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

    // ---- 推論結論的等級下限 ----

    /// <summary>
    /// <b>關鍵回歸測試：紫P 正版但電腦被植入 AnyDesk。</b>
    /// <para>
    /// 只有一項 High 的命中，加總 10 分落在「低」(0–19)，結束代碼會是 0 ——
    /// 但推論結論明明是「遠端工具遭入侵」。報告會一邊說你被入侵、一邊在最顯眼處
    /// 標「低風險」，而且自動化腳本會判定沒問題。
    /// </para>
    /// <para>
    /// 加總式評分表達不了「組合的意義大於各項相加」，那正是 S-06 的職責，
    /// 所以推論結論必須能替等級設下限。
    /// </para>
    /// </summary>
    [Fact]
    public void 推論結論會把等級拉高到下限()
    {
        var findings = new[] { TestFindings.Fail("M2-06", Severity.High) };
        var inferences = new[]
        {
            new Inference("R4", "第三方遠端工具遭入侵", ["M2-06"], RiskLevel.High),
        };

        var result = _scorer.Score(findings, inferences);

        Assert.Equal(20, result.Score);
        Assert.Equal(RiskLevel.High, result.Level);   // 20 分本應是「中」
        Assert.Contains("R4", result.LevelRaisedBy);
    }

    [Fact]
    public void 單一High的Warning在沒有推論時仍是低風險()
    {
        // 對照組：證明問題確實出在「加總永遠出不了低」而非別處
        var result = Score([TestFindings.Warning("M2-06", Severity.High)]);

        Assert.Equal(10, result.Score);
        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Null(result.LevelRaisedBy);
    }

    [Fact]
    public void 分數已高於下限時不動等級()
    {
        var findings = Enumerable.Range(1, 5)
            .Select(i => TestFindings.Fail($"M3-{i:00}", Severity.High))
            .ToList();
        var inferences = new[] { new Inference("R4", "x", [], RiskLevel.High) };

        var result = _scorer.Score(findings, inferences);

        Assert.Equal(100, result.Score);
        Assert.Equal(RiskLevel.Extreme, result.Level);
        Assert.Null(result.LevelRaisedBy);   // 本來就是極高，不是被拉高的
    }

    [Fact]
    public void 多個推論取最高的下限()
    {
        var inferences = new[]
        {
            new Inference("R4", "x", [], RiskLevel.High),
            new Inference("R1", "y", [], RiskLevel.Extreme),
        };

        var result = _scorer.Score([], inferences);

        Assert.Equal(RiskLevel.Extreme, result.Level);
        Assert.Contains("R1", result.LevelRaisedBy);
    }

    [Fact]
    public void 全數Pass的推論不會拉高等級()
    {
        // R5「端點未見異常」的下限是 Low，不該影響任何東西
        var result = _scorer.Score([], [new Inference("R5", "端點未見異常", [])]);

        Assert.Equal(RiskLevel.Low, result.Level);
        Assert.Null(result.LevelRaisedBy);
    }

    [Fact]
    public void Critical強制升等的說明優先於推論()
    {
        var result = _scorer.Score(
            [TestFindings.Fail("M1-01", Severity.Critical)],
            [new Inference("R4", "x", [], RiskLevel.High)]);

        Assert.Equal(RiskLevel.Extreme, result.Level);
        Assert.Contains("Critical", result.LevelRaisedBy);
    }
}
