using LcAudit.Core.Model;
using LcAudit.Core.Scoring;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>功能規格 S-06 決策表。</summary>
public sealed class InferenceEngineTests
{
    private readonly InferenceEngine _engine = new();

    private IReadOnlyList<string> RuleIdsFor(params Finding[] findings)
        => [.. _engine.Infer(findings).Select(i => i.RuleId)];

    [Theory]
    [InlineData("M1-01")]
    [InlineData("M1-02")]
    [InlineData("M1-04")]
    public void 假紫P任一項命中即觸發R1(string id)
        => Assert.Contains("R1", RuleIdsFor(TestFindings.Fail(id, Severity.Critical)));

    [Fact]
    public void R1會記錄觸發的檢查項編號()
    {
        var inferences = _engine.Infer(
        [
            TestFindings.Fail("M1-01", Severity.Critical),
            TestFindings.Fail("M1-04", Severity.Critical),
        ]);

        var r1 = Assert.Single(inferences, i => i.RuleId == "R1");
        Assert.Equal(["M1-01", "M1-04"], r1.MatchedCheckIds);
    }

    [Fact]
    public void 防毒兩項須同時命中才觸發R2()
    {
        Assert.DoesNotContain("R2", RuleIdsFor(TestFindings.Warning("M3-10", Severity.High)));

        Assert.Contains("R2", RuleIdsFor(
            TestFindings.Warning("M3-10", Severity.High),
            TestFindings.Fail("M3-11", Severity.High)));
    }

    [Fact]
    public void 遠端登入加帳號異動才觸發R3()
    {
        Assert.DoesNotContain("R3", RuleIdsFor(TestFindings.Warning("M2-01", Severity.High)));
        Assert.DoesNotContain("R3", RuleIdsFor(TestFindings.Warning("M3-04", Severity.High)));

        Assert.Contains("R3", RuleIdsFor(
            TestFindings.Warning("M2-01", Severity.High),
            TestFindings.Warning("M3-04", Severity.High)));
    }

    [Fact]
    public void 遠端工具命中且M1乾淨才觸發R4()
        => Assert.Contains("R4", RuleIdsFor(
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Warning("M2-06", Severity.High)));

    [Fact]
    public void M1有命中時不觸發R4以免歸因錯誤()
    {
        // 紫P 本身就是假的，入侵途徑應歸因於 R1，不該說是遠端工具被入侵
        var ruleIds = RuleIdsFor(
            TestFindings.Fail("M1-01", Severity.Critical),
            TestFindings.Warning("M2-06", Severity.High));

        Assert.Contains("R1", ruleIds);
        Assert.DoesNotContain("R4", ruleIds);
    }

    [Fact]
    public void 全數Pass觸發R5()
    {
        var inferences = _engine.Infer(
        [
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Pass("M2-01", Severity.High),
        ]);

        var r5 = Assert.Single(inferences);
        Assert.Equal("R5", r5.RuleId);
        Assert.Contains("帳號側", r5.Conclusion);
    }

    [Fact]
    public void 有Inconclusive時改用保留語氣的R5P()
    {
        var inferences = _engine.Infer(
        [
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Inconclusive("M2-01", Severity.High),
        ]);

        var r5 = Assert.Single(inferences);
        Assert.Equal("R5-P", r5.RuleId);
        Assert.DoesNotContain("端點未見異常", r5.Conclusion);
    }

    [Fact]
    public void 有命中時不輸出R5()
    {
        var ruleIds = RuleIdsFor(TestFindings.Fail("M1-01", Severity.Critical));

        Assert.DoesNotContain("R5", ruleIds);
        Assert.DoesNotContain("R5-P", ruleIds);
    }

    [Fact]
    public void 多條規則同時成立時R1排在最前()
    {
        var ruleIds = RuleIdsFor(
            TestFindings.Fail("M1-01", Severity.Critical),
            TestFindings.Warning("M3-10", Severity.High),
            TestFindings.Fail("M3-11", Severity.High),
            TestFindings.Warning("M2-01", Severity.High),
            TestFindings.Warning("M3-04", Severity.High));

        Assert.Equal(["R1", "R2", "R3"], ruleIds);
    }

    [Fact]
    public void 空清單視為全數Pass()
        => Assert.Equal(["R5"], RuleIdsFor());
}
