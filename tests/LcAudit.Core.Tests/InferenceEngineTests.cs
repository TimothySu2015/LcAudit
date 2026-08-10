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
    public void 假紫P任一項判Fail即觸發R1(string id)
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
    public void 防毒兩項須同時命中且即時防護確實關閉才觸發R2()
    {
        // 只有排除清單存在（Warning）不足以斷定防毒「被主動停用」
        Assert.DoesNotContain("R2", RuleIdsFor(TestFindings.Warning("M3-10", Severity.High)));
        Assert.DoesNotContain("R2", RuleIdsFor(
            TestFindings.Warning("M3-10", Severity.High),
            TestFindings.Warning("M3-11", Severity.High)));

        Assert.Contains("R2", RuleIdsFor(
            TestFindings.Warning("M3-10", Severity.High),
            TestFindings.Fail("M3-11", Severity.High)));
    }

    [Fact]
    public void 單獨的遠端登入或帳號異動都不觸發R3()
    {
        Assert.DoesNotContain("R3", RuleIdsFor(TestFindings.Warning("M2-01", Severity.High)));
        Assert.DoesNotContain("R3", RuleIdsFor(TestFindings.Warning("M3-04", Severity.High)));
    }

    /// <summary>
    /// 沒有爆破或公網登入跡證時，只能說「值得核對」，不能宣告「遭爆破」。
    /// <para>
    /// 實測一台正常使用公司 RDP 的筆電就會命中這個組合，原本會被拉到「高」
    /// 並宣告「RDP 遭爆破」—— 但 M2-03（登入失敗爆量）根本沒命中。
    /// </para>
    /// </summary>
    [Fact]
    public void 沒有爆破跡證時R3降為保留語氣且等級下限為中()
    {
        var inferences = _engine.Infer(
        [
            TestFindings.Warning("M2-01", Severity.High),
            TestFindings.Warning("M3-04", Severity.High),
        ]);

        var r3 = Assert.Single(inferences, i => i.RuleId.StartsWith("R3", StringComparison.Ordinal));
        Assert.Equal("R3-P", r3.RuleId);
        Assert.Equal(RiskLevel.Medium, r3.MinimumLevel);
        Assert.Contains("正常遠端使用", r3.Conclusion);
    }

    [Theory]
    [InlineData("M2-02")]   // 來自公網的網路登入
    [InlineData("M2-03")]   // 登入失敗爆量
    public void 有爆破或公網登入跡證時R3才宣告遭爆破(string evidenceId)
    {
        var inferences = _engine.Infer(
        [
            TestFindings.Warning("M2-01", Severity.High),
            TestFindings.Warning("M3-04", Severity.High),
            TestFindings.Fail(evidenceId, Severity.High),
        ]);

        var r3 = Assert.Single(inferences, i => i.RuleId.StartsWith("R3", StringComparison.Ordinal));
        Assert.Equal("R3", r3.RuleId);
        Assert.Equal(RiskLevel.High, r3.MinimumLevel);
        Assert.Contains("遭爆破", r3.Conclusion);
    }

    [Fact]
    public void 遠端工具有連入紀錄且M1乾淨才觸發R4()
        // Fail 代表確實有連入紀錄
        => Assert.Contains("R4", RuleIdsFor(
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Fail("M2-06", Severity.High)));

    /// <summary>
    /// 「偵測到 AnyDesk 已安裝但沒有任何連入紀錄」是 Warning，代表「值得問一下」，
    /// 不代表「遭入侵」。用它下 R4 的結論是過度推論。
    /// </summary>
    [Fact]
    public void 只是裝了遠端工具但沒有連入紀錄不觸發R4()
        => Assert.DoesNotContain("R4", RuleIdsFor(
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Warning("M2-06", Severity.High)));

    /// <summary>
    /// <b>關鍵回歸測試。</b>
    /// <para>
    /// 真實案例：一台紫P 完全正版的機器（M1-01/M1-02 皆 Pass），只因為 M1-04 是
    /// Warning（安裝程式解壓出來的檔案本來就沒有 MOTW），就被推論為「假紫P，
    /// 端點已不可信，建議直接重灌」。使用者若照做就是白白重灌一台乾淨的電腦。
    /// </para>
    /// </summary>
    [Fact]
    public void M1只有Warning不得觸發假紫P推論()
    {
        var ruleIds = RuleIdsFor(
            TestFindings.Pass("M1-01", Severity.Critical),
            TestFindings.Pass("M1-02", Severity.Critical),
            TestFindings.Warning("M1-04", Severity.Critical));

        Assert.DoesNotContain("R1", ruleIds);
    }

    [Fact]
    public void M1_04為Fail時仍會觸發假紫P推論()
        => Assert.Contains("R1", RuleIdsFor(TestFindings.Fail("M1-04", Severity.Critical)));

    [Fact]
    public void M1判Fail時不觸發R4以免歸因錯誤()
    {
        // 紫P 本身就是假的，入侵途徑應歸因於 R1，不該說是遠端工具被入侵
        var ruleIds = RuleIdsFor(
            TestFindings.Fail("M1-01", Severity.Critical),
            TestFindings.Fail("M2-06", Severity.High));

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

        // 沒有爆破跡證，第三條走保留語氣的 R3-P
        Assert.Equal(["R1", "R2", "R3-P"], ruleIds);
    }

    [Fact]
    public void 空清單視為全數Pass()
        => Assert.Equal(["R5"], RuleIdsFor());
}
