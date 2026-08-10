using LcAudit.Core.Model;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>功能規格 S-01 / S-02：Severity 即分數，Fail 計 100%、Warning 計 50%。</summary>
public sealed class FindingScoreTests
{
    [Theory]
    [InlineData(Severity.Critical, 40)]
    [InlineData(Severity.High, 20)]
    [InlineData(Severity.Medium, 10)]
    [InlineData(Severity.Low, 5)]
    [InlineData(Severity.Info, 0)]
    public void Severity列舉底值即為分數(Severity severity, int expected)
        => Assert.Equal(expected, (int)severity);

    [Theory]
    [InlineData(Severity.Critical, 40)]
    [InlineData(Severity.High, 20)]
    [InlineData(Severity.Medium, 10)]
    [InlineData(Severity.Low, 5)]
    [InlineData(Severity.Info, 0)]
    public void Fail計滿分(Severity severity, int expected)
        => Assert.Equal(expected, TestFindings.Fail("M1-01", severity).Score);

    [Theory]
    [InlineData(Severity.Critical, 20)]
    [InlineData(Severity.High, 10)]
    [InlineData(Severity.Medium, 5)]
    [InlineData(Severity.Low, 2)]   // 整數除法截斷，刻意行為
    [InlineData(Severity.Info, 0)]
    public void Warning計半分(Severity severity, int expected)
        => Assert.Equal(expected, TestFindings.Warning("M1-01", severity).Score);

    [Theory]
    [InlineData(CheckStatus.Pass)]
    [InlineData(CheckStatus.Inconclusive)]
    [InlineData(CheckStatus.Skipped)]
    public void 其餘狀態不計分(CheckStatus status)
        => Assert.Equal(0, TestFindings.Create("M1-01", Severity.Critical, status).Score);

    [Theory]
    [InlineData(CheckStatus.Fail, true)]
    [InlineData(CheckStatus.Warning, true)]
    [InlineData(CheckStatus.Pass, false)]
    [InlineData(CheckStatus.Inconclusive, false)]
    [InlineData(CheckStatus.Skipped, false)]
    public void IsHit僅涵蓋Fail與Warning(CheckStatus status, bool expected)
        => Assert.Equal(expected, TestFindings.Create("M1-01", Severity.High, status).IsHit);
}
