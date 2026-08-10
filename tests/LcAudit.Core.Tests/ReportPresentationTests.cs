using LcAudit.Core.Model;
using LcAudit.Reporting;
using Xunit;

namespace LcAudit.Core.Tests;

public sealed class ReportPresentationTests
{
    [Theory]
    [InlineData(RiskLevel.Low, "低")]
    [InlineData(RiskLevel.Medium, "中")]
    [InlineData(RiskLevel.High, "高")]
    [InlineData(RiskLevel.Extreme, "極高")]
    public void 風險等級文字符合功能規格S04(RiskLevel level, string expected)
        => Assert.Equal(expected, ReportPresentation.LevelText(level));

    [Fact]
    public void 所有RiskLevel都有對應文字()
    {
        // 新增列舉成員卻忘了補對照時，這個測試會抓到
        foreach (var level in Enum.GetValues<RiskLevel>())
        {
            Assert.NotEqual("未知", ReportPresentation.LevelText(level));
        }
    }

    [Fact]
    public void 所有CheckStatus都有對應文字與顏色()
    {
        foreach (var status in Enum.GetValues<CheckStatus>())
        {
            Assert.NotEqual("未知", ReportPresentation.StatusText(status));
            Assert.NotEqual("default", ReportPresentation.StatusColour(status));
        }
    }

    [Theory]
    [InlineData(CheckStatus.Fail, "red")]
    [InlineData(CheckStatus.Warning, "yellow")]
    [InlineData(CheckStatus.Pass, "green")]
    [InlineData(CheckStatus.Inconclusive, "grey")]
    public void 配色符合功能規格8_1(CheckStatus status, string expected)
        => Assert.Equal(expected, ReportPresentation.StatusColour(status));
}
