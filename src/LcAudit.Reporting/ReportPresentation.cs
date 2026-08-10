using LcAudit.Core.Model;

namespace LcAudit.Reporting;

/// <summary>
/// 報告的顯示用字串與配色（功能規格 §8.1）。
/// <para>純函式，不相依任何輸出裝置，可單元測試。</para>
/// </summary>
public static class ReportPresentation
{
    public static string LevelText(RiskLevel level) => level switch
    {
        RiskLevel.Low => "低",
        RiskLevel.Medium => "中",
        RiskLevel.High => "高",
        RiskLevel.Extreme => "極高",
        _ => "未知",
    };

    public static string StatusText(CheckStatus status) => status switch
    {
        CheckStatus.Pass => "通過",
        CheckStatus.Warning => "警告",
        CheckStatus.Fail => "異常",
        CheckStatus.Inconclusive => "無法判定",
        CheckStatus.Skipped => "已跳過",
        _ => "未知",
    };

    /// <summary>Spectre.Console 的色彩標記名稱。</summary>
    public static string StatusColour(CheckStatus status) => status switch
    {
        CheckStatus.Pass => "green",
        CheckStatus.Warning => "yellow",
        CheckStatus.Fail => "red",
        CheckStatus.Inconclusive => "grey",
        CheckStatus.Skipped => "grey",
        _ => "default",
    };

    public static string LevelColour(RiskLevel level) => level switch
    {
        RiskLevel.Low => "green",
        RiskLevel.Medium => "yellow",
        RiskLevel.High => "darkorange",
        RiskLevel.Extreme => "red",
        _ => "default",
    };
}
