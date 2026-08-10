namespace LcAudit.Core.Model;

/// <summary>
/// 整體風險等級（功能規格 S-04）。
/// <para>
/// 列舉底值即 CLI 結束代碼（功能規格 §7.1）。這是 Console App 的對外契約，
/// 不可為了排版好看而重新編號。10 保留給「執行環境錯誤」，不屬於本列舉。
/// </para>
/// </summary>
public enum RiskLevel
{
    /// <summary>0–19 低</summary>
    Low = 0,

    /// <summary>20–49 中</summary>
    Medium = 1,

    /// <summary>50–79 高</summary>
    High = 2,

    /// <summary>80–100 極高；亦由 S-05 的 Critical 強制升等產生</summary>
    Extreme = 3,
}
