namespace LcAudit.Core.Model;

/// <summary>評分結果。</summary>
/// <param name="Score">套用上限後的總分（0–100，S-03）。</param>
/// <param name="RawScore">未套上限的原始加總，供報告顯示「遠超過 100」的嚴重程度。</param>
/// <param name="Level">風險等級（S-04；可能被 S-05 強制升等）。</param>
/// <param name="CriticalHits">觸發 S-05 強制升等的 Critical 項目數。</param>
/// <param name="LevelRaisedBy">
/// 等級被強制拉高的原因；未被拉高時為 <c>null</c>。
/// 報告必須說明「為什麼分數只有 10 分卻標示為高風險」，否則使用者會覺得工具在亂報。
/// </param>
public sealed record ScoreResult(
    int Score,
    int RawScore,
    RiskLevel Level,
    int CriticalHits,
    string? LevelRaisedBy = null);
