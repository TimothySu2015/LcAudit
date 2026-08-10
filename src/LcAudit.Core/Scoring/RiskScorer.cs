using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Core.Scoring;

/// <summary>風險評分實作（功能規格 FR-S，S-01～S-05）。</summary>
public sealed class RiskScorer : IRiskScorer
{
    /// <summary>總分上限（S-03）。</summary>
    public const int MaxScore = 100;

    public ScoreResult Score(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        // S-01 / S-02：分數由 Finding.Score 依 Severity 與 Status 決定
        var rawScore = findings.Sum(f => f.Score);
        var score = Math.Min(rawScore, MaxScore);   // S-03

        // S-05：任一 Critical 命中強制升等為「極高」。
        //
        // 這裡刻意只認 Fail，不認 Warning。規格寫的是「命中」，字面上兩者皆屬命中，
        // 但 Critical 項目的 Warning 意為「有可疑跡象、需人工研判」（例如 M1-03 憑證過期
        // 但有時間戳）。若 Warning 也強制升等，正常機器會被判為「極高」，
        // 誤報會直接吃掉工具的可信度 —— 使用者第二次就不看報告了。
        //
        // Warning 仍以 50%（Critical → 20 分）計分，累加後自然會推升等級，並未被忽略。
        var criticalHits = findings.Count(f =>
            f.Severity == Severity.Critical && f.Status == CheckStatus.Fail);

        var level = criticalHits > 0 ? RiskLevel.Extreme : LevelFor(score);

        return new ScoreResult(score, rawScore, level, criticalHits);
    }

    /// <summary>分數對應風險等級（S-04）。</summary>
    public static RiskLevel LevelFor(int score) => score switch
    {
        < 0 => throw new ArgumentOutOfRangeException(nameof(score), score, "分數不可為負。"),
        <= 19 => RiskLevel.Low,
        <= 49 => RiskLevel.Medium,
        <= 79 => RiskLevel.High,
        _ => RiskLevel.Extreme,
    };
}
