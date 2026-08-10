using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Core.Scoring;

/// <summary>風險評分實作（功能規格 FR-S，S-01～S-05）。</summary>
public sealed class RiskScorer : IRiskScorer
{
    /// <summary>總分上限（S-03）。</summary>
    public const int MaxScore = 100;

    public ScoreResult Score(IReadOnlyList<Finding> findings, IReadOnlyList<Inference> inferences)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(inferences);

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
        string? raisedBy = criticalHits > 0 ? $"命中 {criticalHits} 項 Critical" : null;

        // 推論結論設下限。
        //
        // 沒有這一段會出現這種報告：紫P 完全正版、只有一項 AnyDesk 連入紀錄，
        // 加起來 10 分落在「低」，結束代碼 0，但推論結論寫著「遠端工具遭入侵」——
        // 一邊說你被入侵、一邊在最顯眼處標「低風險」。矛盾的方向還是危險的那一邊。
        //
        // 加總式評分本來就表達不了「組合的意義大於各項相加」，那正是 S-06 的職責，
        // 所以它的結論必須能回饋到等級。
        var floor = inferences.Count == 0
            ? RiskLevel.Low
            : inferences.Max(i => i.MinimumLevel);

        if (floor > level)
        {
            var trigger = inferences.First(i => i.MinimumLevel == floor);
            level = floor;
            raisedBy = $"推論規則 {trigger.RuleId} 成立";
        }

        return new ScoreResult(score, rawScore, level, criticalHits, raisedBy);
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
