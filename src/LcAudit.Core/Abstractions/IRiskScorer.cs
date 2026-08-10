using LcAudit.Core.Model;

namespace LcAudit.Core.Abstractions;

/// <summary>風險評分（功能規格 S-01～S-05）。</summary>
public interface IRiskScorer
{
    /// <param name="inferences">
    /// 推論引擎的結論。成立的推論會替風險等級設下限 ——
    /// 加總式評分無法表達「組合的意義大於各項相加」，那正是 S-06 的職責。
    /// </param>
    ScoreResult Score(IReadOnlyList<Finding> findings, IReadOnlyList<Inference> inferences);
}
