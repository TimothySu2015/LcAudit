using LcAudit.Core.Model;

namespace LcAudit.Core.Abstractions;

/// <summary>風險評分（功能規格 S-01～S-05）。</summary>
public interface IRiskScorer
{
    ScoreResult Score(IReadOnlyList<Finding> findings);
}
