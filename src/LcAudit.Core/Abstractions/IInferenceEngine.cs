using LcAudit.Core.Model;

namespace LcAudit.Core.Abstractions;

/// <summary>入侵途徑推論（功能規格 S-06）。</summary>
public interface IInferenceEngine
{
    /// <summary>回傳所有成立的推論，依嚴重度排序，最該先看的在前。</summary>
    IReadOnlyList<Inference> Infer(IReadOnlyList<Finding> findings);
}
