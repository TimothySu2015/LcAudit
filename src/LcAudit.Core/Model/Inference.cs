namespace LcAudit.Core.Model;

/// <summary>
/// 推論引擎的單條結論（功能規格 S-06）。
/// </summary>
/// <param name="RuleId">規則編號，如 <c>"R1"</c>，供報告與測試對照。</param>
/// <param name="Conclusion">給使用者看的結論敘述。</param>
/// <param name="MatchedCheckIds">觸發本規則的檢查項編號，讓使用者能回頭查證。</param>
public sealed record Inference(
    string RuleId,
    string Conclusion,
    IReadOnlyList<string> MatchedCheckIds);
