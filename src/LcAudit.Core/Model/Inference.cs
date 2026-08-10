namespace LcAudit.Core.Model;

/// <summary>
/// 推論引擎的單條結論（功能規格 S-06）。
/// </summary>
/// <param name="RuleId">規則編號，如 <c>"R1"</c>，供報告與測試對照。</param>
/// <param name="Conclusion">給使用者看的結論敘述。</param>
/// <param name="MatchedCheckIds">觸發本規則的檢查項編號，讓使用者能回頭查證。</param>
/// <param name="MinimumLevel">
/// 本推論成立時的風險等級下限。
/// <para>
/// 加總式評分無法表達「組合的意義大於各項相加」—— 例如紫P 完全正版、只有一項
/// AnyDesk 連入紀錄，加起來 10 分落在「低」，但推論結論卻是「遠端工具遭入侵」。
/// 報告會一邊說你被入侵、一邊在最顯眼處標「低風險」，而且結束代碼是 0。
/// </para>
/// <para>
/// S-06 的存在意義就是判讀組合，因此它的結論必須能回饋到等級，而不只是寫一行字。
/// </para>
/// </param>
public sealed record Inference(
    string RuleId,
    string Conclusion,
    IReadOnlyList<string> MatchedCheckIds,
    RiskLevel MinimumLevel = RiskLevel.Low);
