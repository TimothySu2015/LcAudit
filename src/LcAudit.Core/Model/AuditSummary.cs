namespace LcAudit.Core.Model;

/// <summary>報告摘要（功能規格 §8.2 的 <c>summary</c> 區塊）。</summary>
public sealed record AuditSummary
{
    public required int Score { get; init; }

    public required int RawScore { get; init; }

    public required RiskLevel Level { get; init; }

    public required int CriticalHits { get; init; }

    public required IReadOnlyList<Inference> Inferences { get; init; }

    /// <summary>本次以 <c>--skip-module</c> 跳過的模組。</summary>
    public required IReadOnlySet<string> SkippedModules { get; init; }

    /// <summary>主要推論結論，供 JSON 的 <c>inference</c> 單一欄位使用。</summary>
    public string? PrimaryInference => Inferences.Count > 0 ? Inferences[0].Conclusion : null;

    /// <summary>
    /// TC-08 的覆蓋率註記。
    /// <para>
    /// 評分刻意維持絕對 100 分制 —— 跳過的檢查項一律計 0 分，而非按已執行項目重新計算滿分比例。
    /// 相對計分會讓 <c>--skip-module M3 --skip-module M4</c> 跑出漂亮的低分，
    /// 在安全工具上是危險的誤導。代價是分數會偏低，因此必須靠本註記明講。
    /// </para>
    /// </summary>
    public string? CoverageNote => SkippedModules.Count == 0
        ? null
        : $"本次掃描已跳過模組 {string.Join("、", SkippedModules.Order(StringComparer.Ordinal))}。"
          + "總分仍以 100 分為基準計算，跳過的檢查項一律計 0 分 —— "
          + "分數偏低不代表這些面向安全，只代表未經檢查。";
}
