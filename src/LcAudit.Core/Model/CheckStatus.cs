namespace LcAudit.Core.Model;

/// <summary>單一檢查項的判定結果（功能規格 §5.2）。</summary>
public enum CheckStatus
{
    /// <summary>檢查通過，未發現異常。不計分。</summary>
    Pass,

    /// <summary>有可疑跡象，需人工研判。計 50% 分數。</summary>
    Warning,

    /// <summary>明確異常。計 100% 分數。</summary>
    Fail,

    /// <summary>因權限不足、路徑不存在、逾時等原因無法判定。不計分，但必須列於報告。</summary>
    Inconclusive,

    /// <summary>因 <c>--skip-module</c> 而未執行。不計分，並觸發報告的覆蓋率註記（TC-08）。</summary>
    Skipped,
}
