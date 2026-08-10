namespace LcAudit.Core.Model;

/// <summary>單一檢查項的判定結果（功能規格 §5.1）。</summary>
public sealed record Finding
{
    /// <summary>檢查項編號，如 <c>"M1-01"</c>。</summary>
    public required string Id { get; init; }

    /// <summary>所屬模組，<c>"M1"</c>～<c>"M4"</c>。</summary>
    public required string Module { get; init; }

    public required string Title { get; init; }

    public required Severity Severity { get; init; }

    public required CheckStatus Status { get; init; }

    /// <summary>資料來源，如 <c>"Security.evtx / EventID 4624"</c>。</summary>
    public required string Source { get; init; }

    public string? Description { get; init; }

    public string? Recommendation { get; init; }

    public IReadOnlyList<Evidence> Evidence { get; init; } = [];

    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.Now;

    /// <summary>是否命中（Fail 或 Warning）。推論引擎以此判斷規則是否成立。</summary>
    public bool IsHit => Status is CheckStatus.Fail or CheckStatus.Warning;

    /// <summary>
    /// 本項計入的風險分數（功能規格 S-01 / S-02）。
    /// Warning 的整數除法截斷是刻意的：Low(5) 的 Warning 計 2 分。
    /// </summary>
    public int Score => Status switch
    {
        CheckStatus.Fail => (int)Severity,
        CheckStatus.Warning => (int)Severity / 2,
        _ => 0,
    };
}
