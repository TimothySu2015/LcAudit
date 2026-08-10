using LcAudit.Core.Model;

namespace LcAudit.Core.Tests;

/// <summary>測試用的 Finding 建構輔助。</summary>
internal static class TestFindings
{
    public static Finding Create(
        string id,
        Severity severity = Severity.Medium,
        CheckStatus status = CheckStatus.Pass) => new()
        {
            Id = id,
            Module = id.Split('-')[0],
            Title = $"測試檢查項 {id}",
            Severity = severity,
            Status = status,
            Source = "測試",
        };

    public static Finding Fail(string id, Severity severity = Severity.Medium)
        => Create(id, severity, CheckStatus.Fail);

    public static Finding Warning(string id, Severity severity = Severity.Medium)
        => Create(id, severity, CheckStatus.Warning);

    public static Finding Pass(string id, Severity severity = Severity.Medium)
        => Create(id, severity, CheckStatus.Pass);

    public static Finding Inconclusive(string id, Severity severity = Severity.Medium)
        => Create(id, severity, CheckStatus.Inconclusive);
}
