using System.Diagnostics;
using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Core.Tests;

/// <summary>可控行為的假檢查項，供 Pipeline 測試使用。</summary>
internal sealed class FakeCheck : ICheck
{
    private readonly Func<AuditContext, CancellationToken, ValueTask<Finding>> _behavior;

    private FakeCheck(
        string id,
        Severity severity,
        Func<AuditContext, CancellationToken, ValueTask<Finding>> behavior)
    {
        Id = id;
        Module = id.Split('-')[0];
        Title = $"假檢查項 {id}";
        Severity = severity;
        Source = "測試";
        _behavior = behavior;
    }

    public string Id { get; }

    public string Module { get; }

    public string Title { get; }

    public Severity Severity { get; }

    public string Source { get; }

    public int ExecutionCount { get; private set; }

    public ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        ExecutionCount++;
        return _behavior(context, ct);
    }

    /// <summary>回傳指定狀態的 Finding。</summary>
    public static FakeCheck Returning(
        string id,
        CheckStatus status = CheckStatus.Pass,
        Severity severity = Severity.Medium)
        => new(id, severity, (_, _) => ValueTask.FromResult(TestFindings.Create(id, severity, status)));

    /// <summary>執行時拋出指定例外。</summary>
    public static FakeCheck Throwing(string id, Exception exception, Severity severity = Severity.Medium)
        => new(id, severity, (_, _) => throw exception);

    /// <summary>永遠不完成，直到 token 被取消 —— 用來觸發逾時。</summary>
    public static FakeCheck Hanging(string id, Severity severity = Severity.Medium)
        => new(id, severity, async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            throw new UnreachableException();
        });
}
