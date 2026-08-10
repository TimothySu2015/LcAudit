using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Core.Pipeline;

/// <summary>
/// 依序執行所有檢查項並彙總結果。
/// <para>
/// 執行順序由 <see cref="ICheck.Id"/> 決定（M1-00 → M1-01 → … → M4-04），
/// 對應功能規格 §4.1 的 M1 → M2 → M3 → M4 流程。M1-00 必須最先跑，
/// 因為它探測出的 <see cref="AuditContext.PurpleInstallPath"/> 是 M1 其餘項的前提。
/// </para>
/// </summary>
public sealed class AuditRunner
{
    private readonly IReadOnlyList<ICheck> _checks;
    private readonly IRiskScorer _scorer;
    private readonly IInferenceEngine _inferenceEngine;

    public AuditRunner(IEnumerable<ICheck> checks, IRiskScorer scorer, IInferenceEngine inferenceEngine)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(scorer);
        ArgumentNullException.ThrowIfNull(inferenceEngine);

        _checks = [.. checks.OrderBy(c => c.Id, StringComparer.Ordinal)];
        _scorer = scorer;
        _inferenceEngine = inferenceEngine;
    }

    public async ValueTask<AuditResult> RunAsync(AuditContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>(_checks.Count);

        foreach (var check in _checks)
        {
            ct.ThrowIfCancellationRequested();

            // 被跳過的項目仍要產生 Finding，報告才能誠實呈現覆蓋率（TC-08）。
            findings.Add(context.SkippedModules.Contains(check.Module)
                ? SkippedFinding(check)
                : await check.ExecuteAsync(context, ct).ConfigureAwait(false));
        }

        // 推論必須先跑 —— 成立的推論會替風險等級設下限，評分需要吃到這個結果。
        var inferences = _inferenceEngine.Infer(findings);
        var score = _scorer.Score(findings, inferences);

        var summary = new AuditSummary
        {
            Score = score.Score,
            RawScore = score.RawScore,
            Level = score.Level,
            CriticalHits = score.CriticalHits,
            LevelRaisedBy = score.LevelRaisedBy,
            Inferences = inferences,
            SkippedModules = context.SkippedModules,
        };

        return new AuditResult(summary, findings);
    }

    private static Finding SkippedFinding(ICheck check) => new()
    {
        Id = check.Id,
        Module = check.Module,
        Title = check.Title,
        Severity = check.Severity,
        Status = CheckStatus.Skipped,
        Source = check.Source,
        Description = $"已依 --skip-module 跳過模組 {check.Module}。",
        Recommendation = "此項未經檢查，不代表安全。",
    };
}
