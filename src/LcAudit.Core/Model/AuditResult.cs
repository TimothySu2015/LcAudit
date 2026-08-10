namespace LcAudit.Core.Model;

/// <summary>
/// <see cref="Pipeline.AuditRunner"/> 的產出：摘要 + 完整 Finding 清單。
/// <para>
/// 不含 <see cref="HostInfo"/> —— 主機資訊需要 Windows API，由 CLI 層填入後組成
/// <see cref="AuditReport"/>。這讓 Core 保持零 Windows 相依。
/// </para>
/// </summary>
public sealed record AuditResult(AuditSummary Summary, IReadOnlyList<Finding> Findings);
