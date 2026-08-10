using LcAudit.Core.Model;

namespace LcAudit.Core.Abstractions;

/// <summary>
/// 單一檢查項。一個檢查項 = 一個實作類別（命名如 <c>M1_02_SignerIdentityCheck</c>）。
/// <para>
/// 實作**不得寫 try/catch** —— 例外與逾時統一由
/// <see cref="Pipeline.SafeCheckDecorator"/> 處理並轉為 Inconclusive（NFR-04）。
/// </para>
/// <para>
/// 實作**不得直接呼叫 Win32** —— 一律經由 <c>Sources</c> 介面，讓判定邏輯可用 fake source 單元測試。
/// </para>
/// </summary>
public interface ICheck
{
    /// <summary>檢查項編號，如 <c>"M1-01"</c>。同時決定執行順序（依序號排序）。</summary>
    string Id { get; }

    /// <summary>所屬模組，<c>"M1"</c>～<c>"M4"</c>。</summary>
    string Module { get; }

    /// <summary>中文檢查項名稱。</summary>
    string Title { get; }

    /// <summary>嚴重度。此為靜態中繼資料，與實際判定結果無關。</summary>
    Severity Severity { get; }

    /// <summary>資料來源描述，如 <c>"Security.evtx / EventID 4624"</c>。</summary>
    string Source { get; }

    ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct);
}
