using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using Microsoft.Extensions.Logging;

namespace LcAudit.Core.Pipeline;

/// <summary>
/// 統一處理檢查項的例外與逾時（NFR-04）。
/// <para>
/// 有了這一層，個別 <see cref="ICheck"/> 就不需要（也不應該）寫 try/catch。
/// DI 註冊時每個 ICheck 都要包一層。
/// </para>
/// </summary>
public sealed class SafeCheckDecorator : ICheck
{
    /// <summary>單一檢查項的逾時上限。全量掃描須在 3 分鐘內完成（NFR-01）。</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly ICheck _inner;
    private readonly ILogger _logger;
    private readonly TimeSpan _timeout;

    public SafeCheckDecorator(ICheck inner, ILogger<SafeCheckDecorator> logger, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(logger);

        _inner = inner;
        _logger = logger;
        _timeout = timeout ?? DefaultTimeout;
    }

    public string Id => _inner.Id;

    public string Module => _inner.Module;

    public string Title => _inner.Title;

    public Severity Severity => _inner.Severity;

    public string Source => _inner.Source;

    public async ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeout);

            return await _inner.ExecuteAsync(context, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // 內層逾時。
            _logger.LogWarning("檢查 {Id} 逾時（{Seconds} 秒）", Id, _timeout.TotalSeconds);
            return Inconclusive($"檢查逾時（超過 {_timeout.TotalSeconds:0} 秒）");
        }
        catch (OperationCanceledException)
        {
            // 外層取消（使用者按 Ctrl+C）必須往上傳，中止整個掃描。
            // 這個 catch 不能省 —— 少了它會落入下方的 catch (Exception)，
            // 取消被吞成 Inconclusive，使用者按了 Ctrl+C 卻看到工具繼續跑完並產出報告。
            throw;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "檢查 {Id} 權限不足", Id);
            return Inconclusive("權限不足，請以系統管理員身分執行");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "檢查 {Id} 執行失敗", Id);
            return Inconclusive($"檢查執行失敗：{ex.GetType().Name}");
        }
    }

    private Finding Inconclusive(string description) => new()
    {
        Id = Id,
        Module = Module,
        Title = Title,
        Severity = Severity,
        Status = CheckStatus.Inconclusive,
        Source = Source,
        Description = description,
        Recommendation = "此項未能完成判定，不代表安全。請排除原因後重新執行。",
    };
}
