using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Pipeline;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LcAudit.Core.Tests;

/// <summary>NFR-04：任一檢查項的例外必須轉為 Inconclusive，不得中斷整體流程。</summary>
public sealed class SafeCheckDecoratorTests
{
    private static readonly AuditContext Context = new()
    {
        IsElevated = false,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(),
    };

    private static SafeCheckDecorator Wrap(ICheck inner, TimeSpan? timeout = null)
        => new(inner, NullLogger<SafeCheckDecorator>.Instance, timeout);

    [Fact]
    public async Task 正常執行時原樣回傳()
    {
        var finding = await Wrap(FakeCheck.Returning("M1-01", CheckStatus.Fail)).ExecuteAsync(Context, default);

        Assert.Equal(CheckStatus.Fail, finding.Status);
    }

    [Fact]
    public async Task 一般例外轉為Inconclusive()
    {
        var finding = await Wrap(FakeCheck.Throwing("M1-05", new InvalidOperationException("boom")))
            .ExecuteAsync(Context, default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Equal("M1-05", finding.Id);
        Assert.Contains("InvalidOperationException", finding.Description);
    }

    [Fact]
    public async Task 權限例外給出提權提示()
    {
        var finding = await Wrap(FakeCheck.Throwing("M2-01", new UnauthorizedAccessException()))
            .ExecuteAsync(Context, default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Contains("系統管理員", finding.Description);
    }

    [Fact]
    public async Task 逾時轉為Inconclusive()
    {
        var finding = await Wrap(FakeCheck.Hanging("M3-12"), TimeSpan.FromMilliseconds(50))
            .ExecuteAsync(Context, default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Contains("逾時", finding.Description);
    }

    [Fact]
    public async Task 外層取消不吞例外()
    {
        // 使用者按 Ctrl+C 時應中止整個流程，不該被誤判為單項逾時
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Wrap(FakeCheck.Hanging("M3-12")).ExecuteAsync(Context, cts.Token));
    }

    [Fact]
    public async Task 轉出的Inconclusive保留原檢查項的中繼資料()
    {
        var inner = FakeCheck.Throwing("M4-03", new IOException(), Severity.High);

        var finding = await Wrap(inner).ExecuteAsync(Context, default);

        Assert.Equal("M4-03", finding.Id);
        Assert.Equal("M4", finding.Module);
        Assert.Equal(inner.Title, finding.Title);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(0, finding.Score);
    }
}
