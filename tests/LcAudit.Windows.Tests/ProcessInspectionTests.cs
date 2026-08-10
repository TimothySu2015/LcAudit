using System.Diagnostics;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class GameProcessDetectorTests
{
    private sealed class FakeProcessInspector(params ProcessSummary[] processes) : IProcessInspector
    {
        public int ImagePathCallCount { get; private set; }

        public IReadOnlyList<ProcessSummary> ListProcesses() => processes;

        public string? TryGetImagePath(int processId)
        {
            ImagePathCallCount++;
            return null;
        }
    }

    [Fact]
    public void 偵測到遊戲程序時回傳其PID()
    {
        var inspector = new FakeProcessInspector(
            new ProcessSummary(100, "explorer"),
            new ProcessSummary(200, "Purple"),
            new ProcessSummary(300, "GameMon"));

        var pids = GameProcessDetector.DetectProtectedPids(inspector);

        Assert.Equal([200, 300], pids.Order());
    }

    [Fact]
    public void 比對不分大小寫()
    {
        var inspector = new FakeProcessInspector(new ProcessSummary(1, "gamemon"));

        Assert.Single(GameProcessDetector.DetectProtectedPids(inspector));
    }

    [Fact]
    public void 沒有遊戲程序時回傳空集合()
    {
        var inspector = new FakeProcessInspector(new ProcessSummary(1, "explorer"));

        Assert.Empty(GameProcessDetector.DetectProtectedPids(inspector));
    }

    [Fact]
    public void 偵測過程完全不取執行檔路徑()
    {
        // 反作弊共存規則：pre-flight 只比對名稱，絕不對受保護程序開 handle
        var inspector = new FakeProcessInspector(new ProcessSummary(200, "Purple"));

        GameProcessDetector.DetectProtectedPids(inspector);

        Assert.Equal(0, inspector.ImagePathCallCount);
    }
}

[Trait("Category", "Integration")]
public sealed class ProcessInspectorIntegrationTests
{
    private readonly ProcessInspector _inspector = new();

    [Fact]
    public void 列舉處理程序包含自己()
    {
        using var current = Process.GetCurrentProcess();

        var processes = _inspector.ListProcesses();

        Assert.Contains(processes, p => p.ProcessId == current.Id);
    }

    [Fact]
    public void 取得自己的執行檔路徑()
    {
        using var current = Process.GetCurrentProcess();

        var path = _inspector.TryGetImagePath(current.Id);

        Assert.NotNull(path);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void 不存在的PID回傳null而非拋例外()
    {
        // 權限不足或程序已結束都是正常結果，呼叫端轉 Inconclusive
        Assert.Null(_inspector.TryGetImagePath(0x7FFFFFFF));
    }

    [Fact]
    public void SystemIdleProcess取不到路徑也不拋例外()
    {
        // PID 0 是 System Idle Process，任何權限都開不了 —— 必須優雅回 null
        Assert.Null(_inspector.TryGetImagePath(0));
    }
}
