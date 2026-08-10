using System.Net;
using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M4;
using LcAudit.Windows.Interop;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class M4CheckTests
{
    private sealed class StubTcp(params TcpConnectionRow[] rows) : ITcpConnectionSource
    {
        public IReadOnlyList<TcpConnectionRow> GetConnections() => rows;
    }

    private sealed class StubProcesses : IProcessInspector
    {
        public List<int> ImagePathRequests { get; } = [];

        public IReadOnlyList<ProcessSummary> ListProcesses() =>
        [
            new(100, "chrome"),
            new(200, "Purple"),
            new(300, "evil"),
        ];

        public string? TryGetImagePath(int processId)
        {
            ImagePathRequests.Add(processId);
            return $@"C:\x\{processId}.exe";
        }
    }

    private sealed class StubVerifier(SignatureTrust trust) : IAuthenticodeVerifier
    {
        public SignatureVerdict Verify(string filePath)
            => new() { FilePath = filePath, Trust = trust, HResult = 0 };

        public SignatureVerdict VerifyIncludingCatalog(string filePath) => Verify(filePath);
    }

    private static TcpConnectionRow Row(
        int pid, string remote, int remotePort, TcpState state = TcpState.Established, int localPort = 50000)
        => new(state, IPAddress.Parse("192.168.1.10"), localPort, IPAddress.Parse(remote), remotePort, pid);

    private static Core.Abstractions.AuditContext Context(params int[] protectedPids) => new()
    {
        IsElevated = true,
        LookbackDays = 90,
        SkippedModules = new HashSet<string>(),
        ProtectedPids = protectedPids.ToHashSet(),
    };

    private static ConnectionWithProcess Resolved(
        TcpConnectionRow row, string? name, SignatureTrust? trust = null)
        => new(row, name, name is null ? null : $@"C:\x\{name}.exe", trust);

    // ---- 反作弊共存規則 ----

    [Fact]
    public async Task M4_03絕不對受保護程序取執行檔路徑()
    {
        // 對遊戲／反作弊程序開 handle 會踩線，即使用的是最小權限旗標也要避免
        var processes = new StubProcesses();
        var check = new M4_03_UnsignedOutboundCheck(
            new StubTcp(Row(200, "203.0.113.5", 443), Row(300, "203.0.113.9", 443)),
            processes,
            new StubVerifier(SignatureTrust.NoSignature));

        await check.ExecuteAsync(Context(200), default);

        Assert.DoesNotContain(200, processes.ImagePathRequests);
        Assert.Contains(300, processes.ImagePathRequests);
    }

    [Fact]
    public async Task M4_03遊戲執行中仍照常檢查其餘程序()
    {
        // 這項是 High(20 分)，要抓的是後門與竊資程式，不該因為遊戲開著就整項放棄
        var check = new M4_03_UnsignedOutboundCheck(
            new StubTcp(Row(300, "203.0.113.9", 443)),
            new StubProcesses(),
            new StubVerifier(SignatureTrust.NoSignature));

        var finding = await check.ExecuteAsync(Context(200), default);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("已排除遊戲與反作弊程序", finding.Description);
    }

    // ---- M4-01 ----

    [Fact]
    public async Task M4_01遊戲未執行判Inconclusive且不計分()
    {
        var check = new M4_01_PurpleConnectionsCheck(new StubTcp(), new StubProcesses());

        var finding = await check.ExecuteAsync(Context(), default);

        Assert.Equal(CheckStatus.Inconclusive, finding.Status);
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(0, finding.Score);
    }

    // ---- M4-02 監聽埠 ----

    private static M4_02_ListeningPortsCheck ListenCheck()
        => new(new StubTcp(), new StubProcesses(), new StubVerifier(SignatureTrust.Valid));

    [Fact]
    public void M4_02沒有遠端工具埠判Pass()
        => Assert.Equal(CheckStatus.Pass, ListenCheck().Evaluate(
            [Resolved(Row(100, "0.0.0.0", 0, TcpState.Listen, 445), "System")]).Status);

    [Theory]
    [InlineData(3389, "遠端桌面 (RDP)")]
    [InlineData(5938, "TeamViewer")]
    [InlineData(7070, "AnyDesk")]
    [InlineData(5900, "VNC")]
    public void M4_02遠端工具埠判Warning(int port, string expectedService)
    {
        var finding = ListenCheck().Evaluate(
            [Resolved(Row(100, "0.0.0.0", 0, TcpState.Listen, port), "svc")]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(5, finding.Score);   // Medium(10) 的 50%
        Assert.Contains(expectedService, finding.Description);
    }

    // ---- M4-03 ----

    private static M4_03_UnsignedOutboundCheck OutboundCheck()
        => new(new StubTcp(), new StubProcesses(), new StubVerifier(SignatureTrust.Valid));

    [Fact]
    public void M4_03全部已簽章判Pass()
        => Assert.Equal(CheckStatus.Pass, OutboundCheck().Evaluate(
            [Resolved(Row(100, "203.0.113.5", 443), "chrome", SignatureTrust.Valid)], false).Status);

    [Fact]
    public void M4_03未簽章程序對外連線判Warning()
    {
        var finding = OutboundCheck().Evaluate(
            [Resolved(Row(300, "203.0.113.9", 443), "evil", SignatureTrust.NoSignature)], false);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);
    }

    [Fact]
    public void M4_03未驗證簽章的連線不算未簽章()
    {
        // 受保護程序的 SignatureTrust 為 null —— 不該被誤判為未簽章
        var finding = OutboundCheck().Evaluate(
            [Resolved(Row(200, "203.0.113.5", 443), "Purple")], true);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M4_03同一程序的多條連線彙總為一筆證據()
    {
        var finding = OutboundCheck().Evaluate(
        [
            Resolved(Row(300, "203.0.113.9", 443), "evil", SignatureTrust.NoSignature),
            Resolved(Row(300, "203.0.113.10", 8080), "evil", SignatureTrust.NoSignature),
        ], false);

        Assert.Single(finding.Evidence);
        Assert.Contains("1 個未簽章", finding.Description);
    }

    // ---- M4-04 ----

    private static M4_04_KnownRemoteServiceCheck ServiceCheck()
        => new(new StubTcp(), new StubProcesses(), new StubVerifier(SignatureTrust.Valid));

    [Fact]
    public void M4_04一般對外連線判Pass()
        => Assert.Equal(CheckStatus.Pass, ServiceCheck().Evaluate(
            [Resolved(Row(100, "203.0.113.5", 443), "chrome")]).Status);

    [Fact]
    public void M4_04連向遠端服務埠判Warning()
    {
        var finding = ServiceCheck().Evaluate([Resolved(Row(100, "203.0.113.5", 5938), "x")]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains(finding.Evidence, e => e.Value.Contains("TeamViewer", StringComparison.Ordinal));
    }

    [Fact]
    public void M4_04依程序名稱比對已知遠端工具()
    {
        var finding = ServiceCheck().Evaluate([Resolved(Row(100, "203.0.113.5", 443), "AnyDesk")]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
    }
}

[Trait("Category", "Integration")]
public sealed class TcpConnectionSourceIntegrationTests
{
    [Fact]
    public void 能取得帶PID的TCP連線表()
    {
        var connections = new TcpConnectionSource().GetConnections();

        Assert.NotEmpty(connections);

        // GetExtendedTcpTable 的重點就是帶 PID ——
        // IPGlobalProperties.GetActiveTcpConnections() 不回傳 PID，故不可用
        Assert.Contains(connections, c => c.OwningProcessId > 0);
    }

    [Fact]
    public void 連接埠的位元組順序轉換正確()
    {
        var connections = new TcpConnectionSource().GetConnections();

        // 未轉換網路位元組順序的話會出現遠超過 65535 的埠號
        Assert.All(connections, c =>
        {
            Assert.InRange(c.LocalPort, 0, 65535);
            Assert.InRange(c.RemotePort, 0, 65535);
        });
    }

    [Fact]
    public void 含有監聽中的連線()
        => Assert.Contains(new TcpConnectionSource().GetConnections(), c => c.State == TcpState.Listen);
}
