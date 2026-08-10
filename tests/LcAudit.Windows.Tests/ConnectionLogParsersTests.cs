using LcAudit.Windows.Checks.M2;
using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 遠端工具紀錄檔格式沒有官方規格且隨版本變動，因此採寬鬆剖析：
/// 認得出時間就帶上，認不出也必須保留原始行 —— 不可因格式不合預期就靜默丟棄證據。
/// </summary>
public sealed class ConnectionLogParsersTests
{
    // ---- AnyDesk ----

    [Fact]
    public void AnyDesk只取連入不取連出()
    {
        const string content = """
            Incoming 2026-05-01, 14:23  1234567890  someone
            Outgoing 2026-05-02, 09:10  9876543210  someone
            Incoming 2026-05-03, 22:05  1234567890  someone
            """;

        var result = ConnectionLogParsers.ParseAnyDesk(content);

        Assert.Equal(2, result.Count);
        Assert.All(result, c => Assert.StartsWith("Incoming", c.RawLine, StringComparison.Ordinal));
    }

    [Fact]
    public void AnyDesk解析時間與遠端ID()
    {
        var result = ConnectionLogParsers.ParseAnyDesk("Incoming 2026-05-01, 14:23  1234567890  someone");

        var connection = Assert.Single(result);
        Assert.Equal(new DateTime(2026, 5, 1, 14, 23, 0), connection.Time!.Value.DateTime);
        Assert.Equal("1234567890", connection.RemoteId);
    }

    [Fact]
    public void AnyDesk時間解析失敗仍保留原始行()
    {
        // 未來版本改格式時，不可因此漏掉這筆證據
        var result = ConnectionLogParsers.ParseAnyDesk("Incoming 未知格式的時間 abcdef");

        var connection = Assert.Single(result);
        Assert.Null(connection.Time);
        Assert.Contains("未知格式", connection.RawLine, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AnyDesk空內容回空清單(string? content)
        => Assert.Empty(ConnectionLogParsers.ParseAnyDesk(content));

    // ---- TeamViewer ----

    [Fact]
    public void TeamViewer解析日月年格式()
    {
        // TeamViewer 用 dd-MM-yyyy。直接 TryParse 會把 05-01-2026 讀成 1 月 5 日，
        // 那會讓時間軸整個錯位 —— 必須固定格式解析。
        var result = ConnectionLogParsers.ParseTeamViewer(
            "1234567890\tSomeName\t05-01-2026 14:23:05\t05-01-2026 14:40:11\tUser\tRemoteControl\t{guid}");

        var connection = Assert.Single(result);
        Assert.Equal(new DateTime(2026, 1, 5, 14, 23, 5), connection.Time!.Value.DateTime);
        Assert.Equal("1234567890", connection.RemoteId);
    }

    [Fact]
    public void TeamViewer每一行都算連入()
    {
        // Connections_incoming.txt 檔名即語意，內容全部都是連入
        const string content = """
            111111111 A 05-01-2026 14:23:05 05-01-2026 14:40:11 User RemoteControl {g1}
            222222222 B 06-01-2026 09:00:00 06-01-2026 09:30:00 User RemoteControl {g2}
            """;

        Assert.Equal(2, ConnectionLogParsers.ParseTeamViewer(content).Count);
    }

    [Fact]
    public void TeamViewer格式異常仍保留原始行()
    {
        var result = ConnectionLogParsers.ParseTeamViewer("完全不符預期的一行");

        var connection = Assert.Single(result);
        Assert.Null(connection.Time);
        Assert.Equal("完全不符預期的一行", connection.RawLine);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TeamViewer空內容回空清單(string? content)
        => Assert.Empty(ConnectionLogParsers.ParseTeamViewer(content));
}
