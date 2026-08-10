using LcAudit.Windows.Interop;

namespace LcAudit.Windows.Sources;

/// <summary>TCP 連線查詢（M4）。</summary>
public interface ITcpConnectionSource
{
    IReadOnlyList<TcpConnectionRow> GetConnections();
}

/// <inheritdoc cref="ITcpConnectionSource"/>
public sealed class TcpConnectionSource : ITcpConnectionSource
{
    public IReadOnlyList<TcpConnectionRow> GetConnections() => IpHlpApi.GetTcpConnections();
}

/// <summary>
/// 遠端存取工具常用的通訊埠（M4-02 / M4-04）。
/// <para>靜態清單，需隨工具版本更迭手動維護（對應已知限制 L-06）。</para>
/// </summary>
public static class RemoteAccessPorts
{
    /// <summary>連接埠 → 對應的服務名稱。</summary>
    public static readonly IReadOnlyDictionary<int, string> Known = new Dictionary<int, string>
    {
        [3389] = "遠端桌面 (RDP)",
        [5938] = "TeamViewer",
        [7070] = "AnyDesk",
        [6568] = "AnyDesk",
        [5900] = "VNC",
        [5901] = "VNC",
        [4899] = "Radmin",
        [8000] = "向日葵 Sunlogin",
        [21115] = "RustDesk",
        [21116] = "RustDesk",
        [21117] = "RustDesk",
        [21118] = "RustDesk",
        [21119] = "RustDesk",
    };

    public static string? Describe(int port) => Known.GetValueOrDefault(port);
}
