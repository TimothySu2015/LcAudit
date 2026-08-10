using System.Net;
using System.Runtime.InteropServices;

namespace LcAudit.Windows.Interop;

/// <summary>
/// <c>iphlpapi.dll</c> —— 取得帶 PID 的 TCP 連線表（M4）。
/// <para>
/// <c>IPGlobalProperties.GetActiveTcpConnections()</c> <b>不回傳 PID</b>，
/// 無法把連線對應到處理程序，不符合 M4-01／M4-03 的需求。
/// </para>
/// <para>唯讀查詢，不開任何 process handle，與反作弊無交集。</para>
/// </summary>
internal static partial class IpHlpApi
{
    private const uint AF_INET = 2;
    private const uint AF_INET6 = 23;
    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        uint ulAf,
        uint TableClass,
        uint Reserved);

    /// <summary>取得所有 TCP 連線（IPv4 + IPv6）。</summary>
    internal static IReadOnlyList<TcpConnectionRow> GetTcpConnections()
    {
        var results = new List<TcpConnectionRow>();

        results.AddRange(Read(AF_INET, ParseIPv4Rows));
        results.AddRange(Read(AF_INET6, ParseIPv6Rows));

        return results;
    }

    private static IReadOnlyList<TcpConnectionRow> Read(
        uint family,
        Func<IntPtr, IReadOnlyList<TcpConnectionRow>> parse)
    {
        // 典型的兩段式呼叫：先傳 size = 0 問所需長度，再配置緩衝區取值。
        uint size = 0;
        var status = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);

        if (status != ERROR_INSUFFICIENT_BUFFER || size == 0)
        {
            return [];
        }

        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            status = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);

            return status == 0 ? parse(buffer) : [];
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IReadOnlyList<TcpConnectionRow> ParseIPv4Rows(IntPtr buffer)
    {
        var count = Marshal.ReadInt32(buffer);
        var rows = new List<TcpConnectionRow>(count);
        var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
        var cursor = buffer + 4;

        for (var i = 0; i < count; i++)
        {
            var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(cursor + (i * rowSize));

            rows.Add(new TcpConnectionRow(
                (TcpState)row.dwState,
                new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)),
                NetworkPort(row.dwLocalPort),
                new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)),
                NetworkPort(row.dwRemotePort),
                (int)row.dwOwningPid));
        }

        return rows;
    }

    private static IReadOnlyList<TcpConnectionRow> ParseIPv6Rows(IntPtr buffer)
    {
        var count = Marshal.ReadInt32(buffer);
        var rows = new List<TcpConnectionRow>(count);
        var rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
        var cursor = buffer + 4;

        for (var i = 0; i < count; i++)
        {
            var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(cursor + (i * rowSize));

            rows.Add(new TcpConnectionRow(
                (TcpState)row.dwState,
                new IPAddress(row.ucLocalAddr, row.dwLocalScopeId),
                NetworkPort(row.dwLocalPort),
                new IPAddress(row.ucRemoteAddr, row.dwRemoteScopeId),
                NetworkPort(row.dwRemotePort),
                (int)row.dwOwningPid));
        }

        return rows;
    }

    /// <summary>連接埠以網路位元組順序存放在低 16 位元。</summary>
    private static int NetworkPort(uint value)
        => ((int)(value & 0xFF) << 8) | (int)((value >> 8) & 0xFF);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;

        public uint dwLocalScopeId;
        public uint dwLocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;

        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }
}

/// <summary>TCP 連線狀態（<c>MIB_TCP_STATE</c>）。</summary>
public enum TcpState
{
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>一筆 TCP 連線。</summary>
public sealed record TcpConnectionRow(
    TcpState State,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int OwningProcessId);
