using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LcAudit.Windows.Sources;

/// <summary>Mark of the Web 內容（<c>Zone.Identifier</c> ADS）。</summary>
/// <param name="ZoneId">3 = 網際網路，4 = 受限制的站台。</param>
/// <param name="HostUrl">實際下載來源。</param>
/// <param name="ReferrerUrl">來源頁面。</param>
public sealed record ZoneIdentifier(int? ZoneId, string? HostUrl, string? ReferrerUrl);

/// <summary>Zone.Identifier 替代資料流讀取（M1-04）。</summary>
public interface IZoneIdentifierReader
{
    /// <summary>讀取檔案的 MOTW；沒有 ADS 或讀不到回 <c>null</c>。</summary>
    ZoneIdentifier? Read(string filePath);
}

/// <inheritdoc cref="IZoneIdentifierReader"/>
public sealed partial class ZoneIdentifierReader : IZoneIdentifierReader
{
    internal const string StreamName = ":Zone.Identifier";

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_ALL = 0x00000007;   // READ | WRITE | DELETE
    private const uint OPEN_EXISTING = 3;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW",
                   StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    public ZoneIdentifier? Read(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var content = ReadStreamContent(filePath + StreamName);

        return content is null ? null : Parse(content);
    }

    /// <summary>
    /// 先走 BCL，失敗再退回 <c>CreateFileW</c>。
    /// <para>
    /// 技術設計 §4.5 指出 .NET 對 <c>"C:\x.exe:Zone.Identifier"</c> 這種路徑的驗證行為
    /// 在各版本間有變動，不可單獨倚賴任一種。兩條路都失敗才視為沒有 MOTW。
    /// </para>
    /// </summary>
    private static string? ReadStreamContent(string streamPath)
    {
        try
        {
            if (File.Exists(streamPath))
            {
                return File.ReadAllText(streamPath);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // 落到下面的 P/Invoke fallback
        }

        using var handle = CreateFile(
            streamPath, GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(handle, FileAccess.Read);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>剖析 INI 格式的 Zone.Identifier 內容。純字串處理，可單元測試。</summary>
    internal static ZoneIdentifier Parse(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        int? zoneId = null;
        string? hostUrl = null;
        string? referrerUrl = null;

        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, out var parsed))
            {
                zoneId = parsed;
            }
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
            {
                hostUrl = value;
            }
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
            {
                referrerUrl = value;
            }
        }

        return new ZoneIdentifier(zoneId, hostUrl, referrerUrl);
    }
}
