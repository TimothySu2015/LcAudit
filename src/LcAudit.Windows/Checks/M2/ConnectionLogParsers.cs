using System.Globalization;

namespace LcAudit.Windows.Checks.M2;

/// <summary>一筆連入紀錄。</summary>
/// <param name="Time">連線時間；無法解析時為 <c>null</c>（仍應列出，別因為時間讀不到就丟掉證據）。</param>
/// <param name="RemoteId">遠端識別碼或帳號。</param>
/// <param name="RawLine">原始行內容，供人工核對。</param>
public sealed record IncomingConnection(DateTimeOffset? Time, string? RemoteId, string RawLine);

/// <summary>
/// 遠端工具連入紀錄的剖析。
/// <para>
/// <b>這些格式沒有官方規格，且會隨版本變動。</b>因此一律採寬鬆剖析：
/// 認得出時間就帶上，認不出也要保留原始行 —— 稽核工具寧可多列一行讓人自己看，
/// 也不該因為格式不合預期就靜默丟棄證據。
/// </para>
/// <para>純字串處理，可完整單元測試。</para>
/// </summary>
public static class ConnectionLogParsers
{
    /// <summary>
    /// AnyDesk <c>connection_trace.txt</c>。
    /// <para>典型行：<c>Incoming 2026-05-01, 14:23  1234567890  (user)</c></para>
    /// </summary>
    public static IReadOnlyList<IncomingConnection> ParseAnyDesk(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return [];
        }

        var results = new List<IncomingConnection>();

        foreach (var raw in content.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            // 只要連入。Outgoing 代表這台機器連出去，不是被連入，方向不能搞混。
            if (!raw.StartsWith("Incoming", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            results.Add(new IncomingConnection(
                TryParseAnyDeskTime(raw),
                ExtractLongestDigitRun(raw),
                raw));
        }

        return results;
    }

    /// <summary>
    /// TeamViewer <c>Connections_incoming.txt</c>。
    /// <para>典型行：<c>1234567890  Name  01-05-2026 14:23:05  01-05-2026 14:40:11  User  RemoteControl  {guid}</c></para>
    /// <para>檔案本身只記錄連入，因此每一行都算。</para>
    /// </summary>
    public static IReadOnlyList<IncomingConnection> ParseTeamViewer(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return [];
        }

        var results = new List<IncomingConnection>();

        foreach (var raw in content.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = raw.Split([' ', '\t'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 0)
            {
                continue;
            }

            results.Add(new IncomingConnection(
                TryParseTeamViewerTime(fields),
                fields[0],
                raw));
        }

        return results;
    }

    private static DateTimeOffset? TryParseAnyDeskTime(string line)
    {
        // "Incoming 2026-05-01, 14:23  ..." —— 取第一段日期與其後的時間
        var parts = line.Split([' ', ',', '\t'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (DateTime.TryParseExact(
                    $"{parts[i]} {parts[i + 1]}",
                    ["yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss"],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out var parsed))
            {
                return new DateTimeOffset(parsed, TimeZoneInfo.Local.GetUtcOffset(parsed));
            }
        }

        return null;
    }

    private static DateTimeOffset? TryParseTeamViewerTime(string[] fields)
    {
        // TeamViewer 用 dd-MM-yyyy，與台灣習慣的 yyyy-MM-dd 不同，
        // 直接 TryParse 會把 05-01-2026 讀成 1 月 5 日，因此固定格式解析。
        for (var i = 0; i < fields.Length - 1; i++)
        {
            if (DateTime.TryParseExact(
                    $"{fields[i]} {fields[i + 1]}",
                    ["dd-MM-yyyy HH:mm:ss", "dd-MM-yyyy HH:mm"],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out var parsed))
            {
                return new DateTimeOffset(parsed, TimeZoneInfo.Local.GetUtcOffset(parsed));
            }
        }

        return null;
    }

    /// <summary>取行中最長的一串數字當作遠端識別碼（AnyDesk ID 通常 9–10 位）。</summary>
    private static string? ExtractLongestDigitRun(string line)
    {
        string? best = null;
        var start = -1;

        for (var i = 0; i <= line.Length; i++)
        {
            if (i < line.Length && char.IsAsciiDigit(line[i]))
            {
                if (start < 0)
                {
                    start = i;
                }

                continue;
            }

            if (start >= 0)
            {
                var candidate = line[start..i];
                if (best is null || candidate.Length > best.Length)
                {
                    best = candidate;
                }

                start = -1;
            }
        }

        return best is { Length: >= 6 } ? best : null;
    }
}
