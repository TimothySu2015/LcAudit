using System.Diagnostics.Eventing.Reader;

namespace LcAudit.Windows.Sources;

/// <inheritdoc cref="IWindowsEventLog"/>
public sealed class WindowsEventLog : IWindowsEventLog
{
    /// <summary>筆數上限預設值（NFR-01）。</summary>
    public const int DefaultMaxEvents = 5000;

    public IReadOnlyList<EventRecordData> Query(
        string logName,
        string xpath,
        IReadOnlyList<string> propertyPaths,
        int maxEvents)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        ArgumentException.ThrowIfNullOrWhiteSpace(xpath);
        ArgumentNullException.ThrowIfNull(propertyPaths);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEvents);

        // 必須先明確探測可讀性。
        //
        // TolerateQueryErrors = true 會讓「權限不足」變成靜默失敗：EventLogReader 建得起來、
        // ReadEvent() 直接回 null，於是「讀不到記錄檔」與「期間內沒有事件」完全無法區分。
        // 未提權時 M2 會全部報「通過」—— 工具在讀不到資料的情況下宣稱沒有遠端登入，
        // 這比沒有這個檢查還糟。已實測確認此行為。
        EnsureReadable(logName);

        var query = new EventLogQuery(logName, PathType.LogName, xpath)
        {
            ReverseDirection = true,     // 新到舊
            TolerateQueryErrors = true,  // 個別損毀的記錄不影響整批
        };

        var results = new List<EventRecordData>();

        // 具名 XPath 取值 —— 不要對每筆記錄呼叫 ToXml()，5000 筆會慢到爆掉。
        using var selector = propertyPaths.Count > 0
            ? new EventLogPropertySelector(propertyPaths)
            : null;

        using var reader = CreateReader(query, logName);

        while (results.Count < maxEvents && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                results.Add(ToData(record, selector, propertyPaths.Count));
            }
        }

        return results;
    }

    /// <summary>
    /// 確認記錄檔真的讀得到。<c>GetLogInformation</c> 在權限不足時會確實拋
    /// <see cref="UnauthorizedAccessException"/>，不像查詢那樣被 TolerateQueryErrors 吞掉。
    /// </summary>
    private static void EnsureReadable(string logName)
    {
        try
        {
            _ = EventLogSession.GlobalSession.GetLogInformation(logName, PathType.LogName);
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (EventLogNotFoundException ex)
        {
            throw new FileNotFoundException($"找不到事件記錄檔「{logName}」。", logName, ex);
        }
        catch (EventLogException ex)
        {
            throw new UnauthorizedAccessException(
                $"無法讀取事件記錄檔「{logName}」，可能需要系統管理員權限。", ex);
        }
    }

    private static EventLogReader CreateReader(EventLogQuery query, string logName)
    {
        try
        {
            return new EventLogReader(query);
        }
        catch (EventLogNotFoundException ex)
        {
            // 記錄檔不存在（例如未啟用的 TerminalServices 記錄）—— 轉成呼叫端能理解的例外
            throw new FileNotFoundException($"找不到事件記錄檔「{logName}」。", logName, ex);
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (EventLogException ex)
        {
            // 讀取 Security 未提權時，底層拋的是 EventLogException 而非 UnauthorizedAccessException。
            // 統一轉成後者，SafeCheckDecorator 才能給出「請以系統管理員執行」的正確提示。
            throw new UnauthorizedAccessException($"無法讀取事件記錄檔「{logName}」，可能需要系統管理員權限。", ex);
        }
    }

    private static EventRecordData ToData(
        EventRecord record,
        EventLogPropertySelector? selector,
        int propertyCount)
    {
        var values = new string?[propertyCount];

        if (selector is not null && record is EventLogRecord logRecord)
        {
            // 欄位缺漏時個別記錄的結構可能不同，逐筆容錯而非讓整批失敗。
            try
            {
                var raw = logRecord.GetPropertyValues(selector);
                for (var i = 0; i < propertyCount && i < raw.Count; i++)
                {
                    values[i] = raw[i]?.ToString();
                }
            }
            catch (EventLogException)
            {
                // 保持 values 全為 null，呼叫端會看到缺值
            }
        }

        return new EventRecordData(
            record.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.MinValue,
            record.Id,
            values);
    }
}
