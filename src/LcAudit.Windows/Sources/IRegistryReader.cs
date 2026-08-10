using Microsoft.Win32;

namespace LcAudit.Windows.Sources;

/// <summary>
/// 登錄檔唯讀存取。
/// <para>抽成介面讓 M3 各檢查項的判定邏輯能用假資料測試，不必真的動登錄檔。</para>
/// </summary>
public interface IRegistryReader
{
    /// <summary>讀取 HKLM 底下的值；鍵或值不存在回 <c>null</c>。</summary>
    object? GetLocalMachineValue(string keyPath, string valueName);

    /// <summary>列舉 HKLM 底下某鍵的所有值名稱與內容；鍵不存在回空集合。</summary>
    IReadOnlyDictionary<string, object?> GetLocalMachineValues(string keyPath);

    /// <summary>列舉子鍵名稱；鍵不存在回空集合。</summary>
    IReadOnlyList<string> GetLocalMachineSubKeyNames(string keyPath);

    /// <summary>
    /// 列舉 HKCU 底下某鍵的所有值；鍵不存在回空集合。
    /// <para>M3-06 必須同時查 HKLM 與 HKCU —— 不需要管理員權限就能寫入的 HKCU Run 鍵，
    /// 正是惡意程式最常用的持久化位置。</para>
    /// </summary>
    IReadOnlyDictionary<string, object?> GetCurrentUserValues(string keyPath);
}

/// <inheritdoc cref="IRegistryReader"/>
public sealed class RegistryReader : IRegistryReader
{
    public object? GetLocalMachineValue(string keyPath, string valueName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        using var key = Registry.LocalMachine.OpenSubKey(keyPath);
        return key?.GetValue(valueName);
    }

    public IReadOnlyDictionary<string, object?> GetLocalMachineValues(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        using var key = Registry.LocalMachine.OpenSubKey(keyPath);
        if (key is null)
        {
            return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        }

        return key.GetValueNames()
                  .ToDictionary(name => name, key.GetValue, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<string> GetLocalMachineSubKeyNames(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        using var key = Registry.LocalMachine.OpenSubKey(keyPath);
        return key is null ? [] : key.GetSubKeyNames();
    }

    public IReadOnlyDictionary<string, object?> GetCurrentUserValues(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        using var key = Registry.CurrentUser.OpenSubKey(keyPath);
        if (key is null)
        {
            return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        }

        return key.GetValueNames()
                  .ToDictionary(name => name, key.GetValue, StringComparer.OrdinalIgnoreCase);
    }
}
