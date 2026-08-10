namespace LcAudit.Windows.Sources;

/// <summary>
/// 從登錄檔的命令列字串中抽出執行檔路徑。
/// <para>
/// 這段的變化比想像中多：引號包裹、未加引號但含空白的路徑、<c>\??\</c> 前綴、
/// <c>\SystemRoot\</c> 相對路徑、<c>svchost.exe -k netsvcs</c> 這種帶參數的形式。
/// 抽錯路徑會讓後續的簽章驗證去驗一個不存在的檔案，結果變成「無法判定」——
/// 而 M3-06/M3-08 的整個價值就建立在「這個執行檔有沒有簽章」上。
/// </para>
/// <para>純字串處理，可完整單元測試。</para>
/// </summary>
public static class CommandLineParser
{
    private static readonly string[] ExecutableExtensions = [".exe", ".sys", ".dll", ".scr", ".com"];

    /// <summary>抽出執行檔路徑並展開環境變數；抽不出來回 <c>null</c>。</summary>
    public static string? ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        var value = commandLine.Trim();

        // 核心物件命名空間前綴，服務的 ImagePath 常見
        if (value.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        var path = value.StartsWith('"')
            ? ExtractQuoted(value)
            : ExtractUnquoted(value);

        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        return Normalise(path);
    }

    private static string? ExtractQuoted(string value)
    {
        var closing = value.IndexOf('"', 1);
        return closing > 1 ? value[1..closing] : null;
    }

    /// <summary>
    /// 未加引號時，不能單純取到第一個空白為止 ——
    /// <c>C:\Program Files\App\app.exe --flag</c> 會被截成 <c>C:\Program</c>。
    /// 改為找第一個可執行副檔名的結尾。
    /// </summary>
    private static string ExtractUnquoted(string value)
    {
        foreach (var extension in ExecutableExtensions)
        {
            var index = value.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                continue;
            }

            var end = index + extension.Length;

            // 必須是路徑的結尾或後面接空白，避免匹配到 "app.exercise" 這種
            if (end == value.Length || value[end] is ' ' or '\t' or '"' or ',')
            {
                return value[..end];
            }
        }

        // 沒有可辨識的副檔名，退回取到第一個空白為止
        var space = value.IndexOf(' ');
        return space > 0 ? value[..space] : value;
    }

    private static string Normalise(string path)
    {
        // \SystemRoot\System32\drivers\x.sys → C:\Windows\System32\drivers\x.sys
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                path[@"\SystemRoot\".Length..]);
        }
        else if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path);
        }

        return Environment.ExpandEnvironmentVariables(path).Trim();
    }

    /// <summary>
    /// 路徑是否位於惡意程式偏好的位置（功能規格 M3-06 的判定條件之一）。
    /// <para>
    /// 正規軟體會裝在 Program Files；落腳在 %TEMP%、%APPDATA%、下載資料夾的
    /// 開機啟動項目，是 dropper 型惡意程式的典型樣式。
    /// </para>
    /// </summary>
    public static bool IsSuspiciousLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string?[] suspiciousRoots =
        [
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        ];

        var full = path.Trim();

        return suspiciousRoots
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Any(root => full.StartsWith(root!, StringComparison.OrdinalIgnoreCase));
    }
}
