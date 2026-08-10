using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 抽錯執行檔路徑會讓後續的簽章驗證去驗一個不存在的檔案，
/// 結果變成「無法判定」—— 而 M3-06/M3-08 的整個價值就建立在簽章判定上。
/// </summary>
public sealed class CommandLineParserTests
{
    [Theory]
    // 引號包裹，含空白路徑與參數
    [InlineData(@"""C:\Program Files\App\app.exe"" --silent", @"C:\Program Files\App\app.exe")]
    [InlineData(@"""C:\Program Files\App\app.exe""", @"C:\Program Files\App\app.exe")]
    // 未加引號但含空白 —— 取到第一個空白為止會被截成 C:\Program
    [InlineData(@"C:\Program Files\App\app.exe --silent", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app.exe", @"C:\Program Files\App\app.exe")]
    // 無空白
    [InlineData(@"C:\Windows\System32\svchost.exe -k netsvcs", @"C:\Windows\System32\svchost.exe")]
    // 核心物件命名空間前綴
    [InlineData(@"\??\C:\Tools\agent.exe", @"C:\Tools\agent.exe")]
    // 逗號分隔的參數
    [InlineData(@"C:\Windows\System32\rundll32.exe ""C:\x.dll"",Entry", @"C:\Windows\System32\rundll32.exe")]
    public void 抽出執行檔路徑(string commandLine, string expected)
        => Assert.Equal(expected, CommandLineParser.ExtractExecutablePath(commandLine));

    [Fact]
    public void 驅動程式的SystemRoot前綴會被展開()
    {
        // 不可寫死 C:\Windows —— 部分機器的 Windows 目錄是 C:\WINDOWS，
        // 路徑在 Windows 上不分大小寫，測試也不該假設大小寫。
        var expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"System32\drivers\evil.sys");

        var result = CommandLineParser.ExtractExecutablePath(@"\SystemRoot\System32\drivers\evil.sys");

        Assert.Equal(expected, result, ignoreCase: true);
    }

    [Fact]
    public void 副檔名須完整比對不可誤切()
    {
        // "app.exercise" 不該被切成 "app.exe"
        var result = CommandLineParser.ExtractExecutablePath(@"C:\Tools\app.exercise.dat");

        Assert.NotEqual(@"C:\Tools\app.exe", result);
    }

    [Fact]
    public void 展開環境變數()
    {
        var result = CommandLineParser.ExtractExecutablePath(@"%SystemRoot%\System32\cmd.exe");

        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), result!,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain('%', result!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void 空輸入回null(string? commandLine)
        => Assert.Null(CommandLineParser.ExtractExecutablePath(commandLine));

    [Fact]
    public void 沒有可辨識副檔名時退回取到第一個空白()
        => Assert.Equal("someprogram", CommandLineParser.ExtractExecutablePath("someprogram --flag"));

    // ---- 可疑位置 ----

    [Fact]
    public void 暫存目錄視為可疑位置()
        => Assert.True(CommandLineParser.IsSuspiciousLocation(
            Path.Combine(Path.GetTempPath(), "dropper.exe")));

    /// <summary>
    /// AppData 與 ProgramData **不算**高風險位置。
    /// <para>
    /// 實測一台乾淨機器：Teams、Discord、Lenovo Vantage 全部中槍，
    /// 連 Windows Defender 自己都被標成可疑（它的執行檔在
    /// <c>%ProgramData%\Microsoft\Windows Defender\Platform\</c>）。
    /// 稽核工具把防毒軟體標成可疑，使用者只會學會忽略這一項。
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(Environment.SpecialFolder.ApplicationData)]
    [InlineData(Environment.SpecialFolder.LocalApplicationData)]
    [InlineData(Environment.SpecialFolder.CommonApplicationData)]
    public void 使用者可寫入的位置不算高風險(Environment.SpecialFolder folder)
    {
        var path = Path.Combine(Environment.GetFolderPath(folder), "x", "y.exe");

        Assert.False(CommandLineParser.IsSuspiciousLocation(path));
        Assert.True(CommandLineParser.IsUserWritableLocation(path));
    }

    [Fact]
    public void Defender自己的路徑不得被判為可疑()
        => Assert.False(CommandLineParser.IsSuspiciousLocation(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe")));

    [Fact]
    public void 下載資料夾視為可疑位置()
        => Assert.True(CommandLineParser.IsSuspiciousLocation(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "setup.exe")));

    [Fact]
    public void ProgramFiles不是可疑位置()
        => Assert.False(CommandLineParser.IsSuspiciousLocation(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "App", "app.exe")));

    [Fact]
    public void System32不是可疑位置()
        => Assert.False(CommandLineParser.IsSuspiciousLocation(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe")));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void 空路徑不算可疑(string? path)
        => Assert.False(CommandLineParser.IsSuspiciousLocation(path));
}
