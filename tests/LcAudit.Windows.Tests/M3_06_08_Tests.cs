using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M3;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class M3_06_08_Tests
{
    private sealed class StubRegistry : IRegistryReader
    {
        public object? GetLocalMachineValue(string keyPath, string valueName) => null;

        public IReadOnlyDictionary<string, object?> GetLocalMachineValues(string keyPath)
            => new Dictionary<string, object?>();

        public IReadOnlyList<string> GetLocalMachineSubKeyNames(string keyPath) => [];

        public IReadOnlyDictionary<string, object?> GetCurrentUserValues(string keyPath)
            => new Dictionary<string, object?>();
    }

    private sealed class StubVerifier : IAuthenticodeVerifier
    {
        public SignatureVerdict Verify(string filePath) => new()
        {
            FilePath = filePath,
            Trust = SignatureTrust.Valid,
            HResult = 0,
        };

        public SignatureVerdict VerifyIncludingCatalog(string filePath) => Verify(filePath);
    }

    private static M3_06_AutoStartCheck AutoStart() => new(new StubRegistry(), new StubVerifier());

    private static M3_08_UnexpectedServicesCheck Services() => new(new StubRegistry(), new StubVerifier());

    private static AutoStartEntry Entry(
        string name,
        string path,
        SignatureTrust? trust = SignatureTrust.Valid)
        => new(@"HKLM\...\Run", name, path, path, trust);

    // ---- M3-06 ----

    [Fact]
    public void M3_06全部已簽章且位置正常判Pass()
    {
        var finding = AutoStart().Evaluate(
        [
            Entry("OneDrive", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe"),
            Entry("Steam", @"C:\Program Files (x86)\Steam\steam.exe"),
        ]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(0, finding.Score);
    }

    [Fact]
    public void M3_06未簽章判Warning()
    {
        var finding = AutoStart().Evaluate(
        [
            Entry("Legit", @"C:\Program Files\App\app.exe"),
            Entry("Backdoor", @"C:\Program Files\X\x.exe", SignatureTrust.NoSignature),
        ]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);   // High(20) 的 50%
        Assert.Contains("1 個未簽章或簽章無效", finding.Description);
    }

    [Fact]
    public void M3_06位於暫存目錄即使已簽章也判Warning()
    {
        var tempExe = Path.Combine(Path.GetTempPath(), "installer.exe");

        var finding = AutoStart().Evaluate([Entry("Temp", tempExe)]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("位於暫存或下載目錄", finding.Description);
    }

    [Fact]
    public void M3_06可疑項目排在證據最前面()
    {
        var finding = AutoStart().Evaluate(
        [
            Entry("Legit", @"C:\Program Files\App\app.exe"),
            Entry("Bad", @"C:\Program Files\X\x.exe", SignatureTrust.NoSignature),
        ]);

        Assert.StartsWith("⚠", finding.Evidence[0].Key, StringComparison.Ordinal);
    }

    /// <summary>
    /// AppData／ProgramData 的已簽章項目不算可疑 —— 否則 Teams、Discord、
    /// Lenovo Vantage、甚至 Windows Defender 自己都會中槍。
    /// </summary>
    [Theory]
    [InlineData(Environment.SpecialFolder.LocalApplicationData)]
    [InlineData(Environment.SpecialFolder.CommonApplicationData)]
    public void M3_06使用者可寫入位置的已簽章項目判Pass(Environment.SpecialFolder folder)
    {
        var path = Path.Combine(Environment.GetFolderPath(folder), "App", "app.exe");

        Assert.Equal(CheckStatus.Pass, AutoStart().Evaluate([Entry("App", path)]).Status);
    }

    [Fact]
    public void M3_06無法判定簽章者不算未簽章()
    {
        // Unknown（未列於對照表的 HRESULT）代表「驗不出來」而非「沒簽章」。
        // 實測 ms-teams.exe 就是 Unknown，不該因此被標為可疑。
        var finding = AutoStart().Evaluate(
            [Entry("Teams", @"C:\Program Files\Teams\ms-teams.exe", SignatureTrust.Unknown)]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_06啟動資料夾只看會被執行的副檔名()
    {
        // desktop.ini 是資料夾外觀設定檔，每個啟動資料夾都有一份 ——
        // 不排除的話每台機器都會多兩個假的可疑啟動項
        Assert.DoesNotContain(".ini", M3_06_AutoStartCheck.StartupExtensions);
        Assert.Contains(".exe", M3_06_AutoStartCheck.StartupExtensions);
        Assert.Contains(".lnk", M3_06_AutoStartCheck.StartupExtensions);
    }

    [Fact]
    public void M3_06未驗證簽章的項目不算未簽章()
    {
        // 捷徑不解析目標，SignatureTrust 為 null —— 不該被當成未簽章而誤報
        var finding = AutoStart().Evaluate(
            [new AutoStartEntry("使用者啟動資料夾", "app.lnk", @"C:\x\app.lnk", null, null)]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    // ---- M3-08 ----

    [Fact]
    public void M3_08全部已簽章判Pass()
    {
        var finding = Services().Evaluate(
        [
            new ServiceEntry("Spooler", "Print Spooler", @"C:\Windows\System32\spoolsv.exe",
                @"C:\Windows\System32\spoolsv.exe", SignatureTrust.Valid),
        ]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_08有效簽章的第三方服務不判Warning()
    {
        // 規格字面是「非 Microsoft 簽章即 Warning」，但任何實際使用的電腦都有大量
        // 合法第三方服務（顯示卡、音效、防毒）。一律 Warning 是純誤報風暴。
        var finding = Services().Evaluate(
        [
            new ServiceEntry("NVDisplay", "NVIDIA Display", @"C:\Program Files\NVIDIA\x.exe",
                @"C:\Program Files\NVIDIA\x.exe", SignatureTrust.Valid),
        ]);

        Assert.Equal(CheckStatus.Pass, finding.Status);
    }

    [Fact]
    public void M3_08未簽章的自動啟動服務判Warning()
    {
        var finding = Services().Evaluate(
        [
            new ServiceEntry("Good", null, @"C:\Windows\System32\a.exe",
                @"C:\Windows\System32\a.exe", SignatureTrust.Valid),
            new ServiceEntry("EvilSvc", "Evil", @"C:\Temp\evil.exe",
                @"C:\Temp\evil.exe", SignatureTrust.NoSignature),
        ]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(5, finding.Score);   // Medium(10) 的 50%
        Assert.Contains(finding.Evidence, e => e.Key.Contains("EvilSvc", StringComparison.Ordinal));
    }

    [Fact]
    public void M3_08列不出服務判Inconclusive而非Pass()
        => Assert.Equal(CheckStatus.Inconclusive, Services().Evaluate([]).Status);
}
