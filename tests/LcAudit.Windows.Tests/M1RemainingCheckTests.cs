using LcAudit.Core.Model;
using LcAudit.Windows.Checks.M1;
using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

public sealed class FileNameSimilarityTests
{
    private static readonly IReadOnlyList<string> KnownGood = ["Purple.exe", "NCLauncher.exe"];

    [Theory]
    // 同形字元：大寫 I 冒充小寫 l
    [InlineData("PurpIe.exe", SimilarityReason.Homoglyph)]
    // 數字 1 冒充 l
    [InlineData("Purp1e.exe", SimilarityReason.Homoglyph)]
    // 數字 0 冒充 o
    [InlineData("NCLauncher.exe", SimilarityReason.Homoglyph, false)]
    public void 同形字元替換會被抓到(string fileName, SimilarityReason reason, bool expectMatch = true)
    {
        var result = FileNameSimilarity.FindSuspicious([fileName], KnownGood);

        if (!expectMatch)
        {
            Assert.Empty(result);
            return;
        }

        var match = Assert.Single(result);
        Assert.Equal(reason, match.Reason);
    }

    [Theory]
    [InlineData("Purple_new.exe")]
    [InlineData("Purple_bak.exe")]
    [InlineData("Purple2.exe")]
    [InlineData("Purple(1).exe")]
    [InlineData("Purple_copy.exe")]
    public void 複製後綴會被抓到(string fileName)
    {
        var match = Assert.Single(FileNameSimilarity.FindSuspicious([fileName], KnownGood));

        Assert.Equal(SimilarityReason.CopySuffix, match.Reason);
        Assert.Equal("Purple", match.SimilarTo);
    }

    [Theory]
    [InlineData("Purpel.exe")]
    [InlineData("Pruple.exe")]
    public void 拼字接近會被抓到(string fileName)
        => Assert.Equal(SimilarityReason.NearMiss,
            Assert.Single(FileNameSimilarity.FindSuspicious([fileName], KnownGood)).Reason);

    [Theory]
    [InlineData("Purple.exe")]      // 正版本身
    [InlineData("NCLauncher.exe")]  // 正版本身
    public void 正版檔名不會被誤判(string fileName)
        => Assert.Empty(FileNameSimilarity.FindSuspicious([fileName], KnownGood));

    [Theory]
    [InlineData("PurpleUpdater.exe")]   // 長度差異大，屬正常的同系列程式
    [InlineData("PurpleCrashHandler.exe")]
    [InlineData("unins000.exe")]
    [InlineData("vcredist.exe")]
    public void 安裝目錄的正常檔案不會被誤判(string fileName)
        => Assert.Empty(FileNameSimilarity.FindSuspicious([fileName], KnownGood));

    [Fact]
    public void rn折疊為m()
        => Assert.Equal("m", FileNameSimilarity.Fold("rn"));

    [Theory]
    [InlineData("", "", 0)]
    [InlineData("abc", "abc", 0)]
    [InlineData("abc", "abd", 1)]
    [InlineData("abc", "", 3)]
    [InlineData("purple", "purpel", 2)]
    public void 編輯距離計算正確(string a, string b, int expected)
        => Assert.Equal(expected, FileNameSimilarity.LevenshteinDistance(a, b));
}

public sealed class ZoneIdentifierParserTests
{
    [Fact]
    public void 剖析標準的ZoneIdentifier()
    {
        const string content = """
            [ZoneTransfer]
            ZoneId=3
            ReferrerUrl=https://lineageclassic.plaync.com/download
            HostUrl=https://downloads.plaync.com/purple-setup.exe
            """;

        var zone = ZoneIdentifierReader.Parse(content);

        Assert.Equal(3, zone.ZoneId);
        Assert.Equal("https://downloads.plaync.com/purple-setup.exe", zone.HostUrl);
        Assert.Equal("https://lineageclassic.plaync.com/download", zone.ReferrerUrl);
    }

    [Fact]
    public void 只有ZoneId沒有網址()
    {
        var zone = ZoneIdentifierReader.Parse("[ZoneTransfer]\r\nZoneId=3\r\n");

        Assert.Equal(3, zone.ZoneId);
        Assert.Null(zone.HostUrl);
        Assert.Null(zone.ReferrerUrl);
    }

    [Fact]
    public void 鍵名不分大小寫()
    {
        var zone = ZoneIdentifierReader.Parse("hosturl=https://plaync.com/x");

        Assert.Equal("https://plaync.com/x", zone.HostUrl);
    }

    [Fact]
    public void 網址含等號不會被截斷()
    {
        var zone = ZoneIdentifierReader.Parse("HostUrl=https://evil.tw/get?a=1&b=2");

        Assert.Equal("https://evil.tw/get?a=1&b=2", zone.HostUrl);
    }
}

public sealed class M1RemainingCheckTests
{
    private sealed class StubVerifier : IAuthenticodeVerifier
    {
        public SignatureVerdict Verify(string filePath) => new()
        {
            FilePath = filePath, Trust = SignatureTrust.Valid, HResult = 0,
        };

        public SignatureVerdict VerifyIncludingCatalog(string filePath) => Verify(filePath);
    }

    private sealed class StubZoneReader(ZoneIdentifier? zone) : IZoneIdentifierReader
    {
        public ZoneIdentifier? Read(string filePath) => zone;
    }

    private sealed class StubEventLog : IWindowsEventLog
    {
        public IReadOnlyList<EventRecordData> Query(
            string logName, string xpath, IReadOnlyList<string> propertyPaths, int maxEvents) => [];

        public bool LogExists(string logName) => true;
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 10, 12, 0, 0, TimeSpan.FromHours(8));

    // ---- M1-03 憑證與時間戳 ----

    private static SignatureVerdict Verdict(SignatureTrust trust, DateTimeOffset? notAfter)
        => new() { FilePath = @"C:\x\Purple.exe", Trust = trust, HResult = 0, NotAfter = notAfter };

    [Fact]
    public void M1_03憑證未過期判Pass()
        => Assert.Equal(CheckStatus.Pass, new M1_03_CertificateChainCheck(new StubVerifier())
            .Evaluate(Verdict(SignatureTrust.Valid, Now.AddYears(1)), Now).Status);

    [Fact]
    public void M1_03憑證過期但簽章仍有效代表有時間戳判Pass()
    {
        // Authenticode 的規則：憑證過期但簽章當下有合法時間戳 → 仍視為有效。
        // 因此 WinVerifyTrust 回 Valid 就代表有時間戳，不必另外剖析 counter-signature。
        var finding = new M1_03_CertificateChainCheck(new StubVerifier())
            .Evaluate(Verdict(SignatureTrust.Valid, Now.AddYears(-1)), Now);

        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Contains("時間戳", finding.Description);
    }

    [Fact]
    public void M1_03憑證過期且簽章無效判Warning()
        => Assert.Equal(CheckStatus.Warning, new M1_03_CertificateChainCheck(new StubVerifier())
            .Evaluate(Verdict(SignatureTrust.Expired, Now.AddYears(-1)), Now).Status);

    [Fact]
    public void M1_03取不到憑證期間判Inconclusive()
        => Assert.Equal(CheckStatus.Inconclusive, new M1_03_CertificateChainCheck(new StubVerifier())
            .Evaluate(Verdict(SignatureTrust.NoSignature, null), Now).Status);

    // ---- M1-04 下載來源 ----

    private static M1_04_DownloadSourceCheck Source(ZoneIdentifier? zone)
        => new(new StubZoneReader(zone));


    [Fact]
    public void M1_04官方安裝檔下載主機判Pass()
        // 官方下載頁指向 ncupdate.com；漏收這個網域會讓所有從官網下載的人被誤判
        => Assert.Equal(CheckStatus.Pass, Source(null).Evaluate(
            new ZoneIdentifier(3,
                "https://gs-purple-inst.download.ncupdate.com/Purple/PURPLE_Installer_2_26_803_19.exe",
                "https://lineageclassic.plaync.com/zh-tw/download/index"), "x").Status);

    [Fact]
    public void M1_04仿冒網域判Fail()
    {
        // 網域字串裡嵌了官方網域卻不是它的子網域 —— 只有刻意仿冒一種解釋
        var finding = Source(null)
            .Evaluate(new ZoneIdentifier(3, "https://plaync.com.evil.tw/x.exe", null), "x");

        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(40, finding.Score);
        Assert.Contains("仿冒", finding.Description);
    }

    [Fact]
    public void M1_04不在白名單但與官方無關者判Warning而非Fail()
    {
        // 白名單是靜態清單、必定不完整（官方隨時可能換 CDN）。
        // 漏收的代價不該由使用者承擔，更不該對從官網下載的人喊「假紫P，去重灌」。
        var finding = Source(null)
            .Evaluate(new ZoneIdentifier(3, "https://some-mirror.example.com/x.exe", null), "x");

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Contains("不一定代表有問題", finding.Description);
    }

    [Fact]
    public void M1_04ReferrerUrl為仿冒網域也判Fail()
    {
        // 技術設計 §4.5：HostUrl 與 ReferrerUrl 皆須檢查
        var finding = Source(null).Evaluate(
            new ZoneIdentifier(3,
                "https://gs-purple-inst.download.ncupdate.com/x.exe",
                "https://plaync.com.evil.tw/page"), "x");

        Assert.Equal(CheckStatus.Fail, finding.Status);
    }

    [Fact]
    public void M1_04沒有MOTW判Warning()
    {
        var finding = Source(null).Evaluate(null, "x");

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(20, finding.Score);
    }

    // ---- M1-05 未簽章模組 ----

    [Fact]
    public void M1_05全部已簽章判Pass()
        => Assert.Equal(CheckStatus.Pass,
            new M1_05_UnsignedModulesCheck(new StubVerifier()).Evaluate([], 42).Status);

    [Fact]
    public void M1_05有未簽章模組判Warning()
    {
        var finding = new M1_05_UnsignedModulesCheck(new StubVerifier())
            .Evaluate([(@"C:\x\evil.dll", SignatureTrust.NoSignature)], 42);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(10, finding.Score);
    }

    [Fact]
    public void M1_05被竄改的模組會特別點出並排在最前()
    {
        var finding = new M1_05_UnsignedModulesCheck(new StubVerifier()).Evaluate(
        [
            (@"C:\x\a.dll", SignatureTrust.NoSignature),
            (@"C:\x\b.dll", SignatureTrust.BadDigest),
        ], 42);

        Assert.Contains("已被竄改", finding.Description);
        Assert.Contains("b.dll", finding.Evidence[0].Value);
    }

    [Fact]
    public void M1_05沒有可掃描的檔案判Inconclusive()
        => Assert.Equal(CheckStatus.Inconclusive,
            new M1_05_UnsignedModulesCheck(new StubVerifier()).Evaluate([], 0).Status);

    // ---- M1-07 安裝位置 ----

    [Fact]
    public void M1_07正常路徑判Pass()
        => Assert.Equal(CheckStatus.Pass, new M1_07_InstallLocationCheck()
            .Evaluate(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NCSOFT", "PURPLE")).Status);

    [Fact]
    public void M1_07暫存目錄判Warning()
        => Assert.Equal(CheckStatus.Warning, new M1_07_InstallLocationCheck()
            .Evaluate(Path.Combine(Path.GetTempPath(), "PURPLE")).Status);

    [Fact]
    public void M1_07未取得路徑判Inconclusive()
        => Assert.Equal(CheckStatus.Inconclusive, new M1_07_InstallLocationCheck().Evaluate(null).Status);

    // ---- M1-08 時間關聯 ----

    private static EventRecordData Session(DateTimeOffset time)
        => new(time, 21, ["ASUS\\user", "10.0.0.1"]);

    [Fact]
    public void M1_08安裝時間附近沒有遠端連入判Pass()
        => Assert.Equal(CheckStatus.Pass, new M1_08_InstallTimeCorrelationCheck(new StubEventLog())
            .Evaluate(Now, [Session(Now.AddDays(-10))]).Status);

    [Fact]
    public void M1_08安裝時間附近有遠端連入判Warning()
    {
        var finding = new M1_08_InstallTimeCorrelationCheck(new StubEventLog())
            .Evaluate(Now, [Session(Now.AddHours(-2))]);

        Assert.Equal(CheckStatus.Warning, finding.Status);
        Assert.Equal(5, finding.Score);
    }

    [Fact]
    public void M1_08視窗邊界為前後24小時()
    {
        var check = new M1_08_InstallTimeCorrelationCheck(new StubEventLog());

        Assert.Equal(CheckStatus.Warning, check.Evaluate(Now, [Session(Now.AddHours(-23.9))]).Status);
        Assert.Equal(CheckStatus.Pass, check.Evaluate(Now, [Session(Now.AddHours(-24.1))]).Status);
    }

    [Fact]
    public void M1_08證據帶時間戳供時間軸使用()
    {
        var finding = new M1_08_InstallTimeCorrelationCheck(new StubEventLog())
            .Evaluate(Now, [Session(Now.AddHours(-2))]);

        Assert.All(finding.Evidence, e => Assert.True(e.Timestamp.HasValue));
    }
}
