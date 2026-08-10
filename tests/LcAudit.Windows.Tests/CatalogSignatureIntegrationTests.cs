using LcAudit.Windows.Sources;
using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 目錄簽章（Catalog）驗證。
/// <para>
/// Windows 系統檔案沒有內嵌簽章，而是由 CatRoot 的 <c>.cat</c> 目錄檔集中背書。
/// 只驗內嵌會把整個作業系統判成未簽章 —— 實測顯示 M3-08 的 150 個自動啟動服務
/// 會誤標 13 個、M3-06 的 16 個啟動項會誤標 6 個。
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class CatalogSignatureIntegrationTests
{
    private readonly AuthenticodeVerifier _verifier = new();

    private static string SystemFile(string relativePath)
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), relativePath);

    [Fact]
    public void 目錄簽章的系統檔案只驗內嵌會判為未簽章()
    {
        var notepad = SystemFile("notepad.exe");
        if (!File.Exists(notepad))
        {
            return;
        }

        // 這是刻意的行為，M1 依賴它 —— 紫P 必須有自己的內嵌簽章
        Assert.Equal(SignatureTrust.NoSignature, _verifier.Verify(notepad).Trust);
    }

    [Fact]
    public void 目錄簽章的系統檔案含目錄驗證後判為有效()
    {
        var notepad = SystemFile("notepad.exe");
        if (!File.Exists(notepad))
        {
            return;
        }

        var verdict = _verifier.VerifyIncludingCatalog(notepad);

        Assert.Equal(SignatureTrust.Valid, verdict.Trust);
        Assert.True(verdict.IsCatalogSigned);
    }

    /// <summary>
    /// <b>關鍵性質</b>：加上目錄查詢後，真正未簽章的檔案仍必須判為未簽章。
    /// 若目錄查詢變成「什麼都放行」，M3-06／M3-08 就完全失去意義。
    /// </summary>
    [Fact]
    public void 真正未簽章的檔案不會被目錄驗證救回來()
    {
        var unsigned = TestAssets.CreateUnsigned();

        Assert.Equal(SignatureTrust.NoSignature, _verifier.Verify(unsigned).Trust);
        Assert.Equal(SignatureTrust.NoSignature, _verifier.VerifyIncludingCatalog(unsigned).Trust);
        Assert.False(_verifier.VerifyIncludingCatalog(unsigned).IsCatalogSigned);
    }

    [Fact]
    public void 內嵌簽章有效時不標記為目錄簽章()
    {
        var signed = TestAssets.FindEmbeddedSignedExecutable();
        if (signed is null)
        {
            return;
        }

        var verdict = _verifier.VerifyIncludingCatalog(signed);

        Assert.Equal(SignatureTrust.Valid, verdict.Trust);
        Assert.False(verdict.IsCatalogSigned);
    }

    [Fact]
    public void 被竄改的檔案不會被目錄驗證救回來()
    {
        var tampered = TestAssets.CreateTampered();
        if (tampered is null)
        {
            return;
        }

        // 竄改後雜湊改變，目錄中找不到對應項目 —— 必須維持 BadDigest
        Assert.Equal(SignatureTrust.BadDigest, _verifier.VerifyIncludingCatalog(tampered).Trust);
    }

    [Fact]
    public void 不存在的檔案不會因目錄查詢而拋例外()
        => Assert.Equal(
            SignatureTrust.FileNotReadable,
            _verifier.VerifyIncludingCatalog(Path.Combine(Path.GetTempPath(), "no-such-9c2f.exe")).Trust);
}
