using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 整合測試用的 PE 素材，一律在測試執行當下產生，不進版控。
/// <para>
/// 不把二進位檔提交進 repo 有三個理由：避免防毒對 repo 誤判、避免 <c>tampered.exe</c>
/// 這種故意壞掉的檔案被誤用、以及各機器可用的已簽章檔案不同。
/// </para>
/// </summary>
internal static class TestAssets
{
    private static readonly Lazy<string> Root = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "LcAudit.TestAssets", Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        return dir;
    });

    /// <summary>
    /// 一個具備有效**內嵌** Authenticode 簽章的檔案。
    /// <para>
    /// 不可用 <c>notepad.exe</c>／<c>kernel32.dll</c> —— 那些是「目錄簽章」(Catalog)，
    /// 複製出來的副本不受目錄保護，<c>WinVerifyTrust</c> 走 WTD_CHOICE_FILE 會判為未簽章。
    /// 技術設計 §7.1 建議用 notepad.exe 複本，那是錯的。
    /// </para>
    /// </summary>
    internal static string? FindEmbeddedSignedExecutable()
    {
        string?[] candidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe"),
            Environment.ProcessPath,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd", "git.exe"),
        ];

        return candidates.FirstOrDefault(p => p is not null && File.Exists(p));
    }

    /// <summary>未簽章的 PE —— 用本方案自行編譯的組件，保證未簽章。</summary>
    internal static string CreateUnsigned()
    {
        var source = typeof(Sources.AuthenticodeVerifier).Assembly.Location;
        var target = Path.Combine(Root.Value, "unsigned.dll");
        File.Copy(source, target, overwrite: true);
        return target;
    }

    /// <summary>已簽章但內容被改動一個位元組 —— 應判為 BadDigest。</summary>
    internal static string? CreateTampered()
    {
        var signed = FindEmbeddedSignedExecutable();
        if (signed is null)
        {
            return null;
        }

        var target = Path.Combine(Root.Value, "tampered.exe");
        File.Copy(signed, target, overwrite: true);

        // 改動檔案中段的一個位元組。避開 PE 標頭，確保落在被簽章涵蓋的內容區。
        using var stream = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Seek(stream.Length / 2, SeekOrigin.Begin);
        var original = stream.ReadByte();
        stream.Seek(stream.Length / 2, SeekOrigin.Begin);
        stream.WriteByte((byte)(original ^ 0xFF));

        return target;
    }

    /// <summary>
    /// <b>回歸測試的守門員</b>：未簽章，但檔案裡塞了一張憑證。
    /// <para>
    /// 這就是 <c>CreateFromSignedFile</c> 與 <c>CERT_QUERY_CONTENT_FLAG_ALL</c> 會中的招 ——
    /// 它們會在檔案任意位置找到這張憑證並回報「簽章者 = NCSOFT Corporation」。
    /// 任何一次重構若讓這個檔案被判為「已簽章」，代表有人把禁忌 API 寫回去了。
    /// </para>
    /// </summary>
    internal static string CreateCertificateEmbeddedUnsigned()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=PURPLE Launcher, O=NCSOFT Corporation, C=KR",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        var target = Path.Combine(Root.Value, "cert-embedded-unsigned.exe");
        var peBytes = File.ReadAllBytes(CreateUnsigned());

        using var stream = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
        stream.Write(peBytes);
        stream.Write(certificate.Export(X509ContentType.Cert));

        return target;
    }
}
