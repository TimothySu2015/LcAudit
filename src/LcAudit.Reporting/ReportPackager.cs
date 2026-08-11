using System.IO.Compression;
using LcAudit.Core.Model;

namespace LcAudit.Reporting;

/// <summary>
/// 把報告檔壓成單一 zip，方便使用者一次寄出。
/// <para>
/// 只做壓縮，**不做傳送**。原因見 <see cref="MailDraft"/> 的說明。
/// </para>
/// </summary>
public sealed class ReportPackager
{
    /// <summary>
    /// 將指定的報告檔壓縮成 zip，回傳壓縮檔路徑。
    /// <para>壓縮檔與報告檔放在同一個目錄底下（NFR-03：只寫 <c>--output</c> 目錄）。</para>
    /// </summary>
    public string Package(AuditReport report, DirectoryInfo outputDirectory, IReadOnlyList<string> files)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(outputDirectory);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentOutOfRangeException.ThrowIfZero(files.Count);

        var zipPath = Path.Combine(outputDirectory.FullName, $"{ReportWriter.BuildBaseName(report)}.zip");

        // 覆寫既有檔案，避免同一秒內重跑時因檔案已存在而失敗
        if (File.Exists(zipPath))
        {
            File.Delete(zipPath);
        }

        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);

        foreach (var file in files.Where(File.Exists))
        {
            archive.CreateEntryFromFile(file, Path.GetFileName(file), CompressionLevel.Optimal);
        }

        return zipPath;
    }
}
