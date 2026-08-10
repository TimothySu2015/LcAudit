using Microsoft.Win32;

namespace LcAudit.Windows.Sources.RemoteTools;

/// <summary>遠端工具痕跡掃描（M2-06 / M2-07 / M2-08）。</summary>
public interface IRemoteToolScanner
{
    RemoteToolTrace Scan(RemoteToolDefinition tool);

    /// <summary>讀取連入紀錄檔內容；讀不到回 <c>null</c>。</summary>
    string? ReadTextFile(string path);
}

/// <inheritdoc cref="IRemoteToolScanner"/>
public sealed class RemoteToolScanner : IRemoteToolScanner
{
    private const string ServicesKeyPath = @"SYSTEM\CurrentControlSet\Services";

    public RemoteToolTrace Scan(RemoteToolDefinition tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        var directories = tool.Directories.Select(Expand).Where(Directory.Exists).ToList();

        return new RemoteToolTrace(
            tool,
            directories,
            [.. FindServices(tool.ServiceNames)],
            [.. tool.IncomingLogFiles.Select(Expand).Where(File.Exists)],
            EstimateInstallTime(directories));
    }

    /// <summary>
    /// 以目錄建立時間中最早者推估安裝時間。
    /// <para>
    /// 是推估值：解壓縮、複製、還原備份都可能改變建立時間。但對使用者而言，
    /// 一個大概的時間點遠比「請你自己回想有沒有授權過」有用得多。
    /// </para>
    /// </summary>
    private static DateTimeOffset? EstimateInstallTime(IReadOnlyList<string> directories)
    {
        DateTimeOffset? earliest = null;

        foreach (var directory in directories)
        {
            try
            {
                var created = new DateTimeOffset(Directory.GetCreationTime(directory));
                if (earliest is null || created < earliest)
                {
                    earliest = created;
                }
            }
            catch (SystemException)
            {
                // 讀不到就算了，不影響其餘判定
            }
        }

        return earliest;
    }

    public string? ReadTextFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            // share mode 必須給滿 —— 這些紀錄檔往往正被遠端工具自己開著寫入，
            // 給不夠會反過來害對方的檔案操作失敗（唯讀原則不只是不寫，也包含不干擾）。
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static IEnumerable<string> FindServices(IReadOnlyList<string> serviceNames)
    {
        if (serviceNames.Count == 0)
        {
            yield break;
        }

        using var servicesKey = Registry.LocalMachine.OpenSubKey(ServicesKeyPath);
        if (servicesKey is null)
        {
            yield break;
        }

        // 前綴比對的清單需要列舉，完全比對的直接開子鍵即可 —— 只在必要時列舉。
        var prefixes = serviceNames.Where(n => n.EndsWith('*')).Select(n => n[..^1]).ToList();
        var existingNames = prefixes.Count > 0 ? servicesKey.GetSubKeyNames() : [];

        foreach (var serviceName in serviceNames)
        {
            if (serviceName.EndsWith('*'))
            {
                var prefix = serviceName[..^1];
                foreach (var found in existingNames.Where(n =>
                             n.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return found;
                }

                continue;
            }

            using var key = servicesKey.OpenSubKey(serviceName);
            if (key is not null)
            {
                yield return serviceName;
            }
        }
    }

    /// <summary>展開環境變數。<c>%ProgramFiles(x86)%</c> 在 64 位元行程下可正常展開。</summary>
    private static string Expand(string path) => Environment.ExpandEnvironmentVariables(path);
}
