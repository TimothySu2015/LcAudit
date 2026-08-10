using Microsoft.Win32;

namespace LcAudit.Windows.Sources;

/// <summary>
/// 依序從三個來源探測紫P 安裝路徑（功能規格 M1-00）：
/// 登錄檔 Uninstall 鍵 → 常見安裝路徑 → 執行中處理程序。
/// <para>
/// 第三個來源在遊戲關閉時會失效，這是預期行為 —— 前兩者才是主力。
/// 三者皆落空時回 <c>null</c>，由 M1-00 判 Inconclusive 並提示使用 <c>--purple-path</c>。
/// </para>
/// </summary>
public sealed class PurplePathProbe(IProcessInspector processInspector) : IPurplePathProbe
{
    private static readonly string[] UninstallKeyPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    /// <summary>Uninstall 鍵的 DisplayName 需含這些關鍵字之一才視為紫P。</summary>
    private static readonly string[] DisplayNameKeywords = ["purple", "ncsoft", "plaync"];

    /// <summary>執行中處理程序的名稱比對清單。</summary>
    private static readonly string[] ProcessNames = ["Purple", "PurpleLauncher", "NCLauncher", "NCLauncherU"];

    public PurplePathProbeResult Probe()
    {
        var attempted = new List<string>();

        attempted.Add("登錄檔 Uninstall 鍵");
        if (TryFromRegistry() is { } fromRegistry)
        {
            return new PurplePathProbeResult(fromRegistry, "登錄檔 Uninstall 鍵", attempted);
        }

        attempted.Add("常見安裝路徑");
        if (TryFromWellKnownPaths() is { } fromPath)
        {
            return new PurplePathProbeResult(fromPath, "常見安裝路徑", attempted);
        }

        attempted.Add("執行中處理程序");
        if (TryFromRunningProcess() is { } fromProcess)
        {
            return new PurplePathProbeResult(fromProcess, "執行中處理程序", attempted);
        }

        return new PurplePathProbeResult(null, null, attempted);
    }

    private static string? TryFromRegistry()
    {
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var keyPath in UninstallKeyPaths)
            {
                using var uninstallKey = hive.OpenSubKey(keyPath);
                if (uninstallKey is null)
                {
                    continue;
                }

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    using var entry = uninstallKey.OpenSubKey(subKeyName);
                    if (entry?.GetValue("DisplayName") is not string displayName)
                    {
                        continue;
                    }

                    if (!DisplayNameKeywords.Any(k =>
                            displayName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    if (entry.GetValue("InstallLocation") is string location
                        && !string.IsNullOrWhiteSpace(location)
                        && Directory.Exists(location))
                    {
                        return Path.TrimEndingDirectorySeparator(location);
                    }
                }
            }
        }

        return null;
    }

    private static string? TryFromWellKnownPaths()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string[] candidates =
        [
            Path.Combine(programFiles, "NCSOFT", "PURPLE"),
            Path.Combine(programFilesX86, "NCSOFT", "PURPLE"),
            Path.Combine(programFiles, "PURPLE"),
            Path.Combine(programFilesX86, "PURPLE"),
            Path.Combine(localAppData, "Programs", "PURPLE"),
        ];

        return candidates.FirstOrDefault(Directory.Exists);
    }

    private string? TryFromRunningProcess()
    {
        var names = ProcessNames.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var process in processInspector.ListProcesses())
        {
            if (!names.Contains(process.Name))
            {
                continue;
            }

            // 只有在名稱命中時才開 handle，且走 PROCESS_QUERY_LIMITED_INFORMATION。
            var imagePath = processInspector.TryGetImagePath(process.ProcessId);
            if (imagePath is not null)
            {
                return Path.GetDirectoryName(imagePath);
            }
        }

        return null;
    }
}
