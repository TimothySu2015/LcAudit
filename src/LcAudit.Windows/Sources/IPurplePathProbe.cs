namespace LcAudit.Windows.Sources;

/// <summary>紫P 安裝路徑的探測結果。</summary>
/// <param name="InstallPath">探測到的安裝目錄；找不到為 <c>null</c>。</param>
/// <param name="DiscoveredVia">探測來源描述，如「登錄檔 Uninstall 鍵」。</param>
/// <param name="AttemptedSources">已嘗試的來源，供 Inconclusive 時說明。</param>
public sealed record PurplePathProbeResult(
    string? InstallPath,
    string? DiscoveredVia,
    IReadOnlyList<string> AttemptedSources);

/// <summary>M1-00 安裝路徑探測。</summary>
public interface IPurplePathProbe
{
    PurplePathProbeResult Probe();
}
