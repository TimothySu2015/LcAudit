namespace LcAudit.Windows.Sources.RemoteTools;

/// <summary>
/// 遠端工具偵測特徵清單（功能規格附錄 B）。
/// <para>
/// 靜態清單，需隨工具版本更迭手動維護 —— 這類軟體改路徑、改服務名很頻繁，
/// 清單過時只會漏報不會誤報，但漏報同樣讓 M2-08 失去意義。
/// </para>
/// </summary>
public static class RemoteToolCatalog
{
    /// <summary>M2-06 專用：AnyDesk。</summary>
    public static readonly RemoteToolDefinition AnyDesk = new(
        "AnyDesk",
        [@"%ProgramData%\AnyDesk", @"%AppData%\AnyDesk"],
        ["AnyDesk"],
        [@"%ProgramData%\AnyDesk\connection_trace.txt", @"%AppData%\AnyDesk\connection_trace.txt"]);

    /// <summary>M2-07 專用：TeamViewer。</summary>
    public static readonly RemoteToolDefinition TeamViewer = new(
        "TeamViewer",
        [@"%ProgramFiles%\TeamViewer", @"%ProgramFiles(x86)%\TeamViewer", @"%AppData%\TeamViewer"],
        ["TeamViewer"],
        [
            @"%ProgramFiles%\TeamViewer\Connections_incoming.txt",
            @"%ProgramFiles(x86)%\TeamViewer\Connections_incoming.txt",
            @"%AppData%\TeamViewer\Connections_incoming.txt",
        ]);

    /// <summary>M2-08：其他遠端工具。</summary>
    public static readonly IReadOnlyList<RemoteToolDefinition> Others =
    [
        new("RustDesk",
            [@"%AppData%\RustDesk", @"%ProgramFiles%\RustDesk"],
            ["RustDesk"],
            []),

        new("ToDesk",
            [@"%ProgramFiles%\ToDesk", @"%ProgramFiles(x86)%\ToDesk", @"%AppData%\ToDesk"],
            ["ToDesk_Service"],
            []),

        new("向日葵 Sunlogin",
            [@"%ProgramFiles%\Oray", @"%ProgramFiles(x86)%\Oray"],
            ["SunloginService", "OrayRemoteService"],
            []),

        new("Chrome Remote Desktop",
            [@"%ProgramFiles(x86)%\Google\Chrome Remote Desktop"],
            ["chromoting"],
            []),

        new("AweSun",
            [@"%ProgramFiles%\AweRay", @"%ProgramFiles(x86)%\AweRay"],
            ["AweSunService", "AweRayRemoteService"],
            []),

        new("AnyViewer",
            [@"%ProgramFiles%\AnyViewer", @"%ProgramFiles(x86)%\AnyViewer"],
            ["AnyViewer"],
            []),

        new("DeskIn",
            [@"%ProgramFiles%\DeskIn", @"%ProgramFiles(x86)%\DeskIn"],
            ["DeskInService"],
            []),

        new("ScreenConnect / ConnectWise Control",
            [@"%ProgramFiles%\ScreenConnect Client", @"%ProgramFiles(x86)%\ScreenConnect Client"],
            ["ScreenConnect Client*"],
            []),

        new("Atera / Splashtop",
            [@"%ProgramFiles%\ATERA Networks", @"%ProgramFiles(x86)%\Splashtop"],
            ["AteraAgent", "SplashtopRemoteService"],
            []),

        new("UltraViewer",
            [@"%ProgramFiles%\UltraViewer", @"%ProgramFiles(x86)%\UltraViewer"],
            ["UltraViewer_Service"],
            []),
    ];

    /// <summary>全部工具，供整體掃描使用。</summary>
    public static IReadOnlyList<RemoteToolDefinition> All => [AnyDesk, TeamViewer, .. Others];
}
