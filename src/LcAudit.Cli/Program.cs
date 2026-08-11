using System.CommandLine;
using System.Globalization;
using System.Text;
using LcAudit.Cli;
using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Pipeline;
using LcAudit.Core.Scoring;
using LcAudit.Reporting;
using LcAudit.Windows.Checks.M1;
using LcAudit.Windows.Checks.M2;
using LcAudit.Windows.Checks.M3;
using LcAudit.Windows.Checks.M4;
using LcAudit.Windows.Sources;
using LcAudit.Windows.Sources.RemoteTools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Spectre.Console;

// 舊版主控台顯示繁中會亂碼，必須在任何輸出之前設定。
Console.OutputEncoding = Encoding.UTF8;

var daysOption = new Option<int>("--days")
{
    Description = "事件回溯天數",
    DefaultValueFactory = _ => 90,
};

var purplePathOption = new Option<string?>("--purple-path")
{
    Description = "手動指定紫P 安裝目錄，跳過自動探測",
};

var outputOption = new Option<DirectoryInfo>("--output")
{
    Description = "報告輸出目錄",
    DefaultValueFactory = _ => new DirectoryInfo(@".\LcAudit-Report"),
};

var skipModuleOption = new Option<string[]>("--skip-module")
{
    Description = "跳過指定模組，如 --skip-module M3 M4",
    AllowMultipleArgumentsPerToken = true,
};

var formatOption = new Option<ReportFormat>("--format")
{
    Description = "報告格式：Console / Json / Html / All",
    DefaultValueFactory = _ => ReportFormat.All,
};

var incidentTimeOption = new Option<string?>("--incident-time")
{
    Description = "事發時間，如 \"2026-08-09 02:00\"。若知道確切範圍，再搭配 --incident-end",
};

var emailOption = new Option<bool>("--email")
{
    Description = "送出報告請作者協助分析（預設關閉；送出前會列出內容並請你確認）",
};

var incidentEndOption = new Option<string?>("--incident-end")
{
    Description = "事發區間的結束時間，如 \"2026-08-09 07:30\"（發現被盜的時間）",
};

var root = new RootCommand("天堂：經典版 帳號安全稽核工具")
{
    daysOption,
    purplePathOption,
    outputOption,
    skipModuleOption,
    formatOption,
    incidentTimeOption,
    incidentEndOption,
    emailOption,
};

root.SetAction((ParseResult parseResult, CancellationToken ct) =>
{
    var options = new AuditOptions
    {
        LookbackDays = parseResult.GetValue(daysOption),
        PurplePath = parseResult.GetValue(purplePathOption),
        OutputPath = parseResult.GetValue(outputOption)!,
        SkipModules = (parseResult.GetValue(skipModuleOption) ?? [])
            .ToHashSet(StringComparer.OrdinalIgnoreCase),
        Format = parseResult.GetValue(formatOption),
        IncidentWindow = BuildIncidentWindow(
            ParseIncidentTime(parseResult.GetValue(incidentTimeOption)),
            ParseIncidentTime(parseResult.GetValue(incidentEndOption))),
        Email = parseResult.GetValue(emailOption),
    };

    return RunAsync(options, ct);
});

return await root.Parse(args).InvokeAsync();

/// <summary>
/// 寬鬆解析使用者輸入的事發時間。
/// <para>
/// 使用者會用各種寫法（<c>2026-08-05 03:20</c>、<c>2026/8/5 3:20</c>、只有日期…），
/// 解析不出來就當作沒提供 —— 不該因為時間格式打錯就讓整個掃描失敗。
/// </para>
/// </summary>
static DateTimeOffset? ParseIncidentTime(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    if (DateTimeOffset.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var parsed)
        || DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out parsed))
    {
        return parsed;
    }

    AnsiConsole.MarkupLine(
        $"[yellow]無法解析事發時間「{Markup.Escape(value)}」，已忽略。"
        + "請用類似 \"2026-08-05 03:20\" 的格式。[/]");

    return null;
}

/// <summary>
/// 由起訖時間組出事發區間。
/// <para>
/// 受害者給得出的通常是「幾點還好、幾點發現不見」的範圍，而不是一個時間點 ——
/// 只給單一時間時退化為零長度區間。
/// </para>
/// </summary>
static IncidentWindow? BuildIncidentWindow(DateTimeOffset? start, DateTimeOffset? end)
{
    if (start is not { } from)
    {
        // 只給結束時間也算數 —— 使用者可能只知道「發現的時間」
        return end is { } only ? IncidentWindow.At(only) : null;
    }

    return end is { } to ? IncidentWindow.Between(from, to) : IncidentWindow.At(from);
}

static async Task<int> RunAsync(AuditOptions options, CancellationToken ct)
{
    var console = AnsiConsole.Console;

    console.Write(new Rule($"[bold]天堂：經典版 帳號安全稽核工具[/] [grey]v{ToolVersion.Current}[/]").LeftJustified());
    console.WriteLine();

    // 由檔案總管雙擊啟動、且沒帶任何參數 —— 使用者多半不會打指令，改走引導流程
    var guided = options.IsDefaultRun && ConsoleLaunch.IsOwnConsole();

    if (guided)
    {
        InteractiveWizard.WriteIntro(console);

        if (!PreFlight.IsElevated() && InteractiveWizard.OfferElevation(console, []))
        {
            // 已在新視窗以系統管理員身分重新啟動，本行程結束
            return 0;
        }

        // 不是每個人都是出事了才來 —— 只想順手檢查電腦的人不該被問「什麼時候被盜」
        if (InteractiveWizard.AskIsIncidentInvestigation(console))
        {
            options = options with { IncidentWindow = InteractiveWizard.AskIncidentWindow(console) };
        }
    }

    var services = BuildServices();
    await using var provider = services.BuildServiceProvider();

    var isElevated = PreFlight.IsElevated();
    var protectedPids = GameProcessDetector.DetectProtectedPids(
        provider.GetRequiredService<IProcessInspector>());

    PreFlight.WriteWarnings(console, isElevated, protectedPids);

    var context = new AuditContext
    {
        IsElevated = isElevated,
        LookbackDays = options.LookbackDays,
        SkippedModules = options.SkipModules,
        IncidentWindow = options.IncidentWindow,
        ProtectedPids = protectedPids,
        PurpleInstallPath = options.PurplePath,
    };

    var result = await provider.GetRequiredService<AuditRunner>().RunAsync(context, ct);

    var report = new AuditReport
    {
        ToolVersion = ToolVersion.Current,
        ReportId = Guid.NewGuid().ToString("N"),
        ScannedAt = DateTimeOffset.Now,
        IncidentWindow = options.IncidentWindow,
        IsElevated = isElevated,
        Host = new HostInfo
        {
            ComputerName = Environment.MachineName,
            OsVersion = Environment.OSVersion.VersionString,
            TimeZone = TimeZoneInfo.Local.Id,
        },
        Summary = result.Summary,
        Findings = result.Findings,
    };

    if (options.Format.HasFlag(ReportFormat.Console))
    {
        new ConsoleReporter(console).Write(report);
    }

    WriteReportFiles(console, provider, report, options, askToUpload: guided);

    // 雙擊執行時視窗會直接關掉，停住讓使用者看得到結果
    if (guided)
    {
        InteractiveWizard.WaitBeforeExit(console);
    }

    // 結束代碼即風險等級（功能規格 §7.1）。這是 Console App 的對外契約。
    return (int)report.Summary.Level;
}

static void WriteReportFiles(
    IAnsiConsole console,
    IServiceProvider provider,
    AuditReport report,
    AuditOptions options,
    bool askToUpload)
{
    // 寫檔失敗不該讓已完成的掃描結果化為烏有 —— Console 已經輸出過了。
    try
    {
        var written = provider.GetRequiredService<ReportWriter>()
                              .Write(report, options.OutputPath, options.Format);

        if (written.Count == 0)
        {
            return;
        }

        console.WriteLine();
        foreach (var path in written)
        {
            console.MarkupLine($"[green]已輸出報告：[/]{Markup.Escape(path)}");
        }

        var wantsUpload = options.Email;

        // 引導模式：使用者沒打參數，所以主動問一次要不要請人幫忙看
        if (!wantsUpload && askToUpload)
        {
            console.WriteLine();
            console.Write(new Rule("[bold]需要作者協助分析嗎？[/]").LeftJustified());
            console.MarkupLine("[grey]這項功能[/][bold]預設關閉[/][grey]。報告已經存在你的電腦裡，不送出完全不影響結果。[/]");
            console.MarkupLine("[grey]只有在你看不懂報告、需要作者幫忙判讀時，才需要送出。[/]");
            console.MarkupLine("[grey]送出的內容僅用於分析你這台電腦的資安弱點，不作其他用途。[/]");
            console.WriteLine();

            wantsUpload = console.Confirm("要送出給作者協助分析嗎？", defaultValue: false);
        }

        if (!wantsUpload)
        {
            return;
        }

        var zipPath = provider.GetRequiredService<ReportPackager>()
                              .Package(report, options.OutputPath, written);

        if (!ReportUploader.Confirm(console, zipPath, report.ReportId))
        {
            // 使用者不上傳，仍協助他自行寄送
            MailDraft.Open(console, zipPath, report.ReportId);
            return;
        }

        if (!ReportUploader.UploadAsync(console, zipPath, report.ReportId, CancellationToken.None)
                           .GetAwaiter().GetResult())
        {
            MailDraft.Open(console, zipPath, report.ReportId);
        }
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        console.WriteLine();
        console.MarkupLine($"[red]報告檔寫入失敗：[/]{Markup.Escape(ex.Message)}");
        console.MarkupLine("[grey]Console 輸出的結果仍然有效，可手動複製保存。[/]");
    }
}

static ServiceCollection BuildServices()
{
    var services = new ServiceCollection();

    services.AddSingleton(NullLoggerFactory.Instance);
    services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(NullLogger<>));

    // Sources
    services.AddSingleton<IProcessInspector, ProcessInspector>();
    services.AddSingleton<IPurplePathProbe, PurplePathProbe>();
    services.AddSingleton<IAuthenticodeVerifier, AuthenticodeVerifier>();

    // Scoring
    services.AddSingleton<IRiskScorer, RiskScorer>();
    services.AddSingleton<IInferenceEngine, InferenceEngine>();

    services.AddSingleton<IWindowsEventLog, WindowsEventLog>();
    services.AddSingleton<IRemoteToolScanner, RemoteToolScanner>();
    services.AddSingleton<IZoneIdentifierReader, ZoneIdentifierReader>();
    services.AddSingleton<IRegistryReader, RegistryReader>();
    services.AddSingleton<ITcpConnectionSource, TcpConnectionSource>();
    services.AddSingleton<ILocalAccountSource, LocalAccountSource>();

    // Reporting
    services.AddSingleton<HtmlReporter>();
    services.AddSingleton<JsonReporter>();
    services.AddSingleton<ReportWriter>();
    services.AddSingleton<ReportPackager>();

    // Checks —— 每個都包一層 SafeCheckDecorator（NFR-04）
    RegisterCheck<M1_00_InstallPathCheck>(services);
    RegisterCheck<M1_01_SignatureStatusCheck>(services);
    RegisterCheck<M1_02_SignerIdentityCheck>(services);
    RegisterCheck<M1_03_CertificateChainCheck>(services);
    RegisterCheck<M1_04_DownloadSourceCheck>(services);
    RegisterCheck<M1_05_UnsignedModulesCheck>(services);
    RegisterCheck<M1_06_SuspiciousFileNameCheck>(services);
    RegisterCheck<M1_07_InstallLocationCheck>(services);
    RegisterCheck<M1_08_InstallTimeCorrelationCheck>(services);
    RegisterCheck<M2_00_LogClearedCheck>(services);
    RegisterCheck<M2_01_RemoteInteractiveLogonCheck>(services);
    RegisterCheck<M2_02_NetworkLogonCheck>(services);
    RegisterCheck<M2_03_LogonFailureBurstCheck>(services);
    RegisterCheck<M2_04_TerminalServicesSessionCheck>(services);
    RegisterCheck<M2_05_RdpClientCheck>(services);
    RegisterCheck<M2_06_AnyDeskCheck>(services);
    RegisterCheck<M2_07_TeamViewerCheck>(services);
    RegisterCheck<M2_08_OtherRemoteToolsCheck>(services);
    RegisterCheck<M2_09_RdpBitmapCacheCheck>(services);
    RegisterCheck<M2_10_LockUnlockTimelineCheck>(services);
    RegisterCheck<M3_01_RdpEnabledCheck>(services);
    RegisterCheck<M3_02_RdpPortCheck>(services);
    RegisterCheck<M3_03_RemoteDesktopUsersCheck>(services);
    RegisterCheck<M3_04_LocalAccountsCheck>(services);
    RegisterCheck<M3_05_AdministratorsGroupCheck>(services);
    RegisterCheck<M3_06_AutoStartCheck>(services);
    RegisterCheck<M3_08_UnexpectedServicesCheck>(services);
    RegisterCheck<M3_10_DefenderExclusionsCheck>(services);
    RegisterCheck<M3_11_DefenderStatusCheck>(services);
    RegisterCheck<M3_13_HostsFileCheck>(services);
    RegisterCheck<M4_01_PurpleConnectionsCheck>(services);
    RegisterCheck<M4_02_ListeningPortsCheck>(services);
    RegisterCheck<M4_03_UnsignedOutboundCheck>(services);
    RegisterCheck<M4_04_KnownRemoteServiceCheck>(services);

    services.AddSingleton<AuditRunner>();

    return services;
}

static void RegisterCheck<TCheck>(IServiceCollection services)
    where TCheck : class, ICheck
    => services.AddSingleton<ICheck>(sp => new SafeCheckDecorator(
        ActivatorUtilities.CreateInstance<TCheck>(sp),
        sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<SafeCheckDecorator>>()));
