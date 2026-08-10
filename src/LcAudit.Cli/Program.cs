using System.CommandLine;
using System.Text;
using LcAudit.Cli;
using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;
using LcAudit.Core.Pipeline;
using LcAudit.Core.Scoring;
using LcAudit.Reporting;
using LcAudit.Windows.Checks.M1;
using LcAudit.Windows.Checks.M2;
using LcAudit.Windows.Sources;
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

var root = new RootCommand("天堂：經典版 帳號安全稽核工具")
{
    daysOption,
    purplePathOption,
    outputOption,
    skipModuleOption,
    formatOption,
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
    };

    return RunAsync(options, ct);
});

return await root.Parse(args).InvokeAsync();

static async Task<int> RunAsync(AuditOptions options, CancellationToken ct)
{
    var console = AnsiConsole.Console;

    console.Write(new Rule("[bold]天堂：經典版 帳號安全稽核工具[/]").LeftJustified());
    console.WriteLine();

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
        ProtectedPids = protectedPids,
        PurpleInstallPath = options.PurplePath,
    };

    var result = await provider.GetRequiredService<AuditRunner>().RunAsync(context, ct);

    var report = new AuditReport
    {
        ScannedAt = DateTimeOffset.Now,
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

    WriteReportFiles(console, provider, report, options);

    // 結束代碼即風險等級（功能規格 §7.1）。這是 Console App 的對外契約。
    return (int)report.Summary.Level;
}

static void WriteReportFiles(
    IAnsiConsole console,
    IServiceProvider provider,
    AuditReport report,
    AuditOptions options)
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

    // Reporting
    services.AddSingleton<HtmlReporter>();
    services.AddSingleton<JsonReporter>();
    services.AddSingleton<ReportWriter>();

    // Checks —— 每個都包一層 SafeCheckDecorator（NFR-04）
    RegisterCheck<M1_00_InstallPathCheck>(services);
    RegisterCheck<M1_01_SignatureStatusCheck>(services);
    RegisterCheck<M1_02_SignerIdentityCheck>(services);
    RegisterCheck<M2_00_LogClearedCheck>(services);
    RegisterCheck<M2_01_RemoteInteractiveLogonCheck>(services);
    RegisterCheck<M2_02_NetworkLogonCheck>(services);
    RegisterCheck<M2_03_LogonFailureBurstCheck>(services);

    services.AddSingleton<AuditRunner>();

    return services;
}

static void RegisterCheck<TCheck>(IServiceCollection services)
    where TCheck : class, ICheck
    => services.AddSingleton<ICheck>(sp => new SafeCheckDecorator(
        ActivatorUtilities.CreateInstance<TCheck>(sp),
        sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<SafeCheckDecorator>>()));
