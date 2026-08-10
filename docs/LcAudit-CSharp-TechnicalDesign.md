# LcAudit — C# / .NET 10 技術設計文件

| 項目 | 內容 |
|---|---|
| 文件版本 | v1.0 |
| 日期 | 2026-08-10 |
| 上游文件 | `LineageClassic-SecurityAudit-Spec.md`（功能規格 v1.0） |
| 目標框架 | .NET 10 (LTS, 2025-11-11 GA) |
| 本文範圍 | 技術架構、專案結構、Interop 規格、關鍵實作骨架 |

> 本文件**取代**功能規格 §3（技術選型）與附錄 A。功能需求 FR-M1～FR-M4、風險評分 FR-S、非功能需求 NFR 全數沿用，但 NFR-07（PowerShell 5.1 語法限制）作廢。

---

## 0. 開始前必讀：一個會讓整個工具失效的陷阱

實作 M1-01 / M1-02（數位簽章驗證）時，**絕對不要使用 `X509Certificate.CreateFromSignedFile()`**。

原因：
1. 該方法在 .NET 9+ 已標記為過時（`SYSLIB0057`）。<cite index="32-1">官方標註為 Obsolete，並建議改用 X509CertificateLoader 載入憑證。</cite>
2. 更嚴重的是它**根本不做簽章驗證**。<cite index="35-1">它內部呼叫 CryptQueryObject 並傳入 CERT_QUERY_CONTENT_FLAG_ALL，而該旗標會在檔案的任意位置尋找任何看起來像密碼學物件的內容，包含嵌入資源與內容區段，而不只是 Authenticode 簽章。</cite>
3. 這是一個有名的漏洞樣式。<cite index="31-1">此模式已在多個產品中重複出現，安全稽核時屢見不鮮；實務上驗證簽章的唯一方式是 P/Invoke WinVerifyTrust。</cite>

**對本工具的直接後果**：偽造的紫P 只要把 NCSOFT 的公開憑證（可從任何官方簽章檔案抽出，非機密）當成資源塞進 PE 檔，`CreateFromSignedFile` 就會回報「簽章者 = NCSOFT Corporation」，M1-02 直接 Pass。整個工具的核心檢查會被最容易的手法繞過。

**強制規定**：
- `Status` 判定 → `WinVerifyTrust`（`WINTRUST_ACTION_GENERIC_VERIFY_V2`）
- `Signer` 抽取 → `CryptQueryObject` 且旗標必須是 `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED`（**不是** `_ALL`）
- 兩者皆通過才算 Pass；`X509CertificateLoader` 在此情境不適用（它只載入憑證檔，不解 Authenticode）
- 建議在 `Directory.Build.props` 加入 `<NoWarn>` 白名單管控，並以 Roslyn Analyzer 或單元測試斷言原始碼中不出現 `CreateFromSignedFile`

---

## 1. 專案結構

```
LcAudit.sln
├── Directory.Build.props
├── Directory.Packages.props          # Central Package Management
├── src/
│   ├── LcAudit.Core/                 # net10.0        — 純領域，無 Windows 相依
│   │   ├── Model/                    # Finding, Severity, CheckStatus, AuditReport
│   │   ├── Abstractions/             # ICheck, IEvidenceSource, IRiskScorer
│   │   ├── Scoring/                  # RiskScorer, InferenceEngine
│   │   └── Pipeline/                 # AuditRunner, SafeCheckDecorator
│   ├── LcAudit.Windows/              # net10.0-windows — 採集器 + Interop
│   │   ├── Interop/                  # LibraryImport 宣告
│   │   ├── Sources/                  # 原始資料存取（Registry/EventLog/FileSystem/Net）
│   │   └── Checks/M1 M2 M3 M4/       # ICheck 實作，一個檢查項一個類別
│   ├── LcAudit.Reporting/            # net10.0        — Console/Json/Html
│   └── LcAudit.Cli/                  # net10.0-windows — 進入點、DI 組裝
└── tests/
    ├── LcAudit.Core.Tests/           # 評分與推論引擎（跨平台可跑）
    ├── LcAudit.Windows.Tests/        # Interop 與採集器（Windows only）
    └── LcAudit.TestAssets/           # 已簽章/未簽章/竄改的測試檔
```

### 1.1 分層原則

| 層 | 相依方向 | 說明 |
|---|---|---|
| `Core` | 不相依任何人 | `Finding` 為 record；`ICheck` 為唯一擴充點。**評分與推論邏輯全在此層**，因此可在 Linux CI 上完整單元測試 |
| `Windows` | → `Core` | 所有 Win32 接觸點；`Sources` 與 `Checks` 分離，讓 Check 的判定邏輯可用 fake source 測試 |
| `Reporting` | → `Core` | 只吃 `AuditReport`，不知道 Windows 存在 |
| `Cli` | → 全部 | 只做參數解析與 DI 組裝 |

**關鍵設計**：`Checks` 不直接呼叫 Win32，而是透過 `Sources` 介面。例如 `M1_02_SignerIdentityCheck` 依賴 `IAuthenticodeVerifier`，這樣「網域白名單後綴比對邏輯」「簽章者字串比對邏輯」這些最容易寫錯的部分都能純單元測試。

---

## 2. 相依套件

`Directory.Packages.props`：

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="System.CommandLine" Version="2.0.10" />
    <PackageVersion Include="Spectre.Console" Version="0.*" />
    <PackageVersion Include="System.Diagnostics.EventLog" Version="10.0.0" />
    <PackageVersion Include="System.Management" Version="10.0.0" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="10.0.0" />
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.0" />
  </ItemGroup>
</Project>
```

| 套件 | 用途 | 備註 |
|---|---|---|
| `System.CommandLine` 2.0.10 | CLI 參數解析 | 2025-11 已 GA。注意 API 與 beta4 差異大：`SetHandler` → `SetAction`，`InvocationContext` 移除，改直接接 `ParseResult` |
| `Spectre.Console` | Console 報告的表格與色彩 | 非必要，但 §8.1 的分色輸出用它省事很多 |
| `System.Diagnostics.EventLog` | `System.Diagnostics.Eventing.Reader` 命名空間 | .NET Core 起事件記錄 API 不在 BCL 內建，必須加此套件 |
| `System.Management` | M3-12 WMI 事件訂閱檢查 | **AOT 不相容**，見 §6 |
| 排程工作 | 建議直接用 `ITaskService` COM interop，不引入 `Microsoft.Win32.TaskScheduler` | 減少外部相依，符合 NFR「零外部相依」精神 |
| 登錄檔 | `Microsoft.Win32.Registry` | `net10.0-windows` TFM 已內建，無須額外套件 |

`Directory.Build.props`：
```xml
<Project>
  <PropertyGroup>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <InvariantGlobalization>false</InvariantGlobalization>
  </PropertyGroup>
</Project>
```

`InvariantGlobalization` 必須為 `false` — 報告含繁中內容，且路徑可能有中文（TC-09）。

---

## 3. 核心模型與擴充點

```csharp
namespace LcAudit.Core.Model;

public enum Severity { Info = 0, Low = 5, Medium = 10, High = 20, Critical = 40 }

public enum CheckStatus { Pass, Warning, Fail, Inconclusive, Skipped }

public sealed record Evidence(string Key, string Value, DateTimeOffset? Timestamp = null);

public sealed record Finding
{
    public required string Id { get; init; }              // "M1-01"
    public required string Module { get; init; }          // "M1"
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required CheckStatus Status { get; init; }
    public required string Source { get; init; }
    public string? Description { get; init; }
    public string? Recommendation { get; init; }
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.Now;

    public int Score => Status switch
    {
        CheckStatus.Fail    => (int)Severity,
        CheckStatus.Warning => (int)Severity / 2,
        _                   => 0
    };
}
```

```csharp
namespace LcAudit.Core.Abstractions;

public interface ICheck
{
    string Id { get; }
    string Module { get; }
    ValueTask<Finding> ExecuteAsync(AuditContext context, CancellationToken ct);
}

public sealed class AuditContext
{
    public required bool IsElevated { get; init; }
    public required int LookbackDays { get; init; }
    public required IReadOnlySet<string> SkippedModules { get; init; }
    /// <summary>M1-00 探測結果，供 M1 其餘項與 M4-01 使用</summary>
    public string? PurpleInstallPath { get; set; }
}
```

### 3.1 SafeCheckDecorator（對應 NFR-04）

用 DI Decorator 統一處理例外與逾時，個別 Check 不需要寫 try/catch：

```csharp
public sealed class SafeCheckDecorator(ICheck inner, ILogger<SafeCheckDecorator> logger) : ICheck
{
    public string Id => inner.Id;
    public string Module => inner.Module;

    public async ValueTask<Finding> ExecuteAsync(AuditContext ctx, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            return await inner.ExecuteAsync(ctx, cts.Token);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Inconclusive("權限不足，請以系統管理員身分執行", ex);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Check {Id} failed", Id);
            return Inconclusive("檢查執行失敗", ex);
        }
    }
    // ...
}
```

註冊時包一層即可：
```csharp
services.Scan(...)  // 或手動列舉
foreach (var t in checkTypes)
    services.AddSingleton<ICheck>(sp =>
        new SafeCheckDecorator((ICheck)ActivatorUtilities.CreateInstance(sp, t),
                               sp.GetRequiredService<ILogger<SafeCheckDecorator>>()));
```

---

## 4. Interop 規格

.NET 10 全面使用 `[LibraryImport]` 來源產生器，不用 `[DllImport]`（AOT 相容、零 marshalling 反射）。

### 4.1 WinVerifyTrust — 簽章狀態（M1-01）

```csharp
namespace LcAudit.Windows.Interop;

internal static partial class WinTrust
{
    internal static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2
        = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [LibraryImport("wintrust.dll", SetLastError = true)]
    internal static partial int WinVerifyTrust(IntPtr hwnd, in Guid pgActionID, IntPtr pWVTData);
}
```

**必須遵守的呼叫序**：
1. 建立 `WINTRUST_FILE_INFO` + `WINTRUST_DATA`
2. `dwUIChoice = WTD_UI_NONE (2)`
3. `fdwRevocationChecks = WTD_REVOKE_NONE (0)` — 離線要求（NFR-06），不可設為 `WTD_REVOKE_WHOLECHAIN`
4. `dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL (0x1000)` — 確保不觸發網路
5. `dwUnionChoice = WTD_CHOICE_FILE (1)`
6. 第一次呼叫：`dwStateAction = WTD_STATEACTION_VERIFY (1)`
7. **第二次呼叫必做**：`dwStateAction = WTD_STATEACTION_CLOSE (2)`，否則洩漏 handle

**回傳碼對照（`Status` 判定表）**

| HRESULT | 常數 | Finding Status | 說明 |
|---|---|---|---|
| `0x00000000` | `S_OK` | Pass | 簽章有效且信任 |
| `0x800B0100` | `TRUST_E_NOSIGNATURE` | **Fail** | 完全未簽章 |
| `0x80096010` | `TRUST_E_BAD_DIGEST` | **Fail** | **檔案被竄改** — 最高優先警示 |
| `0x800B0111` | `TRUST_E_EXPLICIT_DISTRUST` | **Fail** | 憑證被明確列為不信任 |
| `0x800B0004` | `TRUST_E_SUBJECT_NOT_TRUSTED` | **Fail** | 主體不受信任 |
| `0x800B010A` | `CERT_E_CHAINING` | **Fail** | 憑證鏈不完整（常見於自簽） |
| `0x800B0101` | `CERT_E_EXPIRED` | Warning | 憑證過期（若有時間戳可降級為 Pass，見 M1-03） |
| `0x80092026` | `CRYPT_E_SECURITY_SETTINGS` | Warning | 政策阻擋，非簽章本身問題 |

> `TRUST_E_NOSIGNATURE` 需再以 `Marshal.GetLastWin32Error()` 區分「無簽章」與「無法讀取檔案」。

### 4.2 CryptQueryObject — 簽章者抽取（M1-02）

```csharp
[LibraryImport("crypt32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool CryptQueryObject(
    uint dwObjectType,                 // CERT_QUERY_OBJECT_FILE = 1
    IntPtr pvObject,                   // LPCWSTR 檔案路徑
    uint dwExpectedContentTypeFlags,   // 見下
    uint dwExpectedFormatTypeFlags,    // CERT_QUERY_FORMAT_FLAG_BINARY = 2
    uint dwFlags,                      // 0
    out uint pdwMsgAndCertEncodingType,
    out uint pdwContentType,
    out uint pdwFormatType,
    out IntPtr phCertStore,
    out IntPtr phMsg,
    out IntPtr ppvContext);
```

```csharp
// 唯一允許的值。使用 CERT_QUERY_CONTENT_FLAG_ALL 視同實作缺陷。
private const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10; // 0x400
```

後續流程：
```
CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM /*6*/, 0, ...)
  → 取得 CMSG_SIGNER_INFO { Issuer, SerialNumber }
CertFindCertificateInStore(phCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                           CERT_FIND_SUBJECT_CERT /*0x000B0007*/, ref certInfo, IntPtr.Zero)
  → CERT_CONTEXT → new X509Certificate2(pCertContext)
最後：CertFreeCertificateContext / CertCloseStore / CryptMsgClose
```

**建議用 `SafeHandle` 包裝這三個 handle**，別靠 finally 手動釋放。

### 4.3 簽章者比對邏輯（純 Core，可測試）

```csharp
// 正確：解析 DN 後比對 O= 欄位
public static bool IsNcsoftSigner(X509Certificate2 cert)
{
    var org = cert.SubjectName
        .EnumerateRelativeDistinguishedNames()
        .FirstOrDefault(rdn => rdn.GetSingleElementType().FriendlyName == "O")
        ?.GetSingleElementValue();

    return string.Equals(org, "NCSOFT Corporation", StringComparison.Ordinal);
}
```

不要用 `cert.Subject.Contains("NCSOFT")` — `CN=NCSOFT-Free-Launcher, O=Evil Ltd` 會通過。

### 4.4 網域白名單（M1-04）— 最容易寫錯的一段

```csharp
private static readonly string[] AllowedHosts =
    ["plaync.com", "playnccdn.com", "ncsoft.com"];

public static bool IsAllowedDownloadHost(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
    if (uri.Scheme is not ("http" or "https")) return false;

    var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();

    return AllowedHosts.Any(allowed =>
        host == allowed || host.EndsWith("." + allowed, StringComparison.Ordinal));
}
```

必要單元測試（`LcAudit.Core.Tests`）：

| 輸入 | 預期 |
|---|---|
| `https://lineageclassic.plaync.com/download` | `true` |
| `https://plaync.com/x` | `true` |
| `https://plaync.com.evil.tw/x` | **`false`** |
| `https://evil.com/?ref=plaync.com` | **`false`** |
| `https://plaync-com.tw/x` | **`false`** |
| `https://xn--...` (Punycode 同形異義) | 依 `IdnHost` 正規化後判定 |
| `https://EVIL.COM` | `false`（大小寫正規化） |

### 4.5 Zone.Identifier / ADS 讀取（M1-04）

.NET 的 `File.ReadAllText` 在 Windows 上會把路徑直接交給 `CreateFileW`，理論上 `"C:\x.exe:Zone.Identifier"` 可行，但**路徑驗證行為在各版本間有變動，不可直接倚賴**。

實作要求：先嘗試 BCL 路徑，失敗則 fallback 到 `CreateFileW` P/Invoke，並在 `LcAudit.Windows.Tests` 用 `TestAssets` 實測驗證你當下的 .NET 10 修訂版行為。

```csharp
[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW",
               StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
internal static partial SafeFileHandle CreateFile(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);
// GENERIC_READ=0x80000000, FILE_SHARE_READ=1, OPEN_EXISTING=3
```

解析 `Zone.Identifier` 內容（INI 格式）：
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://...
HostUrl=https://...
```
判定：`HostUrl` 與 `ReferrerUrl` 皆須通過 §4.4；**任一不通過即 Fail**。整個檔案不存在 → `Warning`（可能是攻擊者刻意剝除 MOTW，也可能是正常解壓縮所致）。

### 4.6 事件記錄（M2）

用 `EventLogQuery` + `EventLogPropertySelector`。**不要對每筆記錄呼叫 `ToXml()`**，5000 筆會慢到爆掉（NFR-01）。

```csharp
var xpath = """
    *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 7776000000]]]
    and *[EventData[Data[@Name='LogonType'] and (Data='10' or Data='3')]]
    """;

var query = new EventLogQuery("Security", PathType.LogName, xpath)
{
    ReverseDirection = true,
    TolerateQueryErrors = true
};

using var selector = new EventLogPropertySelector(
[
    "Event/EventData/Data[@Name='TargetUserName']",
    "Event/EventData/Data[@Name='TargetDomainName']",
    "Event/EventData/Data[@Name='LogonType']",
    "Event/EventData/Data[@Name='IpAddress']",
    "Event/EventData/Data[@Name='IpPort']",
    "Event/EventData/Data[@Name='ProcessName']"
]);

using var reader = new EventLogReader(query);
while (reader.ReadEvent() is EventLogRecord rec)
{
    using (rec)
    {
        var p = rec.GetPropertyValues(selector);
        // p[0] = TargetUserName ... 具名取值，不再有 PowerShell 版的索引脆弱性問題
    }
}
```

這一點是改用 C# 的實質收益：功能規格 §6 FR-M2 註記的「`Properties[8]` 索引不可硬寫」問題，在 `EventLogPropertySelector` 具名 XPath 下自然消失。

**timediff 換算**：毫秒。90 天 = `90 × 86400 × 1000` = `7776000000`。

**額外必做**：查 `EventID=1102`（安全性記錄檔已清除）。若命中，M2 全模組結果需附註「事件記錄曾被清除，Pass 不具意義」（對應 TC-07 與限制 L-01）。

### 4.7 TCP 連線 + PID（M4）

`IPGlobalProperties.GetActiveTcpConnections()` **不回傳 PID**，無法對應到處理程序，不符合 M4-01/M4-03 需求。必須用：

```csharp
[LibraryImport("iphlpapi.dll", SetLastError = true)]
internal static partial uint GetExtendedTcpTable(
    IntPtr pTcpTable, ref uint pdwSize,
    [MarshalAs(UnmanagedType.Bool)] bool bOrder,
    uint ulAf,              // AF_INET = 2, AF_INET6 = 23
    uint TableClass,        // TCP_TABLE_OWNER_PID_ALL = 5
    uint Reserved);
```

IPv4 與 IPv6 需各呼叫一次。典型的「先傳 size=0 取所需長度，再配置緩衝區」兩段式呼叫。

### 4.8 其他 Win32 觸點

| 檢查項 | API |
|---|---|
| M3-07 排程工作 | `ITaskService` COM（`CLSID_TaskScheduler` = `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}`），列舉 `\` 並排除 `\Microsoft\*` |
| M3-09 防火牆規則 | `INetFwPolicy2` COM（`HNetCfg.FwPolicy2`），`Rules` 篩 `Direction == Inbound && Action == Allow && Enabled` |
| M3-10/11 Defender | 優先讀 `HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\*`；WMI `root\Microsoft\Windows\Defender` 的 `MSFT_MpPreference` 為備援 |
| M3-12 WMI 事件訂閱 | `root\subscription` 下的 `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` |
| 提權檢測 | `new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)` |

---

## 5. CLI（System.CommandLine 2.0.10）

注意 GA 版 API 與網路上多數 beta 教學不同：<cite index="38-1">`SetHandler` 已改為 `SetAction`，`InvocationContext` 移除改為直接傳入 `ParseResult`，`CommandLineBuilder` 與 `AddMiddleware` 皆已移除。</cite>

```csharp
var daysOption   = new Option<int>("--days")   { DefaultValueFactory = _ => 90 };
var pathOption   = new Option<string?>("--purple-path");
var outputOption = new Option<DirectoryInfo>("--output")
                   { DefaultValueFactory = _ => new(@".\LcAudit-Report") };
var formatOption = new Option<ReportFormat>("--format")
                   { DefaultValueFactory = _ => ReportFormat.All };
var skipOption   = new Option<string[]>("--skip-module") { AllowMultipleArgumentsPerToken = true };

var root = new RootCommand("天堂：經典版 帳號安全稽核工具")
    { daysOption, pathOption, outputOption, formatOption, skipOption };

root.SetAction(async (ParseResult parseResult, CancellationToken ct) =>
{
    var options = new AuditOptions
    {
        LookbackDays = parseResult.GetValue(daysOption),
        PurplePath   = parseResult.GetValue(pathOption),
        OutputPath   = parseResult.GetValue(outputOption)!,
        Format       = parseResult.GetValue(formatOption),
        SkipModules  = parseResult.GetValue(skipOption) ?? []
    };

    var report = await host.Services.GetRequiredService<AuditRunner>().RunAsync(options, ct);
    return (int)report.Summary.Level;   // 對應功能規格 §7.1 結束代碼 0~3
});

return await root.Parse(args).InvokeAsync();
```

---

## 6. 發佈與封裝

```xml
<PropertyGroup>
  <TargetFramework>net10.0-windows</TargetFramework>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
  <SelfContained>true</SelfContained>
  <PublishSingleFile>true</PublishSingleFile>
  <PublishReadyToRun>true</PublishReadyToRun>
  <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
  <EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>
</PropertyGroup>
```

### 6.1 為什麼 v1.0 不用 NativeAOT

雖然 AOT 對「事發時要在可疑主機上跑一個小工具」很有吸引力，但：

| 阻礙 | 說明 | 解法 |
|---|---|---|
| `System.Management` | 大量反射，官方未標註 AOT 相容 | 改用 `Microsoft.Management.Infrastructure`（MI API），或直接 P/Invoke WMI COM |
| COM interop（排程工作、防火牆） | 需 `EnableComHosting` 或手動 `ComWrappers`，`[GeneratedComInterface]` 可解但要重寫介面宣告 | 用 .NET 8+ 的 `[GeneratedComInterface]` 來源產生器 |
| `System.Diagnostics.EventLog` | AOT 相容性需實測 | 建 spike 專案驗證 |

**建議路線**：v1.0 先 `PublishSingleFile` + `ReadyToRun` 出貨（約 60–80 MB，可接受）；v1.1 把 `System.Management` 換掉後再評估 AOT，可壓到 10 MB 以內、啟動時間從 ~200ms 降到 ~10ms。

### 6.2 工具自身的可信度（呼應 NFR-09）

這是一個要在「可能已被入侵的主機」上執行的安全工具，本身就是高價值的供應鏈標的。

- 用自己的憑證簽章，或至少在 GitHub Release 附 SHA-256
- 在 CI 產生 build provenance（SLSA attestation）
- Reproducible build：固定 `<Deterministic>true</Deterministic>` 與 SDK 版本（`global.json`）
- 諷刺但務實的一點：**這個工具能不能通過它自己的 M1-01 檢查**，可以當成一個整合測試

---

## 7. 測試策略

| 層級 | 專案 | 範圍 |
|---|---|---|
| 單元（跨平台） | `LcAudit.Core.Tests` | 評分模型（S-01～S-05）、推論引擎（S-06 決策表）、網域白名單（§4.4 全部案例）、DN 解析 |
| 單元（Windows） | `LcAudit.Windows.Tests` | 各 Check 搭配 fake `IEvidenceSource`；ADS 讀取；Event XML 剖析（餵入固定 XML 字串） |
| 整合（Windows） | 同上，`[Trait("Category","Integration")]` | WinVerifyTrust 對 `TestAssets` 實檔驗證 |

### 7.1 TestAssets 準備（M1 驗收關鍵）

| 檔案 | 產生方式 | 預期 |
|---|---|---|
| `signed-valid.exe` | 任一微軟簽章的系統執行檔（如 `notepad.exe` 複本） | `S_OK` |
| `unsigned.exe` | 自行編譯，不簽 | `TRUST_E_NOSIGNATURE` |
| `tampered.exe` | 取已簽章檔，用 hex editor 改動一個位元組 | `TRUST_E_BAD_DIGEST` |
| `selfsigned.exe` | `New-SelfSignedCertificate` + `signtool` | `CERT_E_CHAINING` |
| **`cert-embedded-unsigned.exe`** | **未簽章，但把一張憑證塞進資源區段** | **必須是 `TRUST_E_NOSIGNATURE`** |

最後一項是回歸測試的核心：它就是 §0 描述的繞過手法。任何一次重構若讓這個檔案被判為「已簽章」，代表有人又把 `CreateFromSignedFile` 或 `CERT_QUERY_CONTENT_FLAG_ALL` 寫回去了。

---

## 8. 實作順序建議

| 階段 | 內容 | 產出 |
|---|---|---|
| 1 | `Core` 模型 + 評分 + 推論引擎 + 對應單元測試 | 可在 Linux 跑的綠燈 CI |
| 2 | `Interop.WinTrust` + `Interop.Crypt32` + TestAssets | M1 完整可用（**單這一步就解決最主流的假紫P 問題**） |
| 3 | `Interop` 事件記錄 + M2 | 遠端存取時間軸 |
| 4 | M3（登錄檔／排程／防火牆／Defender） | 持久化檢查 |
| 5 | M4 + `Reporting` | 完整報告 |
| 6 | CLI 組裝、發佈管線、自我簽章 | v1.0 |

階段 2 結束時就已經有獨立價值，可先出一個 `--module M1` 的最小版本自用。

---

## 9. 待你實測確認的項目

以下三點依 .NET 10 修訂版可能有差異，建議先寫 spike 驗證再定案：

1. `File.ReadAllText(@"C:\x.exe:Zone.Identifier")` 在 .NET 10 是否可行，或必須走 §4.5 的 P/Invoke fallback
2. `System.Diagnostics.EventLog` 10.0.0 在 `PublishSingleFile` + `TrimMode=full` 下是否正常（若要走 §6.1 的 v1.1 路線）
3. `X509Certificate2.SubjectName.EnumerateRelativeDistinguishedNames()` 對 NCSOFT 實際憑證的 DN 結構回傳值（韓國憑證可能有非預期的 RDN 排列或多值 RDN）
