# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案現況

`LcAudit` 是天堂：經典版帳號安全稽核工具 —— 在可能已被入侵的 Windows 主機上，以**唯讀方式**蒐集三類跡證（PURPLE Launcher 是否官方正版、是否曾遭遠端存取、是否被植入持久化後門），輸出風險評分與報告。

**實作形式：C# / .NET 10 Console App（`net10.0-windows`, win-x64），單一執行檔發佈。** 這是唯一的實作方向 —— 不做 GUI、不做服務、不做 Web。使用者的操作方式就是開一個終端機、跑 `LcAudit.exe` 帶參數，看 Console 輸出並拿到報告檔。

**進度：四個專案皆已建立，`--purple-path` 的 M1 最小版本可實際執行**，161 個測試全綠。

- `LcAudit.Core` — 領域模型、評分、推論引擎、純判定邏輯（網域白名單、DN 解析）
- `LcAudit.Windows` — `Interop/`（WinTrust、Crypt32、Kernel32、SafeHandles）、`Sources/`（AuthenticodeVerifier、ProcessInspector、PurplePathProbe、GameProcessDetector、WindowsEventLog、EventQueries）、`Sources/RemoteTools/`（工具特徵目錄與掃描）、`Checks/M1/`（M1-00～M1-02）、`Checks/M2/`（**M2 已全數完成**：M2-00 記錄檔清除偵測 + M2-01～M2-10）
- `LcAudit.Reporting` — `ConsoleReporter`（Spectre.Console）、`HtmlReporter`（§8.3 自包含單檔）、`JsonReporter`（§8.2）、`ReportWriter`（檔名與編碼）、`ReportPresentation`
- `LcAudit.Cli` — `System.CommandLine` 2.0.10 GA API + DI + pre-flight，結束代碼已接風險等級

已端到端驗證：正常簽章但簽章者非 NCSOFT → M1-02 Fail(40) → 強制「極高」→ 結束代碼 3；改造正版（竄改）→ M1-01 BadDigest + M1-02 皆 Fail(80)。

**M3 已完成 8/13**：M3-01、02、03、04、05、10、11、13。**尚未實作**：M1-03～M1-08、M3-06（Run/RunOnce + 啟動資料夾）、M3-07（排程工作，需 `ITaskService` COM）、M3-08（非預期服務）、M3-09（防火牆，需 `INetFwPolicy2` COM）、M3-12（WMI 事件訂閱）、M4。CLI 參數已全部接通（`--days`／`--purple-path`／`--output`／`--format`／`--skip-module`）。

**注意 M2 的驗證缺口**：M2-04 的具名欄位擷取已對真實事件驗證通過（使用者、來源位址、事件類型皆正確）。但 **Security 記錄相關項（M2-00～M2-03、M2-10）的「有資料」路徑仍只用假資料測過** —— 本機開發時未提權。首次以系統管理員執行時要重點確認 4624/4625 的 `TargetUserName`、`IpAddress`、`LogonType` 有正確填入，欄位名稱對不上的話會全部變成空值而靜默判 Pass。

**方向別搞混**：M2-05（RDP 用戶端）與 M2-09（Bitmap 快取）記的是「本機**連出去**」，不是被連入；M2-06/07 的 `Connections_incoming` 才是被連入。程式碼與報告文案都刻意標注了方向。

**測試素材不進版控**：整合測試的 PE 檔在執行當下產生（`TestAssets.cs`），避免防毒對 repo 誤判、避免故意損壞的檔案被誤用。**不可用 `notepad.exe`／`kernel32.dll` 當已簽章素材** —— 那是目錄簽章(Catalog)，複本不受保護，`WinVerifyTrust` 走 `WTD_CHOICE_FILE` 會判為未簽章（技術設計 §7.1 建議用 notepad.exe 複本，那是錯的）。要用內嵌簽章的檔案，如 `%ProgramFiles%\dotnet\dotnet.exe`。

## 文件的權威順序（Ground Truth）

| 文件 | 地位 |
|---|---|
| `docs/LineageClassic-SecurityAudit-Spec.md` | 功能規格 v1.0 — FR-M1～M4、FR-S、NFR、測試案例 TC-01～10 的唯一真相來源 |
| `docs/LcAudit-CSharp-TechnicalDesign.md` | 技術設計 v1.0 — **取代**功能規格 §3（技術選型）與附錄 A；並作廢 NFR-07 |

兩者衝突時：技術層面依技術設計文件，功能／判定條件依功能規格。

**注意功能規格已過時的部分**：功能規格 §3 選的是「PowerShell 5.1 單一 `.ps1`」、§4 的架構圖是 PowerShell 函式（`New-Finding`、`Invoke-SafeCheck`、`Out-HtmlReport`…）、附錄 A 是 PS Cmdlet 對照表、NFR-07 限制 PS 5.1 語法 —— **這些全部作廢**。讀規格時只取其中的檢查項定義、判定條件、Severity、白名單、評分規則；實作手法一律以技術設計文件為準。看到規格裡的 `Get-AuthenticodeSignature`、`Get-WinEvent`、`Get-ScheduledTask` 等 Cmdlet，要對應到技術設計 §4 的 Win32 / BCL 作法，不要用 `Process.Start("powershell")` 去包 Cmdlet。

## 絕對禁止事項（違反即整個工具失效）

實作 M1-01 / M1-02 數位簽章驗證時：

- **禁止 `X509Certificate.CreateFromSignedFile()`** — 它根本不驗證簽章，只是掃檔案任意位置找像憑證的東西。偽造的紫P 只要把 NCSOFT 公開憑證塞進資源區段就能通過。
- **禁止 `CERT_QUERY_CONTENT_FLAG_ALL`** — `CryptQueryObject` 的旗標必須且只能是 `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED` (0x400)。
- 正確作法：`Status` 判定走 `WinVerifyTrust`（`WINTRUST_ACTION_GENERIC_VERIFY_V2`），`Signer` 抽取走 `CryptQueryObject` + PKCS7_SIGNED_EMBED，**兩者皆通過才算 Pass**。
- **回歸測試守門員是「被竄改的已簽章檔案」**，不是規格說的 `cert-embedded-unsigned.exe`。已在本機實測確認：拿正版 `dotnet.exe` 改動中段一個位元組後，`WinVerifyTrust` 回 `TRUST_E_BAD_DIGEST`（正確），而 `CreateFromSignedFile` 照樣回報「O=Microsoft Corporation」，對竄改毫無反應。假紫P 最省事的做法就是改造正版，不必自己弄憑證。
- `cert-embedded-unsigned.exe` 這個素材**沒有重現**技術設計 §0 描述的繞過。已試兩種構造（DER 附加於 PE 尾端、編為 .NET 內嵌資源），`CreateFromSignedFile` 兩者都拋 `CryptographicException` 而非回報憑證裡的簽章者。它仍是合理的負面案例，但別當它是守門員。若要做出真正的資源區段陷阱，需以 Win32 資源（而非 .NET 內嵌資源）寫入，尚未驗證。
- 禁令不因此放寬：`CreateFromSignedFile` 的致命缺陷是**它根本不做任何驗證**，上面的竄改實測已足以證明。

其他易錯點：
- 簽章者比對必須解析 DN 取 `O=` 欄位比對 `"NCSOFT Corporation"`，**不可** `cert.Subject.Contains("NCSOFT")`（`CN=NCSOFT-Free-Launcher, O=Evil Ltd` 會通過）。
- 網域白名單必須是**後綴比對**（`host == allowed || host.EndsWith("." + allowed)`，取 `uri.IdnHost` 正規化），**不可** `Contains`／`-like "*plaync*"`（`plaync.com.evil.tw` 會誤判為安全）。
- `WinVerifyTrust` 第一次呼叫後**必做**第二次 `WTD_STATEACTION_CLOSE`，否則洩漏 handle。
- `IPGlobalProperties.GetActiveTcpConnections()` 不回傳 PID，M4-01/M4-03 必須用 `GetExtendedTcpTable`。

## 報告輸出的兩條鐵律

**1. HTML 報告的所有插入值都必須經過 `HtmlReporter.Esc()`，無一例外。** 報告內容大量來自攻擊者可控的資料 —— Security 4625 的 `TargetUserName` 是嘗試登入者自己填的、檔名可以任意命名、憑證 Subject 也是。不跳脫的話，一個叫 `<script>…</script>.exe` 的檔案或帳號就能讓報告在被害者開啟時執行指令碼，稽核工具的產出變成攻擊載體。

報告刻意**不含任何 JavaScript**（折疊用原生 `<details>`），也不引用任何外部資源 —— 對應 §8.3 自包含要求與 NFR-06 離線要求。`HtmlReporterTests` 有測試守住這三點。寫測試時注意：跳脫後的 `onerror=` 以純文字出現是**正常且無害**的，正確的斷言是「原始字串不得原樣出現」而非「不得含某子字串」。

**2. 寫檔只能經由 `ReportWriter`，且只能寫在 `--output` 目錄下**（NFR-03）。UTF-8 with BOM（NFR-08）。`--format Console` 時連目錄都不建立。

## 本機帳號與群組的三個坑（M3 實作前必讀，皆已實測確認）

**1. 群組名稱是在地化的，一律用 well-known SID 定位。** 硬寫 `"Administrators"` 在部分語系會查不到群組 —— 而且失效方式是「找不到成員」，看起來就像「沒有異常」。用 `new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount))` 取在地化名稱，再去掉 `BUILTIN\` 前綴餵給 `NetLocalGroupGetMembers`。

**2. 空群組會回傳 null buffer，那是「沒有成員」不是「查詢失敗」。** `NetLocalGroupGetMembers` 對空群組回 `NERR_Success` + `entriesRead = 0` + `buffer = IntPtr.Zero`。若在 buffer 為 null 時拋例外，M3-03 會把正常的「遠端桌面使用者群組是空的」誤報為 `Inconclusive`。

**3. 內建帳號用 SID 的 RID 辨識，不用名稱。** 攻擊者常把後門帳號改名為 `Administrator`。RID 500/512/518/519 才是可信依據。

## 事件記錄的三個坑（M2 實作前必讀，皆已實測確認）

**1. `TolerateQueryErrors = true` 會讓權限不足變成靜默失敗。** 未提權查 Security 記錄時，`EventLogReader` 建得起來、`ReadEvent()` 直接回 `null`，**不拋任何例外**。於是「讀不到記錄檔」與「期間內沒有事件」完全無法區分，M2 會全部報「通過」—— 工具在讀不到資料的情況下宣稱沒有遠端登入，這比沒有這個檢查還糟。

修法：`WindowsEventLog.Query` 進入查詢前先呼叫 `EventLogSession.GlobalSession.GetLogInformation()` 明確探測可讀性，它會確實拋 `UnauthorizedAccessException`。不要改用 `TolerateQueryErrors = false` —— 那會讓單筆損毀記錄毀掉整批查詢。回歸測試見 `WindowsEventLogIntegrationTests.未提權讀取Security必須拋例外而非靜默回空`。

**2. 不是所有事件記錄都需要提權。** Security 記錄需要，但 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` **不需要** —— 已實測確認可在未提權下讀出完整的工作階段時間軸（含使用者與來源位址）。這讓 M2-04 成為未提權執行時最有價值的遠端存取跡證來源。實作新的事件記錄檢查時，別預設「一律需要提權」而白白放棄可得的資料。

另外，TerminalServices 這類記錄檔在從未使用過遠端桌面的機器上可能根本不存在 —— 那應判 `Inconclusive`（查不到），而非讓 `FileNotFoundException` 變成語意模糊的「檢查執行失敗」。用 `IWindowsEventLog.LogExists()` 先問。

**3. XPath 的比較運算子必須是字面的 `<=`，不可寫成 XML 跳脫的 `&lt;=`。** `EventLogQuery` 收的是純 XPath 運算式而非 XML，跳脫版會被拒為「指定的查詢無效」。而且這個錯誤會被 `SafeCheckDecorator` 吞成 `Inconclusive`，極難察覺。`EventQueries` 有測試守住。

## 反作弊共存規則（M1-00 / M4-01 / M4-03 實作前必讀）

天堂經典版有 kernel-mode 反作弊（GameGuard／XIGNCODE 這一類，用 `ObRegisterCallbacks` 監控對受保護程序的 handle 請求）。本工具的檢查行為絕大多數與它無交集，但**取得「執行中處理程序的執行檔路徑」這件事會踩線**：

- **禁止 `Process.MainModule.FileName`／`.Path`** — 底層是 `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` + `EnumProcessModules`。`PROCESS_VM_READ` 正是外掛讀取遊戲記憶體用的權限旗標，反作弊會剝權限、記錄，部分版本直接讓遊戲跳錯誤結束。
- **正確作法**：`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION /* 0x1000 */)` + `QueryFullProcessImageNameW`。此權限為最小化情境設計，最可能被放行；被拒也只是 Access Denied → `Inconclusive`。
- `Process.ProcessName`（僅名稱、不含路徑）走系統快照不開 handle，可安全使用。
- **禁止啟用 `SeDebugPrivilege`** — 管理員工具的常見習慣，但這是最強的反作弊觸發器之一，且本工具不需要它。
- **禁止**列舉他人程序的模組（`EnumProcessModules`／`Module32First`）、`ReadProcessMemory` 系列、`CreateRemoteThread`／`VirtualAllocEx`／`SetWindowsHookEx`、載入任何驅動。

**Pre-flight 要求**：偵測到遊戲或反作弊程序執行中時，Console 首行警示「建議關閉遊戲與紫P 後再執行」。偵測只用 `Process.ProcessName` 比對名稱（不開 handle），比對出的 PID 存入 `AuditContext.ProtectedPids`。

執行中時的降級策略**分兩種，不要一律跳過**：

- **M4-01**（紫P 處理程序連線）→ 判 `Inconclusive`。它是 `Info` 級、0 分，犧牲掉不影響評分。
- **M4-03**（未簽章處理程序對外連線）→ **照常執行，但跳過 `ProtectedPids` 內的 PID**，其餘程序仍取路徑驗簽。此項是 `High`（20 分），且它要抓的是後門／竊資程式，與遊戲程序無關，不該整項放棄。
- M4-02／M4-04 不受影響，永遠照常執行。

**執行模式的覆蓋率**（決定 Console 警示的措辭輕重）：關閉遊戲只損失 M4-01 一項、0 分；**未提權則損失約 8 項**（M2-01/02/03/10、EventID 1102 清除偵測、M3-10/11、M3-12、M4-03 跨使用者程序），分數差距可達 100+。提權遠比遊戲是否關閉重要，兩者的警示強度要反映這個差異。

**檔案共用模式**：M1-05 遞迴掃描紫P 安裝目錄時，一律以 `FileShare.ReadWrite | FileShare.Delete` 開檔。share mode 給不夠會反過來害執行中的 launcher 檔案操作失敗。

**AV 誤判（比反作弊更可能發生）**：一個未簽章、會列舉 process、讀 Security log、查 Defender 排除清單的壓縮自解壓執行檔，樣式與 dropper 型惡意程式高度重疊。因此 `EnableCompressionInSingleFile` 設 `false`（**刻意偏離技術設計 §6 的 `true`，勿改回**），並落實 NFR-09（自我簽章或附 SHA-256）。

## 架構要點

四個專案，相依單向；只有 `LcAudit.Cli` 是 Console App（`OutputType=Exe`），其餘三個都是 classlib：

```
src/LcAudit.Core/       net10.0          領域模型 + 評分 + 推論引擎 — 不相依任何人，Linux CI 可完整測試
src/LcAudit.Windows/    net10.0-windows  Interop/ (P/Invoke) + Sources/ (原始資料存取) + Checks/M1..M4/
src/LcAudit.Reporting/  net10.0          Console / Json / Html — 只吃 AuditReport
src/LcAudit.Cli/        net10.0-windows  Exe — 參數解析 + DI 組裝 + 結束代碼
tests/LcAudit.Core.Tests/       跨平台，Linux CI 可跑
tests/LcAudit.Windows.Tests/    Windows only，含 Integration trait
tests/LcAudit.TestAssets/       已簽章／未簽章／竄改的測試檔
```

**Console App 的組成**：`System.CommandLine` 2.0.10 解析參數（GA 版 API：`SetAction` 而非 `SetHandler`，直接接 `ParseResult`，沒有 `InvocationContext`／`CommandLineBuilder`）、`Microsoft.Extensions.DependencyInjection` 組裝所有 `ICheck`、`Spectre.Console` 做 §8.1 的分色表格輸出。`Program.cs` 只做這三件事，不放任何檢查邏輯。結束代碼由風險等級決定（見「評分規則」），這是 Console App 的對外契約之一，不可只印訊息就 `return 0`。

**其他相依**：`System.Diagnostics.EventLog`（.NET Core 起 `Eventing.Reader` 不在 BCL，必須加）、`System.Management`（僅 M3-12 WMI 事件訂閱，且 AOT 不相容）。排程工作與防火牆走 COM interop（`ITaskService`／`INetFwPolicy2`），不引入 `Microsoft.Win32.TaskScheduler`。P/Invoke 一律用 `[LibraryImport]` 來源產生器，不用 `[DllImport]`。

**關鍵設計**：`Checks` 不直接呼叫 Win32，一律透過 `Sources` 介面（如 `IAuthenticodeVerifier`）。判定邏輯（白名單比對、DN 比對、評分）全部留在可純單元測試的位置。一個檢查項 = 一個 `ICheck` 實作類別（`M1_02_SignerIdentityCheck` 這種命名）。

**例外處理**：個別 Check **不寫 try/catch**。`SafeCheckDecorator` 統一包裝例外與 30 秒逾時，失敗轉 `Inconclusive`（NFR-04）。DI 註冊時每個 `ICheck` 都包一層。

**模組間狀態**：`AuditContext` 上只有兩項共享狀態 —— M1-00 探測出的 `PurpleInstallPath`（供 M1 其餘項與 M4-01 使用），以及 pre-flight 產生的 `ProtectedPids`（供 M4-03 排除，見上節）。其餘一律不共享。

**執行流程**：提權檢查 → 環境探測 → M1 → M2 → M3 → M4 → 風險彙總 → 報告輸出。

## 不可妥協的約束

| 約束 | 影響 |
|---|---|
| 全程唯讀 | 除 `--output` 目錄外不得寫入任何路徑；不得修改檔案時間戳；不做任何修復／清除／隔離 |
| 完全離線 | 不得發出任何網路請求。`fdwRevocationChecks = WTD_REVOKE_NONE`，`dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL`；M4-04 反查用內建靜態清單，不做 DNS |
| 降級不中斷 | 任一檢查項失敗只標 `Inconclusive`，不影響其餘項目 |
| 效能 | 完整掃描 < 3 分鐘；事件查詢 `MaxEvents` 預設 5000；**不要對每筆事件呼叫 `ToXml()`**，用 `EventLogPropertySelector` 具名 XPath；篩選一律下推到 XPath，不要撈回來再用 C# 過濾（4624 動輒數萬筆） |
| 中文 | `InvariantGlobalization=false`（報告與路徑含繁中，TC-09）；報告檔輸出 UTF-8 with BOM；Console 輸出開頭設 `Console.OutputEncoding = Encoding.UTF8`，否則舊版主控台顯示繁中會亂碼 |
| 未提權可跑 | 未以系統管理員執行時不得直接結束；Security log 相關項標 `Inconclusive`，其餘照常，並於 Console 首行警示（TC-02） |
| 不碰遊戲 | 記憶體、封包、遊戲檔案完整性一律不觸碰（涉及反作弊機制） |

## 評分規則

Severity 即分數：`Critical=40, High=20, Medium=10, Low=5, Info=0`（enum 底值直接就是分數）。`Fail` 計 100%、`Warning` 計 50%、其餘 0。總分上限 100。等級 0–19 低 / 20–49 中 / 50–79 高 / 80–100 極高。**任一 Critical 命中直接強制為「極高」，不受總分影響**。結束代碼 0/1/2/3 對應四個等級，10 = 執行環境錯誤。

推論引擎（S-06）依 M1/M2/M3 命中組合輸出「最可能的入侵途徑」，決策表見功能規格 §6 FR-S。

## 建置與測試

`Directory.Build.props`、`Directory.Packages.props`（CPM 已啟用）、`global.json`（釘 SDK 10.0.203）皆已就位。**新增專案時 `PackageReference` 不可寫 `Version`**，版本一律加到 `Directory.Packages.props`。新專案要記得 `dotnet sln add`。

日常指令：

```powershell
dotnet build
dotnet test                                          # 全部
dotnet test tests/LcAudit.Core.Tests                 # 跨平台單元測試（評分、白名單、DN 解析）
dotnet test --filter "FullyQualifiedName~IsAllowedDownloadHost"   # 單一測試
dotnet test --filter "Category!=Integration"         # 排除需實檔的 WinVerifyTrust 整合測試
dotnet run --project src/LcAudit.Cli -- --days 90 --format All
```

發佈（v1.0 走 SingleFile + ReadyToRun，**不用 NativeAOT** —— `System.Management` 與 COM interop 未過關，見技術設計 §6.1）：

```powershell
dotnet publish src/LcAudit.Cli -c Release -r win-x64 --self-contained
```

CLI 參數：`--days`(90) `--purple-path` `--output`(.\LcAudit-Report) `--format`(All) `--skip-module`。

`TreatWarningsAsErrors=true` 下警告即建置失敗，每次改完主動 build 驗證。執行測試前先依全域規則確認沒有殘留程序鎖檔（`tasklist | findstr LcAudit`）。

## 實作順序

技術設計 §8 定義的階段：~~Core 模型+評分~~（已完成）→ **Interop WinTrust/Crypt32 + TestAssets（單這步就解決最主流的假紫P 問題）** → 事件記錄+M2 → M3 → M4+Reporting → CLI+發佈。階段 2 結束即有獨立價值，可先出 `--module M1` 的最小版本。

## 已定案的判定基準（規格留白處，勿再自行改動）

規格多處只寫判定方向、未給可實作的基準。以下是已定案的，改動前先確認理由仍成立：

| 議題 | 決定 | 理由 |
|---|---|---|
| **S-05 Critical 強制升等的觸發條件** | 僅 `Fail`，**Warning 不觸發** | 規格寫「命中」，字面含 Warning。但 Critical 項的 Warning 意為「需人工研判」（如 M1-03 憑證過期但有時間戳），一併升等會讓正常機器判為「極高」，誤報吃掉工具可信度。Warning 仍計 50%，可累加自然升等 |
| **TC-08 跳過模組時的評分基準** | 絕對 100 分制，跳過項計 0 分 | 相對計分會讓 `--skip-module M3 --skip-module M4` 跑出漂亮的低分。代價是分數偏低，由 `AuditSummary.CoverageNote` 明講 |
| **S-06「全數 Pass」的認定** | 有 `Inconclusive` 時改用 R5-P 保留語氣 | 「沒檢查成功」不等於「檢查過沒問題」，混為一談會給出不實的安全感 |
| **DN 的 O= 欄位比對** | 比對 OID `2.5.4.10`，非 `FriendlyName` | FriendlyName 依平台與地區設定而異，Linux CI 上可能拿不到 `"O"` |
| **多值 RDN** | 跳過該 RDN 繼續找，不拋例外 | 技術設計 §9-3 待實測，先確保不讓整個檢查爆掉 |
| **M2-02 私有網段清單** | RFC1918 + loopback + **CGNAT `100.64/10`** + link-local `169.254/16` + IPv6 ULA `fc00::/7` + IPv6 link-local；`-`／空字串／`0.0.0.0`／`::` 獨立為 `Unspecified` 不計入 | 見 `PrivateAddressClassifier`。漏掉 CGNAT 會對大量使用電信 NAT 的正常使用者誤報 `Fail`(20 分)；4624 本機登入時 `IpAddress` 常是 `-`，不特別處理會被當成公網 |
| **M2 系統帳號排除** | 帳號結尾 `$`、`ANONYMOUS LOGON`、`SYSTEM`、`LOCAL SERVICE`、`NETWORK SERVICE`、`-`、空值一律排除 | 見 `LogonRecord.IsSystemAccount`。不排除的話 M2-02 會對每台正常的網域機器噴 Fail |
| **M3-05「非預期成員」的三級判定** | 內建帳號（RID 500/512/518/519）＋目前使用者＋`--expect-admin` → 預期；非預期的**網域**成員 → `Warning`；非預期的**本機**帳號 → `Fail` | 規格只寫「非預期 → Fail」。但這是 Critical(40)、命中即強制「極高」—— 公司配發的電腦本機 Administrators 含網域群組是常態，一律判 Fail 對企業使用者是純誤報。家用機出現第二個本機管理員才確實高度可疑 |
| **M3-13 非敏感的 hosts 自訂對應** | 判 `Pass` 但完整列出證據，**不判 Warning** | 規格只定義「含遊戲／入口網站導向 → Fail」。本項是 Critical，一個 Warning 就是 20 分；廣告阻擋等自訂對應很常見，為此讓正常機器背 20 分不合理 |
| **M3-04「近期建立的帳號」** | 用 `C:\Users\<name>` 的 `CreationTime` 推估，報告明確註明是推估值 | 本機帳號沒有可靠的建立時間來源，登錄檔與 `NetUserGetInfo` 都不提供 |

`ICheck` 比技術設計 §3 多了 `Title` / `Severity` / `Source` 三個唯讀屬性 —— `SafeCheckDecorator` 與 `AuditRunner` 需要這些靜態中繼資料，才能在檢查項「沒能執行」時仍組出完整的 `Finding`。

## 仍待定案（動到對應模組前必須先決定）

| 期限 | 議題 |
|---|---|
| 隨時 | **紫P 主程式檔名與安裝路徑需實機確認** —— `PurpleExecutableLocator.CandidateNames`（`Purple.exe`／`PurpleLauncher.exe`／`NCLauncher.exe`／`NCLauncherU.exe`）、`PurplePathProbe` 的常見路徑清單、`GameProcessDetector.KnownNames` 全部是推測值，未經實機驗證 |
| M1-06 實作前 | **檔名相似度**演算法（同形字元表 `l/I/1`、`O/0`、`rn/m`，或 Levenshtein 門檻）；**M1-08「時間接近」**的視窗大小 |
| M2 其餘項實作前 | **M2-08 遠端工具偵測清單**（功能規格附錄 B 有起點，但版本更迭快）；**M2-04 TerminalServices 記錄檔在未啟用時的行為** —— `WindowsEventLog` 已把 `EventLogNotFoundException` 轉為 `FileNotFoundException`，但 M2-04 應判 `Inconclusive` 而非讓它變成一般例外 |
| M3-09 實作前 | **「近期新增」無法實作** —— `INetFwPolicy2` 不提供規則建立時間，登錄檔 `FirewallRules` 的 `LastWriteTime` 是整個 key 的而非逐條。判定條件需改寫，例如退化為「列出所有非 Microsoft 簽章程式的 Inbound Allow 規則」 |

## 已知待驗證項目

技術設計 §9 列出三點需先寫 spike 實測（.NET 10 修訂版行為可能有差異）：ADS 讀取是否需 `CreateFileW` fallback、`System.Diagnostics.EventLog` 在 SingleFile+Trim 下的行為、NCSOFT 實際憑證的 DN 結構（韓國憑證可能有多值 RDN）。
