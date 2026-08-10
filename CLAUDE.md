# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案現況

`LcAudit` 是天堂：經典版帳號安全稽核工具 —— 在可能已被入侵的 Windows 主機上，以**唯讀方式**蒐集三類跡證（PURPLE Launcher 是否官方正版、是否曾遭遠端存取、是否被植入持久化後門），輸出風險評分與報告。

**實作形式：C# / .NET 10 Console App（`net10.0-windows`, win-x64），單一執行檔發佈。** 這是唯一的實作方向 —— 不做 GUI、不做服務、不做 Web。使用者的操作方式就是開一個終端機、跑 `LcAudit.exe` 帶參數，看 Console 輸出並拿到報告檔。

**進度：階段 1 已完成**（技術設計 §8 的六階段）。`LcAudit.Core` + `LcAudit.Core.Tests` 已建立並全綠（103 個測試），內容為領域模型、評分、推論引擎、以及兩處純判定邏輯（網域白名單、DN 解析）。`LcAudit.Windows` / `Reporting` / `Cli` **尚未建立**，下一步是階段 2（Interop WinTrust/Crypt32 + TestAssets）。

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
- 回歸測試守門員：`cert-embedded-unsigned.exe`（未簽章但內嵌憑證）必須判為 `TRUST_E_NOSIGNATURE`。任何重構讓它變成「已簽章」，就是有人把上述禁忌寫回去了。

其他易錯點：
- 簽章者比對必須解析 DN 取 `O=` 欄位比對 `"NCSOFT Corporation"`，**不可** `cert.Subject.Contains("NCSOFT")`（`CN=NCSOFT-Free-Launcher, O=Evil Ltd` 會通過）。
- 網域白名單必須是**後綴比對**（`host == allowed || host.EndsWith("." + allowed)`，取 `uri.IdnHost` 正規化），**不可** `Contains`／`-like "*plaync*"`（`plaync.com.evil.tw` 會誤判為安全）。
- `WinVerifyTrust` 第一次呼叫後**必做**第二次 `WTD_STATEACTION_CLOSE`，否則洩漏 handle。
- `IPGlobalProperties.GetActiveTcpConnections()` 不回傳 PID，M4-01/M4-03 必須用 `GetExtendedTcpTable`。

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
| 效能 | 完整掃描 < 3 分鐘；事件查詢 `MaxEvents` 預設 5000；**不要對每筆事件呼叫 `ToXml()`**，用 `EventLogPropertySelector` 具名 XPath |
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

`ICheck` 比技術設計 §3 多了 `Title` / `Severity` / `Source` 三個唯讀屬性 —— `SafeCheckDecorator` 與 `AuditRunner` 需要這些靜態中繼資料，才能在檢查項「沒能執行」時仍組出完整的 `Finding`。

## 仍待定案（動到對應模組前必須先決定）

| 期限 | 議題 |
|---|---|
| 階段 2 前 | **M1-06 檔名相似度**演算法（同形字元表 `l/I/1`、`O/0`、`rn/m`，或 Levenshtein 門檻）；**M1-08「時間接近」**的視窗大小 |
| 階段 3 前 | **M2-02 私有網段清單** —— 至少涵蓋 RFC1918、CGNAT `100.64/10`、link-local `169.254/16`、loopback、IPv6 ULA `fc00::/7`；4624 的 `IpAddress` 常出現 `-`／空字串／`::1`，未排除會直接誤判成 `Fail` |
| 階段 4 前 | **M3-03/04/05「非預期成員」的基線** —— 規格從未定義。M3-05 是 Critical(40)、命中即強制「極高」，基線不明會讓裝過 SQL Server／Docker 或有第二管理員帳號的正常機器狂噴極高風險。需預設白名單 + 參數補充<br>**M3-09「近期新增」無法實作** —— `INetFwPolicy2` 不提供規則建立時間，登錄檔 `FirewallRules` 的 `LastWriteTime` 是整個 key 的。判定條件需改寫<br>**M3-04「近期建立的帳號」** —— 同樣無可靠來源，只能用 `C:\Users\<name>` 的 `CreationTime` 推估，報告須註明是推估值 |

## 已知待驗證項目

技術設計 §9 列出三點需先寫 spike 實測（.NET 10 修訂版行為可能有差異）：ADS 讀取是否需 `CreateFileW` fallback、`System.Diagnostics.EventLog` 在 SingleFile+Trim 下的行為、NCSOFT 實際憑證的 DN 結構（韓國憑證可能有多值 RDN）。
