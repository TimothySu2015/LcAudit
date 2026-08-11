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

**M1（9 項）、M2（11 項）、M4（4 項）全數完成，M3 完成 10/13。** 406 個測試全綠，完整掃描約 9 秒。

**尚未實作**：M3-07（排程工作，需 `ITaskService` COM）、M3-09（防火牆，需 `INetFwPolicy2` COM）、M3-12（WMI 事件訂閱，需 `System.Management`）。三者都需要新的相依，其餘功能皆已可用。

M1 已端到端驗證：`plaync.com.evil.tw` 被 M1-04 擋下（後綴比對）、`PurpIe.exe` 被 M1-06 抓到（同形字元）、ADS 讀取正常。M4 的 `GetExtendedTcpTable` 已對真實連線表驗證（含 PID 與位元組順序轉換）。

全量掃描實測約 7 秒（含 150 個服務的簽章驗證），遠低於 NFR-01 的 3 分鐘上限。簽章驗證務必用路徑做快取 —— svchost 代管的服務全指向同一個執行檔。CLI 參數已全部接通（`--days`／`--purple-path`／`--output`／`--format`／`--skip-module`）。

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
- **內嵌簽章與目錄簽章要分開看**。`IAuthenticodeVerifier` 有兩個方法：`Verify()` 只驗內嵌（**M1 專用**），`VerifyIncludingCatalog()` 內嵌不過再查 CatRoot 目錄檔（**M3-06／M3-08 專用**）。Windows 系統檔案（`notepad.exe`、絕大多數 `.sys` 驅動）沒有內嵌簽章，只驗內嵌會把整個作業系統判成未簽章 —— 實測 M3-08 的 150 個服務會誤標 13 個、M3-06 的 16 個啟動項誤標 6 個。反過來，M1 **不可**放寬到目錄簽章：紫P 是第三方程式，本來就該有自己的內嵌簽章。
- **回歸測試守門員是「被竄改的已簽章檔案」**，不是規格說的 `cert-embedded-unsigned.exe`。已在本機實測確認：拿正版 `dotnet.exe` 改動中段一個位元組後，`WinVerifyTrust` 回 `TRUST_E_BAD_DIGEST`（正確），而 `CreateFromSignedFile` 照樣回報「O=Microsoft Corporation」，對竄改毫無反應。假紫P 最省事的做法就是改造正版，不必自己弄憑證。
- `cert-embedded-unsigned.exe` 這個素材**沒有重現**技術設計 §0 描述的繞過。已試兩種構造（DER 附加於 PE 尾端、編為 .NET 內嵌資源），`CreateFromSignedFile` 兩者都拋 `CryptographicException` 而非回報憑證裡的簽章者。它仍是合理的負面案例，但別當它是守門員。若要做出真正的資源區段陷阱，需以 Win32 資源（而非 .NET 內嵌資源）寫入，尚未驗證。
- 禁令不因此放寬：`CreateFromSignedFile` 的致命缺陷是**它根本不做任何驗證**，上面的竄改實測已足以證明。

其他易錯點：
- 簽章者比對必須解析 DN 取 `O=` 欄位，**不可** `cert.Subject.Contains("NCSOFT")`（`CN=NCSOFT-Free-Launcher, O=Evil Ltd` 會通過）。
- **現行官方簽章者是 `O=NC Corporation`，不是 `NCSOFT`。** 已下載官方安裝檔 `PURPLE_Installer_2_26_803_19.exe` 實測確認，完整 Subject 為 `CN=NC Corporation, O=NC Corporation, L=Seongnam, S=Gyeonggi, C=KR`，簽發者是 Microsoft ID Verified CS EOC CA（Azure Trusted Signing）。**公司已更名，組織名稱中不再出現 "NCSOFT" 字串。**
- 技術設計 §4.3 寫的 `"NCSOFT Corporation"` 是錯的。更早的舊憑證是 `NCsoft Corp.`（韓國）與 `NCsoft`（美國）。任何以「完全相符」或「Contains("NCSOFT")」為基礎的判定，都會把**官方安裝檔本身**判為假紫P → Critical → 極高 → 對 100% 的正常使用者喊「端點已不可信，建議重灌」。這是本工具最嚴重的失敗模式。
- 因此 `SignerNameValidator.Classify()` 採三級判定：符合 `KnownOfficialOrganizations` → `Official`(Pass)；**第一個字詞**為 `NC` 或以 `NCSOFT` 開頭 → `LikelyOfficial`(**Warning**)；其餘 → `NotOfficial`(Fail)。用字詞邊界而非 `Contains` 才排得掉 `NCR Corporation`、`NCC Group`、`Encoding Ltd`。仍然只看 `O=` 欄位，CN 陷阱依舊擋得住。
- **Azure Trusted Signing 的憑證有效期只有數天**（實測那張是 2026-08-06～08-09）。所以「憑證已過期但簽章有效」是**常態而非異常** —— M1-03 從 `WinVerifyTrust` 回 `Valid` 反推「有時間戳」的設計因此是正確且必要的。
- 網域白名單必須是**後綴比對**（`host == allowed || host.EndsWith("." + allowed)`，取 `uri.IdnHost` 正規化），**不可** `Contains`／`-like "*plaync*"`（`plaync.com.evil.tw` 會誤判為安全）。
- **功能規格的白名單漏了 `ncupdate.com`**。官方下載頁指向 `https://gs-purple-inst.download.ncupdate.com/Purple/PURPLE_Installer_*.exe`（已實測確認）。漏掉它的後果是：**任何人從官網下載紫P 都會被 M1-04 判 `Fail` → Critical → 極高**，也就是對絕大多數正常使用者喊「假紫P，建議重灌」。
- 因此 `DownloadHostValidator.Classify()` 也改三級：正確後綴 → `Official`(Pass)；**網域字串嵌了官方網域卻不是其子網域** → `Impersonation`(**Fail**，`plaync.com.evil.tw` 這種只有仿冒一種解釋)；與官方無關 → `Unknown`(**Warning**)。白名單是靜態清單、必定不完整，官方隨時可能換 CDN —— 漏收的代價不該由使用者承擔。

## 教訓：判定前提要拿真實資料驗證，不能只看規格

第一份真實使用者報告（正版紫P、乾淨機器）被判為「極高／假紫P／建議重灌」，8 個命中項目中有 7 個是誤報。逐一檢討後歸納出三種前提錯誤：

**1. 把「必然發生的事」判為可疑**
- M1-04「沒有 MOTW」→ 主程式由安裝程式解壓產生，**從來就不帶 Zone.Identifier**；下載回來的安裝檔也多半裝完就刪。這對每個正常使用者都必定成立，判 `Warning` 等於全體誤報。已改判 `Inconclusive`，並改為優先在下載資料夾找 `PURPLE_Installer*.exe` 讀它的 MOTW。
- M1-05「未簽章模組」→ 前提「官方紫P 的模組應全數具備 NCSOFT 簽章」根本是錯的。實測正版安裝 597 個模組中 105 個未簽章，全是 `Autofac.dll`／`AutoMapper.dll`／`CefSharp.*` 這類第三方 NuGet 套件。已改為只有 `BadDigest`（被竄改）才判 `Fail`，未簽章僅列為參考。

**2. 判定範圍過寬**
- `IsSuspiciousLocation` 原本含 `%APPDATA%`／`%LOCALAPPDATA%`／`%ProgramData%` → Teams、Discord、Lenovo Vantage 全中槍，**連 Windows Defender 自己都被標成可疑**。現在只認 `%TEMP%` 與下載資料夾；其餘改用 `IsUserWritableLocation`，必須同時未簽章才算可疑。
- `IsUnsigned` 原本把 `Unknown`／`SecuritySettings`／`Expired` 都算成未簽章。那些是「**驗不出來**」不是「沒簽章」。
- M1-06 的編輯距離長度差放寬到 2 → 官方元件 `purpleon.exe` 中槍（距離 2、長度差 2）。已收緊為 ≤1，並對檔名去重。
- M2-04 未區分來源 → 把本機主控台登入當成遠端連入（實測 52 筆中遠端 0 筆）。現在以 `PrivateAddressClassifier` 判斷來源欄位能否解析為 IP，避免依賴「本機」/"LOCAL" 這種會隨系統語言變動的字串。
- M3-06 未過濾副檔名 → `desktop.ini` 被當成啟動項。
- M4-04 誤用 `GameProcessDetector.KnownNames` 當遠端工具清單 → **紫P 自己被判為「連向已知遠端服務」**。

**3. 推論規則不分 Fail 與 Warning**
- R1「假紫P，建議重灌」被 M1-04 的 `Warning` 觸發，而 M1-01/M1-02 明明都 Pass。**會叫人重灌的結論只能由 `Fail` 觸發。**
- R4「遠端工具遭入侵」同理 —— 「裝了但沒有連入紀錄」是 Warning，不代表遭入侵。
- R3「RDP 遭爆破」的兩個組成都是設計上只產出 Warning 的檢查項，正常使用公司 RDP 的機器必然命中。已拆為兩級：有 M2-02／M2-03 的爆破或公網登入跡證才敢說「遭爆破」（下限「高」），否則降為保留語氣的 R3-P（下限「中」）。

**通則**：新增或修改判定條件前，先問「一台完全乾淨的機器上，這個條件會不會成立？」如果會，那它就不是異常的證據。有真實報告時務必拿來對照。

## 事發時間是最有價值的一個輸入（`--incident-time`）

真實案例：一台被盜帳號的電腦，**AnyDesk 的安裝時間正好就是帳號被盜的時間**。

工具收集了大量時間戳，卻**沒有錨點** —— 只能把一堆時間丟給使用者自己比對。但受害者永遠知道大概什麼時候出事。給了錨點，`IncidentTimeline` 就能把所有帶時間戳的證據依距離排序，把最相關的推到報告最前面。

實作刻意放在**報告層**（`HtmlReporter`／`ConsoleReporter`）而非新增檢查項 —— 它吃的是所有 `Finding.Evidence` 上既有的 `Timestamp`，零耦合，而且未來任何檢查項只要帶上時間戳就自動納入。

**連帶調整**：M2-06/07「有安裝但無連入紀錄」原本一律 `Warning`。但沒有連入紀錄不代表沒被連入 —— 攻擊者用完清掉紀錄檔、或移除工具只剩殘留目錄都是這個結果。因此若 `InstallTimeContext.HasEvidence` 成立（安裝當下螢幕鎖定、或當時有人遠端連著），改判 `Fail`：那不是「值得問一下」，是「有人趁你不在時裝的」。

## 教訓：規格裡的「外部世界事實」必須查證

把規格當 Ground Truth 是對的，但要分辨兩種內容：

| 類型 | 例子 | 處理方式 |
|---|---|---|
| **設計決定** | 評分權重、Severity、模組劃分、判定流程 | 照著做，這是規格的權威範圍 |
| **外部世界事實** | 憑證組織名稱、官方網域、主程式檔名、安裝路徑、服務名稱 | **必須查證**。規格作者也可能寫錯或過時 |

已經抓到兩個：`"NCSOFT Corporation"`（實際是 `NCsoft Corp.`／`NCsoft`）與缺漏的 `ncupdate.com`。兩者都會讓**乾淨的正版使用者**被判為「極高」風險並被建議重灌 —— 這是本工具最嚴重的失敗模式，而且都源自照抄未經查證的字串。

**仍未查證的同類項目**：`PurpleExecutableLocator.CandidateNames`（主程式檔名）、`PurplePathProbe` 的常見安裝路徑、`GameProcessDetector.KnownNames`（遊戲與反作弊程序名）、`RemoteToolCatalog`（遠端工具路徑與服務名）。這些目前只造成漏報而非誤報，但同樣需要實機確認。
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

**報告要回答使用者答得出來的問題**。M2-06/07/08 原本寫「請逐筆核對是否為你本人或你授權的人所為」—— 但**使用者往往根本不知道電腦上有這個遠端程式**，這種問法他答不出來，只會看著報告發呆。

改為：報出**安裝時間**（目錄建立時間推估），並用既有資料做交叉比對 —— 安裝當下螢幕是否鎖定（Security 4800/4801）、前後是否有遠端工作階段（M2-04 的記錄檔，不需提權）、以及**與紫P 的安裝時間相距多久**（`AuditContext.PurpleInstallPath`，唯一允許跨模組共享的狀態）。最後直接問「你認得這個程式嗎？如果完全沒印象裝過，那就是答案」。

兩者相隔 24 小時內即視為同一時段，並標明先後順序 —— 「先裝遠端工具、再換紫P」正是「被誘導安裝後由對方接手」的典型順序。相隔很久也照樣報出天數，使用者可據此判斷哪一次才是異常的。

這些資料我們本來就都有，只是先前沒拿來互相印證。

**模組間狀態**：`AuditContext` 上只有兩項共享狀態 —— M1-00 探測出的 `PurpleInstallPath`（供 M1 其餘項與 M4-01 使用），以及 pre-flight 產生的 `ProtectedPids`（供 M4-03 排除，見上節）。其餘一律不共享。

**執行流程**：提權檢查 → 環境探測 → M1 → M2 → M3 → M4 → 風險彙總 → 報告輸出。

## 不可妥協的約束

| 約束 | 影響 |
|---|---|
| 全程唯讀 | 除 `--output` 目錄外不得寫入任何路徑；不得修改檔案時間戳；不做任何修復／清除／隔離 |
| 檢查全程離線 | **所有檢查項**不得發出任何網路請求。`fdwRevocationChecks = WTD_REVOKE_NONE`，`dwProvFlags \|= WTD_CACHE_ONLY_URL_RETRIEVAL`；M4-04 反查用內建靜態清單，不做 DNS。<br>**唯一例外**是 `ReportUploader`（`--email` 上傳報告），它在檢查全部完成之後才執行，且必須經使用者於提示中確認。新增網路呼叫請先確認它不在檢查路徑上 |
| 降級不中斷 | 任一檢查項失敗只標 `Inconclusive`，不影響其餘項目 |
| 效能 | 完整掃描 < 3 分鐘；事件查詢 `MaxEvents` 預設 5000；**不要對每筆事件呼叫 `ToXml()`**，用 `EventLogPropertySelector` 具名 XPath；篩選一律下推到 XPath，不要撈回來再用 C# 過濾（4624 動輒數萬筆） |
| 中文 | `InvariantGlobalization=false`（報告與路徑含繁中，TC-09）；報告檔輸出 UTF-8 with BOM；Console 輸出開頭設 `Console.OutputEncoding = Encoding.UTF8`，否則舊版主控台顯示繁中會亂碼 |
| 未提權可跑 | 未以系統管理員執行時不得直接結束；Security log 相關項標 `Inconclusive`，其餘照常，並於 Console 首行警示（TC-02） |
| 不碰遊戲 | 記憶體、封包、遊戲檔案完整性一律不觸碰（涉及反作弊機制） |

## 評分規則

Severity 即分數：`Critical=40, High=20, Medium=10, Low=5, Info=0`（enum 底值直接就是分數）。`Fail` 計 100%、`Warning` 計 50%、其餘 0。總分上限 100。等級 0–19 低 / 20–49 中 / 50–79 高 / 80–100 極高。**任一 Critical 命中直接強制為「極高」，不受總分影響**。結束代碼 0/1/2/3 對應四個等級，10 = 執行環境錯誤。

推論引擎（S-06）依 M1/M2/M3 命中組合輸出「最可能的入侵途徑」，決策表見功能規格 §6 FR-S。

**推論結論會替風險等級設下限**（`Inference.MinimumLevel`，R1→極高、R2/R3/R4→高）。這是規格外的補強，理由是規格的加總式評分有個會致命的洞：

> 紫P 完全正版、電腦被植入 AnyDesk 且有連入紀錄 —— 單一 High 項目加起來 10 分，落在「低」(0–19)，**結束代碼 0**。報告會一邊在推論結論寫「第三方遠端工具遭入侵」，一邊在最顯眼的卡片標「低風險」，自動化腳本則判定沒問題。

單一 High 的 Warning 在數學上永遠出不了「低」區間。加總表達不了「組合的意義大於各項相加」，而那正是 S-06 的職責，所以它的結論必須能回饋到等級。等級被拉高時 `AuditSummary.LevelRaisedBy` 會說明原因，報告一定要顯示 —— 否則使用者看到「10 分但高風險」會覺得工具在亂報，反而不信其他發現。

連帶調整：M2-06/07 的「有實際連入紀錄」從 `Warning` 改為 `Fail`。規格寫的是 Warning，但規格自己對 `Fail` 的定義是「明確異常」—— 有人連進你的電腦，這個事實並不模糊，只剩「是否經你授權」需要人工判斷，而報告已附上逐筆時間與來源。「只是裝了但沒有連入紀錄」仍維持 `Warning`。

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
| **M1-06 檔名相似度演算法** | 三條各自可解釋的規則：同形字元折疊後碰撞、正版名稱＋複製後綴、編輯距離 ≤2 且長度差 ≤2 | 規格只舉了 `PurpIe`／`Purple_new` 兩例。純用編輯距離會把安裝目錄裡正常的 `PurpleUpdater.exe` 掃進來；長度差限制就是為了擋這個 |
| **M1-08「時間接近」的視窗** | ±24 小時 | 攻擊者取得遠端存取後未必立刻動手，窗口再放大會把無關的日常遠端使用掃進來 |
| **M1-03 時間戳的判定方式** | 不另外剖析 counter-signature；`WinVerifyTrust` 回 `Valid` 但憑證已過期 ⇒ 有時間戳 | Authenticode 的規則本來就是「憑證過期但簽章當下有合法時間戳 → 仍有效」，可直接從驗證結果反推，省下一整套 Crypt32 剖析 |
| **M1-08 不從 M2 取結果** | 自行查詢終端服務工作階段記錄 | M1-08 依編號在 M2 之前執行，且模組間刻意不共享狀態。該記錄檔不需提權，未提權時仍能完成關聯 |
| **M4-04 改判連線目標埠，不做 IP→網域反查** | 比對對外連線的**目標埠**與發起程序名稱 | 規格寫「反查已知遠端服務網域，對照內建靜態清單」。但不做 DNS 就無法把 IP 反查成網域，而這類服務全架在雲端、IP 段變動頻繁，內建 IP 清單無法負責任地維護 —— 給一份過期清單只會製造「檢查過了」的假象。改判目標埠是離線可靠的部分 |

`ICheck` 比技術設計 §3 多了 `Title` / `Severity` / `Source` 三個唯讀屬性 —— `SafeCheckDecorator` 與 `AuditRunner` 需要這些靜態中繼資料，才能在檢查項「沒能執行」時仍組出完整的 `Finding`。

## 仍待定案（動到對應模組前必須先決定）

| 期限 | 議題 |
|---|---|
| 隨時 | **紫P 主程式檔名與安裝路徑需實機確認** —— `PurpleExecutableLocator.CandidateNames`（`Purple.exe`／`PurpleLauncher.exe`／`NCLauncher.exe`／`NCLauncherU.exe`）、`PurplePathProbe` 的常見路徑清單、`GameProcessDetector.KnownNames` 全部是推測值，未經實機驗證 |
| M2 其餘項實作前 | **M2-08 遠端工具偵測清單**（功能規格附錄 B 有起點，但版本更迭快）；**M2-04 TerminalServices 記錄檔在未啟用時的行為** —— `WindowsEventLog` 已把 `EventLogNotFoundException` 轉為 `FileNotFoundException`，但 M2-04 應判 `Inconclusive` 而非讓它變成一般例外 |
| M3-09 實作前 | **「近期新增」無法實作** —— `INetFwPolicy2` 不提供規則建立時間，登錄檔 `FirewallRules` 的 `LastWriteTime` 是整個 key 的而非逐條。判定條件需改寫，例如退化為「列出所有非 Microsoft 簽章程式的 Inbound Allow 規則」 |

## 已知待驗證項目

技術設計 §9 列出三點需先寫 spike 實測（.NET 10 修訂版行為可能有差異）：ADS 讀取是否需 `CreateFileW` fallback、`System.Diagnostics.EventLog` 在 SingleFile+Trim 下的行為、NCSOFT 實際憑證的 DN 結構（韓國憑證可能有多值 RDN）。
