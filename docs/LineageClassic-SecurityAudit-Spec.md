# 天堂：經典版 帳號安全稽核工具 — 規格文件

| 項目 | 內容 |
|---|---|
| 文件名稱 | LineageClassic Security Audit Tool — Functional Specification |
| 版本 | v1.0 (Draft) |
| 日期 | 2026-08-10 |
| 專案代號 | `LcAudit` |
| 文件狀態 | 待實作 |

---

## 1. 目的與範圍

### 1.1 目的
在單機環境下，以**唯讀方式**蒐集並判讀三類跡證，協助玩家判斷帳號被盜的可能途徑：

1. PURPLE Launcher（紫P）是否為官方正版
2. 主機是否曾遭遠端存取
3. 主機是否被植入持久化後門

### 1.2 範圍內 (In Scope)
- 本機 Windows 10 / 11 單機掃描
- 數位簽章驗證、事件記錄剖析、登錄檔與排程檢查
- 風險評分與報告輸出（Console / JSON / HTML）

### 1.3 範圍外 (Out of Scope)
- 任何形式的修復、清除、隔離、刪除動作
- 惡意程式行為分析、沙箱、動態解析
- 網路掃描或對外通報
- 遊戲記憶體、封包、遊戲檔案完整性檢查（涉及反作弊機制，不觸碰）

### 1.4 設計原則
| 原則 | 說明 |
|---|---|
| **唯讀 (Read-Only)** | 全程不寫入受檢系統，僅寫出報告檔至指定輸出目錄 |
| **取證優先** | 不修改檔案時間戳；所有發現須附時間點與原始資料來源路徑 |
| **可離線執行** | 不得依賴網路連線；無外部套件相依 |
| **降級不中斷** | 任一檢查項失敗僅標記為 `Inconclusive`，不影響其餘項目 |

---

## 2. 名詞定義

| 縮寫 | 說明 |
|---|---|
| 紫P / PURPLE | NCSOFT 官方遊戲啟動器 (PURPLE Launcher) |
| ADS | Alternate Data Stream，NTFS 替代資料流 |
| MOTW | Mark of the Web，即 `Zone.Identifier` ADS |
| LogonType 10 | Windows 遠端互動式登入（RDP） |
| LogonType 3 | 網路登入（SMB / 遠端 WMI 等） |
| Finding | 單一檢查項的判定結果 |

---

## 3. 技術選型

| 項目 | 決定 | 理由 |
|---|---|---|
| 語言/執行環境 | **PowerShell 5.1**（Windows 內建） | 免安裝、免編譯，事發當下即可執行；`Get-WinEvent`、`Get-AuthenticodeSignature` 為原生 API |
| 相容性目標 | PowerShell 5.1 與 7.x 皆需可執行 | 5.1 為 Windows 預設 |
| 外部相依 | **零** | 受汙染主機不宜再下載任何東西 |
| 封裝形式 | 單一 `.ps1` 檔 | 便於檢視原始碼、便於流通 |

> **備選方案**：若需長期維護與單元測試，可改以 .NET 8 Console App + `System.Security.Cryptography.X509Certificates` + `System.Diagnostics.Eventing.Reader` 實作。但需編譯與部署，事故當下取得成本較高，故 v1.0 不採用。

### 3.1 執行前提
- 需**系統管理員權限**（讀取 Security 事件記錄的必要條件）
- 若未提權：Security log 相關項目標記為 `Inconclusive`，其餘照常執行，並於報告首行警示

---

## 4. 系統架構

```
LcAudit.ps1
├── Core
│   ├── New-Finding          # 建立標準 Finding 物件
│   ├── Invoke-SafeCheck     # try/catch 包裝，失敗轉 Inconclusive
│   └── Write-Log            # 執行過程記錄
├── Modules
│   ├── M1-PurpleIntegrity   # 紫P 完整性
│   ├── M2-RemoteAccess      # 遠端存取跡證
│   ├── M3-Persistence       # 持久化與後門
│   └── M4-NetworkActivity   # 網路連線
├── Scoring
│   └── Get-RiskScore        # 風險彙總
└── Reporters
    ├── Out-ConsoleReport
    ├── Out-JsonReport
    └── Out-HtmlReport
```

### 4.1 執行流程
```
提權檢查 → 環境探測 → M1 → M2 → M3 → M4 → 風險彙總 → 報告輸出
```
模組間不共享狀態（除 M1 探測出的紫P安裝路徑供 M4 使用）。

---

## 5. 資料模型

### 5.1 Finding 物件

```
Finding {
  Id            : string    # 檢查項編號，如 "M1-01"
  Module        : string    # M1 | M2 | M3 | M4
  Title         : string    # 中文檢查項名稱
  Severity      : enum      # Critical | High | Medium | Low | Info
  Status        : enum      # Pass | Fail | Warning | Inconclusive
  Score         : int       # 命中時計入的風險分數
  Evidence      : object[]  # 原始證據（路徑、時間、值）
  Source        : string    # 資料來源，如 "Security.evtx / EventID 4624"
  Description   : string    # 判定說明
  Recommendation: string    # 建議處置
  CollectedAt   : datetime
}
```

### 5.2 Status 定義

| Status | 意義 | 是否計分 |
|---|---|---|
| `Pass` | 檢查通過，未發現異常 | 否 |
| `Warning` | 有可疑跡象，需人工研判 | 計 50% |
| `Fail` | 明確異常 | 計 100% |
| `Inconclusive` | 因權限、路徑不存在等無法判定 | 否（但需於報告列出） |

---

## 6. 功能需求

### FR-M1｜紫P 完整性驗證

**目標**：判定本機安裝的 PURPLE Launcher 是否為 NCSOFT 官方版本。

| ID | 檢查項 | 資料來源 | 判定條件 | Severity |
|---|---|---|---|---|
| M1-00 | 探測安裝路徑 | 登錄檔 Uninstall 鍵、常見安裝路徑、執行中處理程序 `MainPath` | 找不到 → `Inconclusive` | Info |
| M1-01 | 主程式數位簽章狀態 | `Get-AuthenticodeSignature` | `Status ≠ Valid` → `Fail` | **Critical** |
| M1-02 | 簽章者身分 | 憑證 Subject | 未含 `NCSOFT` → `Fail` | **Critical** |
| M1-03 | 憑證鏈與時間戳 | 憑證 NotBefore / NotAfter / 時間戳記 | 憑證過期且無時間戳 → `Warning` | Medium |
| M1-04 | 安裝檔下載來源 | `Zone.Identifier` ADS 之 `HostUrl` / `ReferrerUrl` | 網域不在白名單 → `Fail`；無 MOTW → `Warning` | **Critical** |
| M1-05 | 安裝目錄未簽章模組 | 遞迴掃描 `*.exe`, `*.dll` | 存在未簽章檔案 → `Warning`（列出清單） | High |
| M1-06 | 可疑檔名相似度 | 檔名比對 | 出現 `Purple*.exe` 的變體（如 `PurpIe`, `Purple_new`）→ `Warning` | High |
| M1-07 | 安裝目錄位置合理性 | 路徑字串 | 位於 `%TEMP%`, `Downloads`, `%APPDATA%` 等非標準位置 → `Warning` | High |
| M1-08 | 安裝時間與異常時間點關聯 | 檔案 CreationTime | 與 M2 發現的可疑遠端時段接近 → `Warning` | Medium |

**M1-04 網域白名單**
```
plaync.com
playnccdn.com
ncsoft.com
```
比對規則需為**後綴比對**（`*.plaync.com` 或 `plaync.com`），不可用 `-like "*plaync*"`，避免 `plaync.evil.com` 誤判為安全。

---

### FR-M2｜遠端存取跡證

**目標**：還原主機是否曾被遠端連入，及其時間與來源。

| ID | 檢查項 | 資料來源 | 判定條件 | Severity |
|---|---|---|---|---|
| M2-01 | 遠端互動登入 | Security / EventID 4624，LogonType = 10 | 有紀錄 → `Warning` 並列出時間+來源IP+帳號 | High |
| M2-02 | 網路登入 | Security / EventID 4624，LogonType = 3，排除 `ANONYMOUS LOGON` 與電腦帳號 | 來源IP 非私有網段 → `Fail` | High |
| M2-03 | 登入失敗爆量 | Security / EventID 4625 | 單一小時 ≥ 10 次 → `Warning` | Medium |
| M2-04 | 終端服務工作階段 | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` EventID 21,22,23,24,25 | 有紀錄 → 列出時間軸 | High |
| M2-05 | RDP 用戶端連線嘗試 | `TerminalServices-RdpClient/Operational` EventID 1024 | — | Info |
| M2-06 | AnyDesk 連線紀錄 | `%APPDATA%\AnyDesk\connection_trace.txt`、`%ProgramData%\AnyDesk\` | 有 incoming 紀錄 → `Warning` | High |
| M2-07 | TeamViewer 連線紀錄 | `Connections_incoming.txt` | 同上 | High |
| M2-08 | 其他遠端工具痕跡 | 檔案系統 + 登錄檔 | 偵測到 RustDesk / ToDesk / Sunlogin(向日葵) / AweSun / AnyViewer / DeskIn / ScreenConnect / Atera | `Warning` | High |
| M2-09 | RDP Bitmap 快取 | `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache` | 檔案存在 → 該機曾**對外**連線（注意方向） | Info |
| M2-10 | 螢幕鎖定/解鎖時間軸 | Security 4800 / 4801 | 建立活動時間軸供比對「人不在時的活動」 | Info |

**M2 共同要求**
- 預設回溯 **90 天**，可由參數調整
- 所有發現需正規化為統一時間軸（本機時間，含時區標示）
- 需彙總「來源 IP 清單」與「首見 / 末見時間」

**Event 4624 欄位索引**（Windows 10/11）
| 索引 | 欄位 |
|---|---|
| `Properties[5]` | TargetUserName |
| `Properties[6]` | TargetDomainName |
| `Properties[8]` | LogonType |
| `Properties[18]` | IpAddress |
| `Properties[19]` | IpPort |

> 實作時不可硬依賴索引即通過驗收；須加上索引越界防呆，並優先嘗試以 `$event.ToXml()` 依 `<Data Name="...">` 取值，索引法僅作為 fallback。

---

### FR-M3｜持久化與後門

| ID | 檢查項 | 資料來源 | 判定條件 | Severity |
|---|---|---|---|---|
| M3-01 | RDP 服務是否啟用 | `HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` | 值 = 0（已啟用）→ `Warning` | High |
| M3-02 | RDP 通訊埠是否被改 | `...\WinStations\RDP-Tcp\PortNumber` | ≠ 3389 → `Fail` | High |
| M3-03 | 遠端桌面使用者群組 | `net localgroup "Remote Desktop Users"` | 非預期成員 → `Warning` | High |
| M3-04 | 本機帳號清單 | `Get-LocalUser` | 存在啟用中的非預期帳號、或近期建立的帳號 → `Warning` | High |
| M3-05 | 系統管理員群組成員 | `Administrators` | 非預期成員 → `Fail` | **Critical** |
| M3-06 | 開機自動啟動 | Run / RunOnce（HKLM+HKCU）、Startup 資料夾 | 未簽章或路徑位於 `%TEMP%`/`%APPDATA%` → `Warning` | High |
| M3-07 | 排程工作 | `Get-ScheduledTask` | 排除 `\Microsoft\*`；Action 指向未簽章執行檔 → `Warning` | High |
| M3-08 | 非預期服務 | `Get-CimService` | 非 Microsoft 簽章且為自動啟動 → `Warning` | Medium |
| M3-09 | 防火牆輸入允許規則 | `Get-NetFirewallRule` | 近期新增的 Inbound Allow 規則 → `Warning` | Medium |
| M3-10 | Defender 排除清單 | `Get-MpPreference` | 存在排除路徑 → `Warning`（惡意程式常見手法） | High |
| M3-11 | Defender 保護狀態 | `Get-MpComputerStatus` | 即時防護關閉 → `Fail` | High |
| M3-12 | WMI 事件訂閱 | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` | 存在非預設項目 → `Warning` | High |
| M3-13 | Hosts 檔竄改 | `%SystemRoot%\System32\drivers\etc\hosts` | 含 `plaync` / `ncsoft` / `google` 相關導向 → `Fail` | **Critical** |

---

### FR-M4｜網路活動

| ID | 檢查項 | 資料來源 | 判定條件 | Severity |
|---|---|---|---|---|
| M4-01 | 紫P 相關處理程序連線 | `Get-NetTCPConnection` + `Get-Process` | 列出遠端 IP / Port | Info |
| M4-02 | 監聽中的通訊埠 | `Get-NetTCPConnection -State Listen` | 存在遠端工具常用埠（3389/5938/7070/6568/…）→ `Warning` | Medium |
| M4-03 | 未簽章處理程序的對外連線 | 交叉比對 | 有 → `Warning` | High |
| M4-04 | 反查已知遠端服務網域 | 對照內建靜態清單（不做 DNS 查詢） | 命中 → `Warning` | Medium |

---

### FR-S｜風險評分

| ID | 需求 |
|---|---|
| S-01 | 依 Severity 給定基礎分：Critical=40, High=20, Medium=10, Low=5, Info=0 |
| S-02 | `Fail` 計 100%，`Warning` 計 50%，其餘 0 |
| S-03 | 總分上限 100 |
| S-04 | 輸出風險等級：0–19 低 / 20–49 中 / 50–79 高 / 80–100 **極高** |
| S-05 | 任一 `Critical` 命中時，等級直接強制為「極高」，不受總分影響 |
| S-06 | 報告須提供「最可能的入侵途徑」推論：依 M1/M2/M3 命中組合輸出對應結論 |

**S-06 推論規則（範例）**
| 命中組合 | 推論結論 |
|---|---|
| M1-01 或 M1-02 或 M1-04 | 假紫P／釣魚安裝檔 — 端點已不可信 |
| M2-06/07/08 有 incoming 且 M1 全 Pass | 第三方遠端工具遭入侵 |
| M2-01/04 + M3-03/04 | RDP 遭爆破或帳號被建立 |
| M3-10 + M3-11 | 防毒遭主動停用 — 高度可疑 |
| 全數 Pass | 端點未見異常，被盜途徑偏向帳號側（釣魚網頁 / 信箱被打穿 / OTP 社交工程） |

---

## 7. CLI 介面

```powershell
.\LcAudit.ps1
    [-Days <int>]              # 事件回溯天數，預設 90
    [-PurplePath <string>]     # 手動指定紫P路徑，跳過自動探測
    [-OutputPath <string>]     # 報告輸出目錄，預設 .\LcAudit-Report
    [-Format <Console|Json|Html|All>]   # 預設 All
    [-SkipModule <string[]>]   # 例如 -SkipModule M4
    [-Quiet]                   # 僅輸出摘要
```

### 7.1 結束代碼
| Code | 意義 |
|---|---|
| 0 | 掃描完成，風險等級 = 低 |
| 1 | 掃描完成，風險等級 = 中 |
| 2 | 掃描完成，風險等級 = 高 |
| 3 | 掃描完成，風險等級 = 極高 |
| 10 | 執行環境錯誤（如非 Windows） |

---

## 8. 輸出規格

### 8.1 Console
- 依模組分區塊，`Fail` 紅色 / `Warning` 黃色 / `Pass` 綠色 / `Inconclusive` 灰色
- 結尾輸出：風險等級、命中項目數、最可能入侵途徑、下一步建議

### 8.2 JSON
檔名 `LcAudit-{COMPUTERNAME}-{yyyyMMdd-HHmmss}.json`
```
{
  "schemaVersion": "1.0",
  "scannedAt": "...",
  "elevated": true,
  "host": { "computerName": "...", "osVersion": "...", "timeZone": "..." },
  "summary": { "score": 0, "level": "低", "criticalHits": 0, "inference": "..." },
  "findings": [ Finding, ... ]
}
```

### 8.3 HTML
- 單一自包含檔案（CSS inline，無外部資源）
- 頂部：風險等級卡片 + 推論結論
- 中段：遠端存取時間軸（依時間排序的表格）
- 下段：完整 Finding 明細，可折疊
- **底部固定區塊：取證保存提醒**（見 §10）

---

## 9. 非功能需求

| ID | 需求 |
|---|---|
| NFR-01 | 完整掃描應於 3 分鐘內完成（事件記錄查詢須設定 `-MaxEvents` 上限，預設 5000） |
| NFR-02 | 記憶體使用不超過 500 MB；事件處理採串流，不整批載入 |
| NFR-03 | 全程唯讀；除 `-OutputPath` 外不得寫入任何路徑 |
| NFR-04 | 任一檢查項的例外必須被捕捉並轉為 `Inconclusive`，不得中斷整體流程 |
| NFR-05 | 報告中不得包含密碼、Token、憑證私鑰等敏感資料 |
| NFR-06 | 不得對外發出任何網路請求 |
| NFR-07 | 相容 PowerShell 5.1 語法（不使用 `??`、`?.`、`ForEach-Object -Parallel`） |
| NFR-08 | 輸出檔案編碼為 UTF-8 with BOM（避免 5.1 環境中文亂碼） |
| NFR-09 | 腳本本身建議自我簽章或提供 SHA-256，供他人驗證未被竄改 |

---

## 10. 取證保存要求

工具需於報告中明確提示以下事項：

1. 在執行任何清除、重灌前，先完整保存本報告的 JSON 與 HTML
2. 建議另行匯出原始事件記錄：
   ```
   wevtutil epl Security .\Security-backup.evtx
   wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" .\TS-backup.evtx
   ```
3. 報案時需一併提供：時間點、來源 IP、遊戲內損失清單、官方 1:1 客服單號

---

## 11. 測試案例

| TC | 情境 | 預期結果 |
|---|---|---|
| TC-01 | 乾淨機器、官方紫P | 風險等級「低」，M1 全 Pass |
| TC-02 | 未提權執行 | 正常完成，M2-01/02/03 標記 `Inconclusive`，首行顯示提權警示 |
| TC-03 | 未安裝紫P | M1-00 `Inconclusive`，M1 其餘項跳過，不拋出例外 |
| TC-04 | 將任一 `.exe` 改名為 `Purple.exe` 置於安裝目錄 | M1-01/M1-02 判定 `Fail`，等級「極高」 |
| TC-05 | 手動建立含非白名單 HostUrl 的 Zone.Identifier | M1-04 判定 `Fail` |
| TC-06 | 安裝並使用 AnyDesk 連入一次 | M2-06 判定 `Warning` 並列出連線時間 |
| TC-07 | 事件記錄已被清空 | M2 各項 `Inconclusive`，並額外提示「事件記錄可能遭清除」（檢查 EventID 1102） |
| TC-08 | 指定 `-SkipModule M3,M4` | 僅執行 M1/M2，評分基準相應調整並於報告註明 |
| TC-09 | 中文路徑 / 中文使用者名稱 | 報告無亂碼，路徑正確 |
| TC-10 | PowerShell 7.x 執行 | 行為與 5.1 一致 |

---

## 12. 已知限制

| 限制 | 說明 |
|---|---|
| L-01 | 攻擊者具管理員權限時可清除事件記錄，`Pass` 不代表未被入侵 |
| L-02 | 事件記錄有大小上限，超過保留期的紀錄無法還原 |
| L-03 | Rootkit 等級的隱藏無法以使用者模式 API 偵測 |
| L-04 | 無法判斷帳號是否在**遊戲廠商端**被異動（需靠官方登入紀錄） |
| L-05 | 若已確認 M1 命中，本工具的其他結果均不可全然採信 —— 應直接重灌 |
| L-06 | 白名單網域清單為靜態，需隨官方變更手動維護 |

---

## 13. 未來版本規劃

| 版本 | 項目 |
|---|---|
| v1.1 | 瀏覽器下載紀錄剖析（Chrome/Edge `History` SQLite） |
| v1.2 | Prefetch / ShimCache 執行痕跡還原 |
| v1.3 | 基線快照比對模式（乾淨時建立基線，事後 diff） |
| v2.0 | .NET 8 重寫，含單元測試與 CI |

---

## 附錄 A：關鍵 API 對照

| 用途 | PowerShell | .NET |
|---|---|---|
| 數位簽章 | `Get-AuthenticodeSignature` | `X509Certificate.CreateFromSignedFile` / WinVerifyTrust |
| 事件記錄 | `Get-WinEvent -FilterHashtable` | `EventLogQuery` / `EventLogReader` |
| ADS 讀取 | `Get-Content -Stream Zone.Identifier` | `CreateFile("path:Zone.Identifier")` P/Invoke |
| TCP 連線 | `Get-NetTCPConnection` | `IPGlobalProperties.GetActiveTcpConnections()` + `GetExtendedTcpTable` 取 PID |
| 排程工作 | `Get-ScheduledTask` | `Microsoft.Win32.TaskScheduler` |
| WMI | `Get-CimInstance` | `System.Management` |

## 附錄 B：遠端工具偵測特徵

| 工具 | 檔案系統特徵 | 服務名稱 |
|---|---|---|
| AnyDesk | `%ProgramData%\AnyDesk\`, `connection_trace.txt` | `AnyDesk` |
| TeamViewer | `Connections_incoming.txt` | `TeamViewer` |
| RustDesk | `%APPDATA%\RustDesk\` | `RustDesk` |
| ToDesk | `%ProgramFiles%\ToDesk\` | `ToDesk_Service` |
| 向日葵 Sunlogin | `%ProgramFiles%\Oray\` | `SunloginService` |
| Chrome Remote Desktop | `%ProgramFiles(x86)%\Google\Chrome Remote Desktop\` | `chromoting` |
| AweSun | `%ProgramFiles%\AweRay\` | `AweSunService` |
| ScreenConnect | — | `ScreenConnect Client*` |
