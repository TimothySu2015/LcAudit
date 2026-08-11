# LcAudit 報告接收端 — 部署步驟

大約 15 分鐘。**不需要信用卡、不需要開通 Google Cloud、不需要維護伺服器。**

---

## 為什麼用 Apps Script 而不是把憑證放進執行檔

`LcAudit.exe` 是公開下載的檔案，任何人都能把裡面的字串挖出來。若在其中放 Gmail 應用程式密碼：

- 拿到的人不只能冒名寄信，**還能用 IMAP 讀取信箱裡所有已收到的報告** —— 那裡面是受害者的電腦名稱、帳號、來源 IP 與軟體清單
- 同一組憑證從數百台不同玩家電腦登入，正是「帳號遭盜用」的特徵，**Google 會預防性停用該帳號，就算完全沒有濫用也一樣**

Apps Script 的 Web App **以指令碼擁有者的身分執行**，所以客戶端只需要一個公開網址，不需要任何憑證。存檔與寄信都在 Google 那一端用你的帳號完成。

---

## 步驟

### 1. 建立存放報告的資料夾

用 `lcaudit2026@gmail.com` 登入 [Google 雲端硬碟](https://drive.google.com)，新增一個資料夾（例如 `LcAudit-Reports`）。

開啟該資料夾，從網址列複製 ID：

```
https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz
                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^ 這一段
```

### 2. 建立指令碼

到 [script.google.com](https://script.google.com)（用同一個帳號登入）→ **新增專案**。

把 `Code.gs` 的內容整個貼上，取代預設內容，然後修改最上方三行設定：

```javascript
const FOLDER_ID = '1AbCdEfGhIjKlMnOpQrStUvWxYz';   // 步驟 1 複製的 ID
const NOTIFY_EMAIL = 'lcaudit2026@gmail.com';
const SHARED_TOKEN = '請換成一長串隨機字串';
```

`SHARED_TOKEN` 可以用這行產生：

```powershell
[Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
```

### 3. 部署

右上角 **部署 → 新增部署作業** → 齒輪選 **網頁應用程式**，然後：

| 欄位 | 選擇 |
|---|---|
| 執行身分 | **我**（這是關鍵，讓指令碼用你的帳號存檔寄信） |
| 誰可以存取 | **所有人** |

按「部署」。第一次會要求授權 —— 會出現「Google 尚未驗證這個應用程式」的警告，那是因為這是你自己寫的指令碼，點**進階 → 前往（不安全）**繼續。

完成後複製那個 **網頁應用程式網址**，形如：

```
https://script.google.com/macros/s/AKfycb.../exec
```

### 4. 確認網址是通的

用瀏覽器直接開那個網址，應該看到：

```json
{"status":200,"message":"LcAudit report endpoint is running"}
```

### 5. 把網址與 token 給我

我會把 `--email` 改成真的上傳到這個端點。

---

## 需要知道的限制

| 項目 | 限制 | 對本用途 |
|---|---|---|
| 儲存空間 | 15 GB（免費 Google 帳號） | 一份報告約 16 KB，可存約 90 萬份 |
| 通知信 | 每天 100 個收件人 | 每份報告一封，遠遠夠用 |
| 指令碼執行時間 | 每天 90 分鐘 | 每次執行不到一秒 |
| POST 大小 | 約 50 MB | 報告 16 KB |

## 濫用風險與應對

那個網址是**公開的** —— 這是設計如此，就像網頁表單的送出網址一樣。`SHARED_TOKEN` 會出現在公開的執行檔裡，**它不是機密**，只能擋掉隨機掃描的機器人。

若真的遭到濫用（有人刻意灌爆你的硬碟）：

1. 在 Apps Script 中**重新部署**，會得到全新網址，舊網址立即失效
2. 更新 token 並發佈新版 LcAudit

指令碼已內建 5 MB 的單檔上限，避免單次上傳灌爆空間。

## 個資提醒

報告內含受害者的電腦名稱、使用者帳號、來源 IP、安裝軟體清單。收下這些資料代表你成為個資的保管者，實務上建議：

- 定期清理不再需要的報告
- 不要把報告轉傳給無關的第三方
- 若當事人要求刪除，配合處理
