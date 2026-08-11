/**
 * LcAudit 報告接收端（Google Apps Script Web App）
 *
 * 為什麼用 Apps Script 而不是把憑證放進執行檔：
 *
 * LcAudit.exe 是公開下載的檔案，任何人都能把裡面的字串挖出來。若在其中放 Gmail
 * 應用程式密碼，拿到的人不只能冒名寄信，還能用 IMAP 讀取信箱裡所有已收到的報告
 * —— 那裡面是受害者的電腦名稱、帳號、來源 IP 與軟體清單。
 *
 * 而且同一組憑證從數百台不同玩家電腦登入，正是「帳號遭盜用」的特徵，Google 會
 * 預防性停用該帳號 —— 就算完全沒有濫用也一樣。
 *
 * Apps Script 的 Web App 以「指令碼擁有者」的身分執行，所以客戶端只需要知道一個
 * 公開網址，不需要任何憑證。存檔與寄信都在 Google 這一端用你的帳號完成。
 *
 * 部署方式見同目錄的 README.md。
 */

// ── 設定（部署前請修改這三行）────────────────────────────────────────────

/** 存放報告的雲端硬碟資料夾 ID（從資料夾網址列尾端複製）。 */
const FOLDER_ID = 'PUT_YOUR_DRIVE_FOLDER_ID_HERE';

/** 收到新報告時的通知信箱。留空字串則不寄通知。 */
const NOTIFY_EMAIL = 'lcaudit2026@gmail.com';

/**
 * 與客戶端共用的識別字串。
 *
 * 這**不是**機密 —— 它會出現在公開的執行檔裡，有心人挖得出來。它的作用只是擋掉
 * 隨機掃描網際網路的機器人，不是真正的存取控制。
 *
 * 若遭到濫用，重新部署一次就會得到全新的網址，舊網址立即失效。
 */
const SHARED_TOKEN = 'PUT_A_RANDOM_STRING_HERE';

/** 單一報告的大小上限。實際報告壓縮後約 16 KB，這個上限已相當寬鬆。 */
const MAX_BYTES = 5 * 1024 * 1024;

// ── 接收端 ───────────────────────────────────────────────────────────────

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return reply(400, 'empty body');
    }

    const payload = JSON.parse(e.postData.contents);

    if (payload.token !== SHARED_TOKEN) {
      return reply(403, 'bad token');
    }

    const fileName = sanitise(payload.fileName);
    if (!fileName) {
      return reply(400, 'bad file name');
    }

    const bytes = Utilities.base64Decode(payload.contentBase64);
    if (bytes.length === 0 || bytes.length > MAX_BYTES) {
      return reply(400, 'bad size');
    }

    const folder = DriveApp.getFolderById(FOLDER_ID);
    const file = folder.createFile(Utilities.newBlob(bytes, 'application/zip', fileName));

    notify(payload.reportId, fileName, bytes.length, file.getUrl());

    return reply(200, 'ok', { reportId: payload.reportId });
  } catch (err) {
    // 不要把內部錯誤細節回傳給客戶端
    console.error(err);
    return reply(500, 'server error');
  }
}

/** 健康檢查用，方便部署後直接用瀏覽器確認網址是通的。 */
function doGet() {
  return reply(200, 'LcAudit report endpoint is running');
}

// ── 內部 ─────────────────────────────────────────────────────────────────

/**
 * 通知信刻意**不帶附件** —— 消費者 Gmail 的寄信配額是每天 100 個收件人，
 * 而寫入雲端硬碟沒有這個限制。報告存在 Drive，信裡只放連結。
 */
function notify(reportId, fileName, byteLength, fileUrl) {
  if (!NOTIFY_EMAIL) {
    return;
  }

  // 配額用完時不要讓整個請求失敗 —— 檔案已經存好了，通知信不是關鍵路徑
  if (MailApp.getRemainingDailyQuota() < 1) {
    console.warn('daily mail quota exhausted, skipping notification');
    return;
  }

  MailApp.sendEmail({
    to: NOTIFY_EMAIL,
    subject: 'LcAudit 新報告 ' + (reportId || '(無識別碼)'),
    body: [
      '收到一份新的稽核報告。',
      '',
      '識別碼：' + (reportId || '(無)'),
      '檔名　：' + fileName,
      '大小　：' + Math.round(byteLength / 1024) + ' KB',
      '連結　：' + fileUrl,
    ].join('\n'),
  });
}

/** 檔名淨化 —— 上傳者可控的字串絕不可直接當檔名使用。 */
function sanitise(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 200) {
    return null;
  }

  const cleaned = name.replace(/[^A-Za-z0-9._-]/g, '_');

  return cleaned.endsWith('.zip') ? cleaned : cleaned + '.zip';
}

function reply(status, message, extra) {
  const body = Object.assign({ status: status, message: message }, extra || {});

  return ContentService
    .createTextOutput(JSON.stringify(body))
    .setMimeType(ContentService.MimeType.JSON);
}
