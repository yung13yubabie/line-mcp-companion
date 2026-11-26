# 2026-11-26 防禦覆核接手紀錄

本輪以 PR #5 的 `a913a96576276ea304dbeac4c6c37d8eadcf0ad0` 為基準，在獨立 checkout 工作，沿用 `security/review-20261125`，沒有合併 main 或建立重複 PR。僅處理自有程式防禦；沒有接觸真實 LINE 聊天、登入、模型 key，沒有占埠攔截或外部主動測試。

**正式發布仍 NO-GO。Review APK 是獨立測試安裝，不能覆蓋正式 App。**

## 已完成的修補

| 項目 | 判定、修補與證據 |
| --- | --- |
| IA-01：一般 audit 的內容旁路 | 原碼確認且獨立合成安全期望修前失敗。一般 audit 不再保存自由文字、訊息、prompt、client 名稱、URL 或供應商錯誤，只保留固定 numeric/boolean metadata 及有限 enum。啟動時以交易清理既有兩個 audit stream 的 detail，使用 SQLite secure_delete 與 WAL checkpoint；保留時間、動作及必要計數。獨立檔案型 SQLite/WAL 合成 marker 檢查通過，不宣稱清除備份、外部副本或檔案系統歷史。 |
| IA-02：本機 MCP 最小權限 | 本機 HTTP 預設僅註冊只讀工具。每個 request 重新讀 `mcp_allow_write`；App「設定 → MCP 連線 → 允許本機 MCP 寫入」可透過已驗證 Control 通道修改，啟用需裝置驗證，關閉可直接執行。已開始的工具操作仍依各自撤銷語意，不宣稱召回在途操作。雲端 gateway 的 OAuth scope 不受此本機開關取代。 |
| IA-03：診斷日誌 | console 的 object、Error、插值完成格式化後，統一遮蔽當前已知秘密並限制單次輸出；移除啟動日誌的 pairing code。Android 使用 4096-byte chunk 持續讀取並限制私有 node.log 最多 2,000,000 bytes，超限輪替，不把 child output 複製到 logcat。格式化遮蔽有獨立合成測試，Android 程序與裝置行為尚待驗收。 |

原有 audit 的詳細錯誤文字會被省略，以動作、固定原因及數量診斷。這是刻意的資料最小化。其餘訊息儲存、EventLog 自由文字 detail、outbox.error 及供應商任意錯誤內容仍有獨立生命週期與剩餘風險，不能把本次修改解讀成「所有日誌無內容」或「整個資料庫已加密」。

## 實際驗證

- 基準原始 Node 回歸：155/155，exit 0。
- 修後 Node 回歸：156/156，exit 0；含真正桌面 `src/main.ts` 子程序啟動與合成資料。首次修後為 155/156，既有 fixture 未指定 `LINE_CONNECTOR_PORT` 而發生 EADDRINUSE；只把 fixture 改為動態埠，保留失敗與修後輸出。
- TypeScript：`npm run typecheck`，exit 0。
- Native gate：30/30，exit 0。只驗證固定來源／雜湊及 gate 邏輯，不代表 runtime 已受支援。
- Android JavaScript 入口：固定 hash 的 Bun 1.4.5 完成 release bundle，mock gate 通過。
- 獨立覆核：audit/console 5/5、標準 MCP SDK client scenario 1/1，exit 0；使用真正 loopback HTTP 與 HMAC Control、合成 sync。涵蓋預設拒絕、直接呼叫拒絕、明確啟用正例及下一個 request 降權。沒有真 LINE 或真模型。
- 所有獨立來源、修前失敗、修後輸出與限制見 [獨立報告](../review-work/independent-20261126/REPORT.md)。CI 另外執行 `npm run test:review` 並保留輸出。
- 本機沒有 Android SDK、adb 或可用裝置；Android 編譯／APK 驗簽以本輪 GitHub Android workflow 實際結果為準。編譯與靜態檢查不能代替裝置啟動、背景或升級驗收。

## Runtime 與正式發布阻擋

2026-11-26 重新讀取 [Termux 官方 OpenSSL 配方](https://github.com/termux/termux-packages/blob/master/packages/openssl/build.sh)，仍為 `1:3.6.5`。OpenSSL 官方的 [3.6 EOL 公告](https://openssl-library.org/post/2026-11-01-eol34-36/) 與 [安全公告清單](https://openssl-library.org/news/vulnerabilities/) 仍不構成此 App 已成功利用的證據；維護風險與可達利用分開判定。沒有將未驗的其他版本替換進 APK，也沒有修改批准欄位繞過 gate。

以下仍阻擋正式發布：受支援且完成 ABI/TLS/SQLite/裝置覆驗的原生 runtime、本機 MCP 伺服器身分、原正式簽章，以及裝置與支援資料途徑端到端驗收。預設只讀只降低權限，不能解除 G01。原簽章未提供，本輪使用 Review 測試簽章，獨立套件 `tw.linemcp.app.review`。

## GitHub 與 APK 交付

採用已連接的 repository owner GitHub connector 寫入既有 PR 分支，固定提交後再讀遠端確認。Review workflow 會產出兩個 ABI 的 APK、簽章／package 報告、native lock、source commit 與 SHA256SUMS；只能把同次成功 run 的檔案搭配使用。APK 與來源 hash／簽章重新核對完成前，不把新產物描述成已驗證交付。

目前 GitHub connector 沒有建立 Release 或二進位 asset 上傳工具；正常 GitHub CLI 回報尚未登入（exit 4），雲端瀏覽器在建立 GitHub tab 時逾時，未進入登入或提交任何 Release。沒有讀取／搬移憑證或嘗試繞過存取控制。Review 預發布尚未建立；若仍受阻，PR 與成功 CI artifact 是已完成工作的交付入口。正式 Release 不在本輪發布範圍。
