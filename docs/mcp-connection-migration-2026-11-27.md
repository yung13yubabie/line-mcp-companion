# 本機 MCP 連線遷移與合併前驗收（2026-11-27）

本輪修正 PR #11 基準 `56ea87a37e6b3b59f2156e11bc2e753b865639e5` 的相容性回歸：main 已預設停用舊 HTTP Bearer，Console 卻仍把 `info.mcp_url` 當唯一連線資訊。這不是新版可用的預設設定。此修補不改 main、不合併、不發布、不安裝 APK、不接觸簽章私鑰或真 LINE 資料。

## 既有設定如何遷移

1. 停用用戶端原本指向本機 `/mcp` 的 HTTP 設定，先保持斷線，不要自動回退到 Bearer。
2. App「總控台 → MCP 連線 → 前往設定取得 stdio 範本」。即使 dashboard 讀取失敗或沒有請求統計，也保留狀態及設定入口。
3. 待狀態為「已就緒」再複製 stdio 設定範本。main 回報真正 listener 綁定的受保護端點；未就緒時 `mcp_secure_url=null`。`mcp_status`、`mcp_auth`、`transport`、實際 legacy Boolean 任一缺失／型別不符／URL 不符精確 loopback 契約時，UI 不產生可用範本。舊服務資訊無法證實就緒時顯示未知，不推導 `/secure`。
4. 在執行 MCP 用戶端的同一裝置準備相容 Node 24.22.3 與本專案相依套件；把範本腳本路徑和 `LMA_MCP_CHANNEL_KEY_FILE` 換成實際絕對路徑。金鑰檔須由使用者控制，Unix regular file 0600／0400、同 owner、非 symlink。
5. 另經 App 原有裝置驗證顯示／複製 MCP 通道 key，存入該私有檔案。範本本身不含 key，不需要 Control key。更換通道 key 後須更新該檔；本輪不自動輪替 key、重置資料庫或清除既有設定。
6. 支援 stdio 的用戶端啟動 `scripts/mcp-stdio.ts`；它才會驗身並與 `/mcp/secure` 交換認證密文。該端點不能直接貼到一般 HTTP MCP 欄位。沒有相容 stdio 用戶端時，安全退路是停用舊連線並保持斷線／使用 App 介面；沒有隱藏的明文 fallback。另行配置的雲端 OAuth gateway 是獨立入口，不能拿本機 key 代用。

設定頁同時顯示舊 HTTP Bearer「已停用／已啟用（相容模式）／實際狀態未知」。`mcp_legacy_http` 只表示配置，`mcp_legacy_http_enabled` 才是本次 listener 就緒且明確 opt-in 的實際狀態。main 預設仍關閉；不得為了讓舊設定看似能用而重新預設啟用。服務不可用但既有 MCP 寫入權限為 true 時，仍允許經 Control 嘗試停用；啟用則仍需就緒及裝置驗證。

## 消費端逐項盤點

| 路徑 | 本輪處置 |
| --- | --- |
| `src/main.ts` 的 `info.mcp_url` | 保留歷史欄位，使用實綁 URL；新增 typed readiness 與實際 legacy 狀態。secure URL 僅 ready 時提供 |
| `Console.kt`／`Settings.kt` | 共用純 Kotlin presenter；Console 在缺 dashboard／stats 時仍顯示；設定以實際 secure 欄位產生不含 key 的 stdio 範本，取消裸 HTTP URL 複製 |
| `MainActivity.kt` 身分失敗畫面 | `server_untrusted` 也涵蓋逾時／連線失敗／proof 缺失，不推定其他 App 惡意、不要求移除其他 App；只檢查／重啟本 App 並保持停止連線，保留原驗證邏輯 |
| `Connector.kt`／`src/control/server.ts` 的 `/connector.mcp_url` | 確認是雲端 OAuth gateway，保留；標籤明示與本機不同 |
| `scripts/mcp-interop.mjs` | 標準 SDK 真實 stdio adapter，僅列工具及 `get_sync_status`；改為 `--url …/mcp/secure --key-file /absolute/path`，舊 argv key 語法 exit 64 且不回印輸入 |
| `scripts/serve-fake.ts` | 明確 legacy=false、預設隨機埠、全合成資料與自有私有臨時 key file，不輸出 key；退出只清自己的 fixture |
| `scripts/oauth-smoke.ts` | 獨立 gateway OAuth helper，保留；不是本機 stdio smoke |
| README／local-mcp-channel／connectors／Secrets/main 註解 | 更正本機入口、KEY_FILE 範本、遷移及舊模式範圍 |
| `SECURITY-REVIEW-BRIEF.md` | 明示原 0.2.1 歷史架構／Bearer 表不是目前契約，新增目前對照，保留歷史審查內容 |

## 可重跑的證據與範圍

`node --test test/mcp-entry-migration.test.ts` 從真正 `src/main.ts` 啟動空白私有資料目錄，mock=false、合成 stdin secrets、無 saved LINE token／登入，驗證 Control hello 與完整 response-body proof、實綁非零埠、ready/legacy 欄位、預設 `/mcp` 拒絕及明確 isolated opt-in 的狀態。再使用真正標準 SDK stdio helper 讀同步狀態，核對沒有訊息工具呼叫或 secret 輸出。合成 fixture 另經相同 helper 核對，不代表 Android。

`LocalMcpPresentationTest` 是標準 JUnit4 純 JVM model 測試，涵蓋未知／型別錯誤／未就緒、實際埠、legacy 實際狀態、無 key 範本與降權。Android CI 以原 Gradle 入口執行 `--dependency-verification strict testReviewUnitTest assembleReview`；JUnit／Hamcrest 檔案以官方 Maven Central 精確 SHA-256 鎖定。XML 必須存在、tests>0，failures/errors/skipped 都是 0，否則不得上傳成功 APK artifact；XML 隨成功 artifact 保留。這些是編譯與 JVM 證據，不是 Compose 畫面或真機成功。

## 仍不可替代的驗收

- 本輪沒有已授權可用 Android 裝置。正常安裝、冷啟動、畫面／複製／裝置驗證、前後景、App 程序重啟、整機重啟後狀態、本機 adapter 於同裝置連通，皆未測；不重跑已結束的 #12 雲端模擬器路線。
- ZIP `zipalign -c -P 16 4` 與全部 ELF LOAD／RELRO／依賴可靜態驗證，但不是 16 KiB 真機原生通過。依 [Android 官方判準](https://developer.android.com/guide/practices/page-sizes)，日後須記同份 APK SHA-256、ABI、裝置 `getconf PAGE_SIZE=16384`，及此 App page-size compatibility mode 關閉的可核對證據。僅能開啟或沒警告不足。不得改使用者手機或全域屬性。
- Review code 5 的歷史乾淨 CI signer 不同，不能覆蓋先前 Review／正式安裝。先用 `scripts/review-apk.py inspect/compare` 驗實檔；不同 signer、同 code／降版必須阻擋。本輪不安裝／卸載、不以清資料冒充遷移，不碰簽章私鑰，不宣稱資料保留升級成功。
- native lock 仍含已 EOL 的 OpenSSL 3.6.5，Node Android 也沒有官方支援保證；production fail-closed gate 必須保留。受支援且可核來源的 runtime、原正式簽章連續性與隔離真機驗收仍是正式發布 NO-GO。新 CI APK 是 Review 建置，不是正式版。

本文件記錄可重跑方法及不可代替的門檻；固定新提交、實際測試與 CI／下載雜湊會放在 PR #11，不能把舊產物當本次程式的結果。
