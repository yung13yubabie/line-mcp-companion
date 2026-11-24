# 主執行緒 / ANR 稽核（2026-11-25）

debug 版在 MainActivity 與 NodeService 啟用 StrictMode（detectAll + penaltyLog，logcat tag `StrictMode`）。

| 原本在主執行緒 | 改成 |
|---|---|
| `Secrets.controlToken/mcpToken`（Keystore + EncryptedSharedPreferences 解密，首次會產生金鑰） | `produceState` + `Dispatchers.IO`，期間顯示轉圈「準備中…」 |
| `startForegroundService` → 5 秒內必須 `startForeground` | 改 `startService`；NodeService.onCreate 立即 `startForeground` |
| Node 資產解壓、行程啟動、stdout 讀取 | `node-supervisor` 背景執行緒 |
| ControlClient HTTP（state/chats/messages/info/設定） | 全部 `withContext(Dispatchers.IO)` |
| Mock 開關讀寫 SharedPreferences（`commit()`）、清除時刪資料夾 | `Dispatchers.IO` |
| QR 圖：640×640 次 `Bitmap.setPixel` | `Dispatchers.Default` + 一次 `setPixels`，產生中顯示轉圈 |
| 聊天室訊息載入 | IO + 頂部進度條 |

驗證（x86_64 模擬器，TCG 軟體模擬）：本 App 行程 StrictMode 違規 0、`am_anr` 0；啟動後主執行緒取樣（debuggerd -j ×6）皆停在 `MessageQueue.nativePollOnce`（閒置）。
同期間模擬器有 18+ 次系統行程 ANR（com.android.phone、systemui 桌布、bluetooth…），是無 KVM 的模擬器本身過慢；先前截圖中的對話框屬於這類。
