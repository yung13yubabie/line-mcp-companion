# LINE MCP App（Android）— 階段 1 骨架

以「次要裝置（ANDROIDSECONDARY）」登入個人 LINE 帳號，把**勾選的會話**同步到手機本地 SQLite，並在 `127.0.0.1` 提供 MCP Server 給外部 AI 讀取。預設**不標已讀**。

> ⚠️ 非官方協議（LINEJS），LINE 可能限制或停用帳號。第一次測試建議用小號。

## 架構

```
┌──────── Android App（tw.linemcp.app）────────────────────────┐
│ Kotlin / Jetpack Compose UI                                  │
│   登入（QR+PIN）· 聊天列表勾選 · 設定                          │
│        │ HTTP 127.0.0.1:47824 /control（Bearer token）        │
│ NodeService（Foreground Service, dataSync）                  │
│   └─ 執行 libnode.so（Node 24 arm64）+ assets/nodeapp/main.mjs │
│        ├─ auth/session   LINEJS BaseClient(device=ANDROIDSECONDARY) │
│        ├─ guard          擋 sendChatChecked/markAsRead/金鑰註冊   │
│        ├─ sync/engine    talk.sync 長輪詢 + getRecentMessagesV2   │
│        ├─ storage        node:sqlite + FTS5 trigram（filesDir）  │
│        ├─ whitelist      只有勾選會話能被 MCP 看到              │
│        └─ mcp/server     127.0.0.1:47823/mcp（Streamable HTTP） │
└──────────────────────────────────────────────────────────────┘
```

## 目錄

| 路徑 | 內容 |
| --- | --- |
| `src/auth/session.ts` | 次要裝置登入（QR+PIN、token），token 存 SQLite |
| `src/guard/upstream-guard.ts` | 已讀回條與 E2EE 金鑰註冊的守門員（預設封鎖） |
| `src/storage/schema.ts`, `db.ts` | SQLite 結構（chat / message / message_fts / read_state / media / line_kv ...） |
| `src/storage/kv-storage.ts` | LINEJS `BaseStorage` 的 SQLite 實作 |
| `src/whitelist.ts` | 會話白名單（未允許與不存在回同一錯誤） |
| `src/sync/engine.ts` | 同步引擎；`sync_scope=allowed`（預設）只抓勾選會話內容 |
| `src/sync/linejs-source.ts` | 真實 LINE 來源（**尚未對真帳號驗證**） |
| `src/media/cache.ts` | 附件下載與快取 |
| `src/mcp/tools.ts`, `server.ts` | 8 個基本 MCP 工具與 HTTP server |
| `src/control/server.ts` | 給 Kotlin UI 的控制 API |
| `src/main.ts` | 常駐程序進入點（Android/桌面共用） |
| `scripts/login-poc.ts` | 桌面登入 PoC |
| `scripts/serve-fake.ts` | 假資料 MCP，方便接 AI 客戶端試用 |
| `test/` | 單元 / 端到端測試（全部假資料，不連 LINE） |
| `android/` | Android Gradle 專案（Compose UI + NodeService） |

## MCP 工具（基本，永遠可用）

`list_allowed_chats`、`get_messages`、`search_messages`、`get_attachment`、`download_media`、`get_unread_summary`、`get_sync_status`、`trigger_sync`。全部受白名單限制，沒有任何工具會呼叫已讀 API。

## 開發

需要 Node 24.11+（LINEJS 要求 `^22.18 || ^24.11 || >=26`，`node:sqlite` 也需要新版 Node）。

```bash
npm install
npm test                 # 13 個測試，不連網
npm run typecheck
npm run serve:fake       # 假資料 MCP：http://127.0.0.1:47823/mcp
```

### 第一次真實登入（桌面 PoC）

```bash
node scripts/login-poc.ts            # 終端機印出 QR → 手機 LINE 掃描 → 手機輸入畫面上的 PIN
node scripts/login-poc.ts --token    # 之後用保存的 token 登入
```

成功會印出顯示名稱與群組數；token 與金鑰在 `.state/line.db`（已 gitignore，請勿外流）。

## Android 建置

```bash
npm run bundle:android               # 把 src/main.ts 打包成 assets/nodeapp/main.mjs
cd android && ./gradlew assembleDebug
```

**還缺 `android/app/src/main/jniLibs/arm64-v8a/libnode.so`**（Android arm64 版 Node 24 執行檔）。nodejs-mobile 只到 Node 18.20.4，不符合 LINEJS 與 `node:sqlite` 的版本需求，所以要自備：

1. 用 Node 官方原始碼的 `android-configure` + Android NDK 交叉編譯 Node 24（建議，靜態連結 OpenSSL/ICU，產物單一檔案）；或
2. 取 Termux 的 `nodejs-lts`（24.22.3）並一併打包它依賴的 `libc++ openssl c-ares libicu libsqlite zlib`，用 patchelf 改 DT_NEEDED/RUNPATH 成 `lib*.so` 名稱。

## 安全預設

- MCP 與控制 API 只綁 `127.0.0.1`，Android 端一律帶隨機 Bearer token（存在 Android Keystore 加密的 SharedPreferences）。
- 已讀：`sendChatChecked / markAsRead / markChatsAsRead / markThreadsAsRead` 預設封鎖，`settings.read_receipts=on` 才放行。
- E2EE：預設封鎖金鑰註冊；QR 登入若沒從主裝置拿到金鑰，登入會**明確失敗**而不是悄悄註冊新金鑰。
- `allowBackup=false`；系統「清除資料」後重新開 App → 重新 QR 登入 → 自動完整同步。
