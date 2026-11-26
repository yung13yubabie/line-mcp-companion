# LINE MCP Companion

在 Android 手機上以「次要裝置」登入 LINE，把你**勾選的聊天**存在手機本機，並在 `127.0.0.1` 提供 MCP，讓 AI 幫你讀訊息、擬回覆、抓詐騙。預設不標已讀，AI 功能預設全關。

> ⚠️ **非官方協定，帳號可能被限制或停用**
> 本 App 使用非官方的 LINE 通訊協定（[LINEJS](https://github.com/evex-dev/linejs)），不是 LINE 官方功能。LINE 可能因此限制或停用你的帳號。**建議用次要帳號或測試帳號。**
> 本專案與 LY Corporation 沒有任何關係，也未獲授權或背書。「LINE」是 LY Corporation 的商標。

## 功能

- **本機同步**：只同步勾選的聊天，SQLite + 全文搜尋（中文可用），不標已讀
- **本機 MCP**：標準 stdio adapter 經 MCP 專用認證加密通道連 `127.0.0.1:47823/mcp/secure`；預設只讀，App 預設停用舊 HTTP Bearer。安裝／測試範圍見 [本機安全通道](docs/local-mcp-channel.md)。
- **代聊二選一**（總控台切換）
  - **由連接器代聊**：外部 AI（Claude、ChatGPT…）經 MCP 的 `send_message` 回覆，App 不需要 API key
  - **App 內建 AI**：OpenAI 相容端點＋備援模型鏈；涉及雲端的整條模型鏈預設先去識別化，涵蓋社群草稿與第二輪改寫。規則可能漏掉個資，開啟雲端模型或 MCP 連接器仍會把允許的內容提供給對應服務。
- **雲端連接器**（預設關）：ChatGPT / Claude / Grok / Gemini 的自訂 MCP 連接器 — OAuth 2.1（DCR + PKCE + App 內配對碼）、Streamable HTTP + 舊版 SSE、可選 Cloudflare 通道，見 [docs/connectors.md](docs/connectors.md)
- **信任狀態**：每個聊天的 AI 回覆、反詐提醒各自「審核（預設）→ 自動」，一鍵降回；緊急停止全部降回
- **安全預設**：AI 代聊有自己的白名單（要同時在 MCP 白名單）、確認佇列（可改字 / 貼圖再送）、頻率 / 每日上限、活躍時段、緊急停止、稽核紀錄、提示注入防護；被隱藏 / 收回的訊息不回、不當脈絡
- **紀錄**：反詐與 AI 代聊紀錄（敏感欄位加密、可篩選、匯出 CSV、保留天數、清除）。全文索引、附件與部分中繼資料仍存於 App 私有空間，並非全庫或全檔加密。
- **長按訊息回覆這則**：引用回覆，可請 AI 擬一句，或回你用過的貼圖
- **去 AI 味**：送出前把太像 AI 的句子改自然（Lieflat 規則，每個聊天可關）
- **反詐雷達**：本機規則 + 可擴充範例庫，不需要 AI；可選擇在群組即時引用回覆提醒並 @ 管理員（每群預設關）
- **日報**：AI 助理經 MCP 寫回、或 App 內建 AI 產生；報紙版面、選日期、點來源跳回原訊息；可手動或每天定時貼到群組（網址會拿掉）
- **安全讀取連結**（每個聊天預設關）：先過反詐規則、詐騙網域、短網址展開、私有 IP 檢查才抓標題 / 文字，不執行 JS、不帶 cookie
- **社群貼文草稿**：把聊天內容整理成你口吻的 FB / IG / Threads / X 草稿（只草稿，不發文）

## MCP 工具

| 類別 | 工具 |
| --- | --- |
| 讀取 | `list_allowed_chats` `get_messages` `search_messages` `get_attachment` `download_media` `get_unread_summary` `get_sync_status` `trigger_sync` |
| 送出 | `send_message`（文字 / 貼圖 / 引用回覆）`generate_and_send_image` `get_ai_suggestion` `get_outbox_item` `list_stickers` |
| 審核 | `list_pending` `edit_pending` `approve_pending`（要在 App 開「允許 MCP 核准」）`reject_pending` `get_chat_trust` `set_chat_trust`（升自動要在 App 開「允許 MCP 升級」）`get_ai_log` |
| 反詐 | `scan_scam_alerts(since, chat_id?)` `list_scam_samples` `add_scam_sample` `compose_scam_warning` `mark_scam_false_positive` `trust_scam_member` `get_scam_log` |
| ChatGPT 相容 | `search` `fetch`（只讀） |
| 日報 | `save_digest` `list_digests` `get_digest` `delete_digest` `post_digest`（貼到群組，走確認佇列 / 信任狀態） |
| 連結 | `read_link`（每個聊天預設關；反詐 / 短網址展開 / SSRF 防護，被擋回 `blocked: 原因`） |

所有工具都只看得到白名單內的聊天；送出類預設進確認佇列，要你在 App 按「送出」。連接器設定見 [docs/connectors.md](docs/connectors.md)。

## 安裝（側載）

### 0.3.1 修復驗證版

[Android review APK workflow](https://github.com/yung13yubabie/line-mcp-companion/actions/workflows/android-review.yml) 會對 PR／修復分支建立兩種 APK；在成功執行的 Artifacts 下載 `line-mcp-companion-review-<commit>`。

| 項目 | Review APK |
| --- | --- |
| 版本／套件 | `0.3.1-review`／`tw.linemcp.app.review` |
| 適用 ABI | `arm64-v8a` 真機；`x86_64` 相容模擬器 |
| 簽章 | 測試簽章；每次乾淨 CI 可能不同，核對同份 artifact 的簽章報告 |
| 本機連接埠 | MCP `47833`、control `47834`、connector `47835` |
| 資料 | 與既有正式 App 分開；不會覆蓋或遷移舊資料 |
| Mock／debug | release bundle 已移除 Mock；`debuggable=false` |

這是尚未完成正式發布驗收的修復驗證版。使用測試帳號與非敏感資料；尚未完成真機 LINE 登入、背景生命週期與雲端連接器端到端驗證。它使用非正式簽章，不能當成舊版 App 的覆蓋更新。

目前固定的原生套件包含已停止支援的 OpenSSL 3.6.5。`assembleRelease`／`bundleRelease` 會拒絕此 runtime，須先更換為受支援且完成覆驗的版本，再使用原正式簽章金鑰。詳見 [安全修復與發布限制](docs/security-update-2026-11-25.md) 及 [原生建置說明](docs/android-build.md)。

### 正式版簽章核對

1. 下載對應 ABI 的 APK，核對同次發布提供的 SHA-256。
2. 檢查簽章：

   ```
   apksigner verify --verbose --print-certs <release.apk>
   ```

   既有專案記錄的正式簽章憑證 SHA-256 為下列值。本次未取得原 keystore，沒有產生使用此憑證的正式更新 APK；Review APK 不使用它。

   ```
   75:E7:2F:E9:BC:01:B9:E8:9F:78:A9:42:53:12:58:1C:1D:4D:AA:92:E9:CB:E2:14:63:F8:76:18:97:EC:A9:0A
   ```

3. 開啟 App → 看完風險說明 → 產生 QR → 用另一台裝置顯示並以手機 LINE 掃描 → 輸入 PIN
4. 在「聊天」勾選要開放的聊天；在「設定」用指紋 / 螢幕鎖確認後複製 MCP 設定

## 開發

需要 Node `24.22.3`、Bun `1.4.5`、JDK 17 以上（本輪使用 Temurin 21）、Android SDK 35／Build Tools 35.0.0。原生套件準備目前支援 Linux x86_64，另需 Python 3.12、GnuPG、`dpkg-deb` 與 `readelf`。

```
npm ci --ignore-scripts --no-audit --no-fund
npm test                       # 單元 / 端到端測試（全部假資料，不連 LINE、不呼叫 AI）
npm run typecheck
LMA_PASSPHRASE='至少 12 個字的密語' npm start   # 桌面執行；沒設 token 會自動產生並只印一次
npm run native:android         # 驗證簽署索引、下載固定套件、重包並驗證 native hashes
npm run android:debug          # debug APK（含 Mock 模式）
npm run android:review         # 獨立 package、測試簽章、移除 Mock 的 Review APK
npm run android:release        # 需受支援且核准的 runtime，以及相同正式 keystore
```

- 桌面模式必須設 `LMA_PASSPHRASE`（加密 LINE token / E2EE 金鑰），否則拒絕啟動
- release 簽章：keystore 放在 repo 外（預設 `../keys/release.jks` + `../keys/keystore.pass`，兩者限擁有者可讀）；可用 `LMA_KEYSTORE`／`LMA_KEYSTORE_PASS_FILE` 覆寫。缺檔、權限過寬、alias 或憑證指紋不符，建置會失敗。
- Mock 模式（只在 debug 版）：設定 → 開發者 → Mock 模式，完全離線的假資料，見 [docs/mock-mode.md](docs/mock-mode.md)

安全設計與威脅模型：[docs/SECURITY-REVIEW-BRIEF.md](docs/SECURITY-REVIEW-BRIEF.md)

0.3.1 安全修復與未解風險：[docs/security-update-2026-11-25.md](docs/security-update-2026-11-25.md)。後續獨立審查依 [資安審查規程](docs/security-review-process.md) 執行；自動測試通過不能替代獨立覆核或真機驗收。

## 授權

Apache-2.0（見 [LICENSE](LICENSE)、[NOTICE](NOTICE)），**`src/style/lieflat/` 除外**：該目錄改作自 Lieflat Less AI Tone，維持 CC BY-NC 4.0（僅限非商業使用）。第三方授權見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
