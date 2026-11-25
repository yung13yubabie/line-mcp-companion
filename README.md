# LINE MCP Companion

在 Android 手機上以「次要裝置」登入 LINE，把你**勾選的聊天**存在手機本機，並在 `127.0.0.1` 提供 MCP，讓 AI 幫你讀訊息、擬回覆、抓詐騙。預設不標已讀，AI 功能預設全關。

> ⚠️ **非官方協定，帳號可能被限制或停用**
> 本 App 使用非官方的 LINE 通訊協定（[LINEJS](https://github.com/evex-dev/linejs)），不是 LINE 官方功能。LINE 可能因此限制或停用你的帳號。**建議用次要帳號或測試帳號。**
> 本專案與 LY Corporation 沒有任何關係，也未獲授權或背書。「LINE」是 LY Corporation 的商標。

## 功能

- **本機同步**：只同步勾選的聊天，SQLite + 全文搜尋（中文可用），不標已讀
- **MCP（Streamable HTTP）**：`127.0.0.1:47823/mcp`，Bearer token，只綁本機
- **代聊二選一**（總控台切換）
  - **由連接器代聊**：外部 AI（Claude、ChatGPT…）經 MCP 的 `send_message` 回覆，App 不需要 API key
  - **App 內建 AI**：填自己的 OpenAI / Grok / Claude（OpenAI 相容）API key，App 自己擬建議
- **安全預設**：AI 代聊有自己的白名單（要同時在 MCP 白名單）、發送前確認（預設開）、頻率 / 每日上限、活躍時段、緊急停止、稽核紀錄、提示注入防護
- **長按訊息回覆這則**：引用回覆，可請 AI 擬一句，或回你用過的貼圖
- **去 AI 味**：送出前把太像 AI 的句子改自然（Lieflat 規則，每個聊天可關）
- **反詐雷達**：本機規則 + 可擴充範例庫，不需要 AI；可選擇在群組即時引用回覆提醒並 @ 管理員（每群預設關）
- **社群貼文草稿**：把聊天內容整理成你口吻的 FB / IG / Threads / X 草稿（只草稿，不發文）

## MCP 工具

| 類別 | 工具 |
| --- | --- |
| 讀取 | `list_allowed_chats` `get_messages` `search_messages` `get_attachment` `download_media` `get_unread_summary` `get_sync_status` `trigger_sync` |
| 送出 | `send_message`（文字 / 貼圖 / 引用回覆）`generate_and_send_image` `get_ai_suggestion` `get_outbox_item` `list_stickers` |
| 反詐 | `scan_scam_alerts(since, chat_id?)` `list_scam_samples` `add_scam_sample` |

所有工具都只看得到白名單內的聊天；送出類預設進確認佇列，要你在 App 按「送出」。連接器設定見 [docs/connectors.md](docs/connectors.md)。

## 安裝（側載）

1. 下載對應的 APK：真機用 `arm64-v8a`，模擬器用 `x86_64`
2. 確認簽章（release 版）：

   ```
   apksigner verify --print-certs line-mcp-app-0.2.1-arm64-v8a-release.apk
   ```

   憑證 SHA-256 必須是：

   ```
   75:E7:2F:E9:BC:01:B9:E8:9F:78:A9:42:53:12:58:1C:1D:4D:AA:92:E9:CB:E2:14:63:F8:76:18:97:EC:A9:0A
   ```

3. 開啟 App → 看完風險說明 → 產生 QR → 用另一台裝置顯示並以手機 LINE 掃描 → 輸入 PIN
4. 在「聊天」勾選要開放的聊天；在「設定」用指紋 / 螢幕鎖確認後複製 MCP 設定

## 開發

需要 Node 24、Bun（打包）、Android SDK。

```
npm install
npm test                       # 單元 / 端到端測試（全部假資料，不連 LINE、不呼叫 AI）
npm run typecheck
LMA_PASSPHRASE='至少 12 個字的密語' npm start   # 桌面執行；沒設 token 會自動產生並只印一次
npm run android:debug          # debug APK（含 Mock 模式）
npm run android:release        # release APK（移除 Mock，需 release keystore）
```

- 桌面模式必須設 `LMA_PASSPHRASE`（加密 LINE token / E2EE 金鑰），否則拒絕啟動
- release 簽章：keystore 放在 repo 外（預設 `../keys/release.jks` + 權限 0600 的 `../keys/keystore.pass`，可用 `LMA_KEYSTORE` / `LMA_KEYSTORE_PASS_FILE` 覆寫）；找不到就不簽，不會退回 debug 金鑰
- Mock 模式（只在 debug 版）：設定 → 開發者 → Mock 模式，完全離線的假資料，見 [docs/mock-mode.md](docs/mock-mode.md)

安全設計與威脅模型：[docs/SECURITY-REVIEW-BRIEF.md](docs/SECURITY-REVIEW-BRIEF.md)

## 授權

Apache-2.0（見 [LICENSE](LICENSE)、[NOTICE](NOTICE)），**`src/style/lieflat/` 除外**：該目錄改作自 Lieflat Less AI Tone，維持 CC BY-NC 4.0（僅限非商業使用）。第三方授權見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
