# 接上 AI 用戶端（連接器）

App 有兩個 MCP 入口，都**只綁手機的 127.0.0.1**：

| 入口 | 位址 | 驗證 | 給誰 |
| --- | --- | --- | --- |
| 本機 MCP | 標準 stdio adapter → `http://127.0.0.1:47823/mcp/secure` | MCP 專用 key、每次 challenge／啟動 epoch、分向 AEAD | 同一支手機上的 stdio 用戶端；手機／Termux 相容性仍待裝置驗收 |
| 雲端連接器閘道（預設關） | `http://127.0.0.1:47825` → 經 HTTPS 通道變成 `https://<你的網址>/mcp`、`/sse` | OAuth 2.1（DCR + PKCE + 配對碼），或預設關閉的獨立 gateway token | ChatGPT、Claude、Grok、Gemini 的「自訂連接器」，以及可帶 header 的 CLI / API |

本機舊 `/mcp` 設定須遷移到 stdio；總控台 → 設定會顯示服務與舊入口的實際狀態，就緒後才能複製不含 key 的檔案式設定範本。`/mcp/secure` 是專用認證封裝，不是可直接貼給 HTTP MCP 用戶端的網址。見[遷移步驟與驗收限制](mcp-connection-migration-2026-11-27.md)。本頁 `/connector` 回應的 `mcp_url` 與 `oauth-smoke.ts` 屬於獨立雲端 gateway，並非本機 `info.mcp_url`，不可混用 key 或替換路徑。

雲端 AI 是從**它們自己的伺服器**連過來，連不到你手機的 127.0.0.1，所以一定要有公開的 HTTPS 網址（通道）。

## 舊入口驗證紀錄（2026-11-25，box 上跑 mock 假資料）

下表為舊入口的歷史互通證據，不是新 stdio adapter 的第三方用戶端或裝置驗收。App 新預設停用本機 HTTP Bearer；開發相容模式須明確設定 `LMA_MCP_LEGACY_HTTP=1`，它保留舊身分風險，不是新安全通道的 fallback。雲端 gateway 仍使用自己的 OAuth／gateway token。

| 用戶端 | 傳輸 | 驗證方式 | 結果 | 怎麼驗的 |
| --- | --- | --- | --- | --- |
| MCP Inspector CLI 2.16.0 | Streamable HTTP | Bearer | ✅ **實測連線**：列出 29 個工具、呼叫 `scan_scam_alerts`；`--strict` 0 個 schema 警告 | `npx @modelcontextprotocol/inspector --cli …/mcp --transport http` |
| MCP Inspector CLI 2.16.0 | SSE | Bearer | ✅ **實測連線**：呼叫 `search` | `--transport sse …/sse` |
| 官方 MCP SDK（TypeScript 1.32）OAuth 用戶端 | Streamable HTTP | OAuth 2.1：自動發現 → DCR → PKCE → 授權頁配對碼 → token | ✅ **實測完整流程**：只讀 token 18 個工具；勾「也允許送出」29 個；`search` → `fetch` | `node scripts/oauth-smoke.ts`（和 Claude Code / Inspector 用同一套 SDK 邏輯） |
| Claude Code 2.1.332 | HTTP + SSE | Bearer header | ✅ **實測**：`claude mcp list` → `✔ Connected`（HTTP、SSE 兩個） | `claude mcp add --transport http … --header` |
| Claude Code 2.1.332 | HTTP | OAuth | ⚠️ **部分**：`! Needs authentication`（正確發現要 OAuth）；要在互動介面 `/mcp` 用瀏覽器登入，box 上沒做 | |
| Gemini CLI 0.71.1 | HTTP + SSE | Bearer header | ✅ **實測**：`gemini mcp list` → `✓ Connected`（HTTP、SSE 兩個） | `gemini mcp add --transport http … -H` |
| Gemini CLI 0.71.1 | HTTP | OAuth | ⚠️ **部分**：`Disconnected`（沒 token）；要 `/mcp auth <name>` 開瀏覽器，box 上沒做 | |
| ChatGPT（Plugins → Add custom MCP server） | HTTP / SSE | OAuth（DCR）或無驗證 | 📄 **只照規格**：box 無法建立公開通道（見下），也沒有帳號 | 用 ChatGPT 的 redirect URI 模擬 DCR + 中繼資料（OK） |
| Claude.ai / Claude Desktop（自訂連接器） | HTTP / SSE | OAuth（DCR） | 📄 **只照規格** | 用 Claude 的 callback 模擬 DCR（OK） |
| Grok（grok.com/connectors → Custom） | HTTP / SSE | OAuth | 📄 **只照規格** | |
| xAI API Remote MCP（`tools: [{type:"mcp"}]`） | HTTP / SSE | `authorization` 參數 = Bearer | 📄 **只照規格**（同 Inspector 的 Bearer 路徑） | 沒呼叫真的 xAI API（規定不用真的 key） |
| Gemini 網頁版 / App（Connected Apps → Custom app） | HTTP | OAuth（DCR 或手動 client id/secret） | 📄 **只照規格**（另外只開放美國、18 歲以上、個人帳號） | 用 gemini.google.com redirect 模擬 DCR（OK） |
| Cloudflare quick tunnel | — | — | ❌ **box 上失敗**：拿到 `*.trycloudflare.com` 網址，但 box 網路擋了 Cloudflare edge（7844 QUIC / HTTP2 都 TLS EOF）。其他 SSH 通道（pinggy / localhost.run）也被 box 網路擋。 | 你自己的手機 / 電腦網路通常沒這限制 |

「模擬」= 在 box 上用 `Host: <假的公開網址>` 打閘道，確認中繼資料、`WWW-Authenticate`、DCR 都用公開的 https 網址，並接受各家 redirect URI；不是真的雲端用戶端連線。

## 各家需求整理（2026-11 查證）

| | 傳輸 | 驗證 | 公開 HTTPS | 其他 |
| --- | --- | --- | --- | --- |
| ChatGPT（網頁版；開發者模式開關 2026-10 已拿掉，改在 Plugins 加「custom MCP server」） | Streamable HTTP、SSE | OAuth（CIMD / DCR / 固定 client）、無驗證、混合；**不能輸入 API key** | 必須（或用 ChatGPT 自己的 Secure MCP Tunnel） | 需要 `iss`（RFC 9207）才會用固定 redirect `https://chatgpt.com/connector_platform_oauth_redirect`；工具可用 `readOnlyHint` / `securitySchemes`；`search` / `fetch` 只在公司知識 / deep research 需要 |
| Claude（claude.ai、Desktop、mobile、Code 共用） | Streamable HTTP、SSE | OAuth DCR / CIMD（預設）、無驗證；靜態 header 只開放部分組織（beta） | 必須，443 埠 | `resource` 要和輸入的 URL 一致；Claude Code / Desktop 本機設定可直接帶 header |
| Grok（grok.com/connectors；企業版要管理員先開） | Streamable HTTP、SSE | OAuth（完成登入） | 必須；拒絕 localhost / 私有 IP | xAI 文件：Cloudflare quick tunnel **不支援 SSE** → 用 `/mcp` |
| xAI API Remote MCP | Streamable HTTP、SSE | `authorization`（Bearer）、`headers` | 必須 | `allowed_tools` 建議只開只讀工具 |
| Gemini App（gemini.google.com → Connected Apps） | Streamable HTTP | OAuth 2.1 + PKCE；DCR 或手動 client id/secret | 必須 `https://` | 授權伺服器中繼資料必填 `authorization_endpoint`、`token_endpoint`、`response_types_supported: ["code"]`、`registration_endpoint` |
| Gemini CLI | `httpUrl`（Streamable HTTP）、`url`（SSE） | `headers` 或 OAuth 自動發現 + DCR | 不需要 | 資料夾要被信任才會載入 MCP；工具 schema 最好單一 `type` |

本專案的對應：

- `/.well-known/oauth-protected-resource[/mcp]`（RFC 9728）、`/.well-known/oauth-authorization-server`、`/.well-known/openid-configuration`（RFC 8414）
- 401 回 `WWW-Authenticate: Bearer resource_metadata="…"`
- `/oauth/register`（DCR，`none` / `client_secret_post` / `client_secret_basic`）、`/oauth/authorize`、`/oauth/token`、`/oauth/revoke`
- PKCE 只收 S256；`resource` 參數驗證（RFC 8707）；授權回應一律帶 `iss`（RFC 9207）
- scope：`line.read`（只讀工具）、`line.send`（送出 / 核准…，要在授權頁另外勾）
- 工具：`readOnlyHint` / `destructiveHint` annotations、`_meta.securitySchemes`、ChatGPT 相容 `search` / `fetch`
- 不支援 CIMD（沒宣告 `client_id_metadata_document_supported`，各家會改用 DCR）

## 開啟雲端連接器（App）

1. 設定 → **雲端連接器** → 開啟（要指紋 / 螢幕鎖）
2. 準備 HTTPS 通道，把 `127.0.0.1:47825` 轉出去（**只轉 47825**，不要轉 47823 / 47824）：
   - **Termux（同一支手機）**：`pkg install cloudflared` → `cloudflared tunnel --url http://127.0.0.1:47825`
   - 或 ngrok：`ngrok http 47825`（要帳號；SSE 也能用）
   - 或 Tailscale Funnel：`tailscale funnel 47825`
3. 把通道給的 `https://xxxx` 貼到「公開網址」→ 儲存（App 只接受這個 Host，其他網域一律 403）
4. 照下面各家步驟加連接器，網址填 `https://xxxx/mcp`
5. AI 用戶端會開一個授權頁 → 在 App 按「顯示」配對碼（要指紋）→ 輸入 → 授權。預設只讀；要讓 AI 送訊息才勾「也允許送出 / 核准」
6. 「已連線的 AI」可以單獨或全部撤銷，立即失效

quick tunnel 每次重開網址都會變：要在 App 更新公開網址，並在 AI 用戶端刪掉舊的連接器重加。

## 各家步驟

### ChatGPT（網頁版）

1. chatgpt.com → **Plugins** → `+` → **Add custom MCP server**
2. 名稱：`LINE`；Connection → Server URL：`https://xxxx/mcp`
3. Authentication：**OAuth**（不用填 client，會自動 DCR）
4. 勾「I understand and want to continue」→ Create → Install
5. 跳出授權頁 → 輸入配對碼 → 授權
6. 寫入動作（`send_message` 等）ChatGPT 會再問你一次；App 端照樣進確認佇列

### Claude（claude.ai / Claude Desktop）

1. Settings → **Connectors** → **Add custom connector**
2. URL：`https://xxxx/mcp`；登入方式選建議的 OAuth（自動註冊）
3. Connect → 授權頁輸入配對碼

### Claude Code

```
# 有 header（最簡單；App 要明確開「接受連接器專用 token」）
claude mcp add --transport http line https://xxxx/mcp --header "Authorization: Bearer <獨立 gateway token>"
# 或 OAuth：
claude mcp add --transport http line https://xxxx/mcp   # 然後在 claude 裡打 /mcp → Authenticate
# 同一支手機（Termux）直接連本機：
# 同手機新入口使用 stdio adapter，見 docs/local-mcp-channel.md；此處不使用 gateway token。
```

### Grok（grok.com）

1. grok.com/connectors → **New Connector** → **Custom**
2. 網址：`https://xxxx/mcp`（Cloudflare quick tunnel 不支援 SSE，用 `/mcp`）
3. 完成授權（配對碼）

### xAI API（Remote MCP tools）

```json
{"tools":[{"type":"mcp","server_url":"https://xxxx/mcp","server_label":"line",
  "authorization":"<MCP token>",
  "allowed_tools":["list_allowed_chats","get_messages","search_messages","scan_scam_alerts","search","fetch"]}]}
```

### Gemini（gemini.google.com）

1. Settings → **Connected Apps** →「Custom apps」→ **Add a custom app**
2. MCP server URL：`https://xxxx/mcp` → Next（支援 DCR，不用填 client）
3. 授權頁輸入配對碼。目前 Google 限美國、18 歲以上、個人帳號、英文介面

### Gemini CLI

`~/.gemini/settings.json`：

```json
{"mcpServers":{"line":{"httpUrl":"https://xxxx/mcp","headers":{"Authorization":"Bearer <獨立 gateway token>"}}}}
```

或不給 header，啟動後 `/mcp auth line` 走 OAuth。專案資料夾要先被信任（trust folder）MCP 才會載入。

## 安全提醒

- 把閘道放上網路 = 你的白名單聊天可以從網路讀到。OAuth 需要 App 裡的配對碼（10 分鐘、一次性、錯 5 次鎖 1 分鐘）；token 存雜湊、access 1 小時、refresh 30 天且每次輪換（重用就整串撤銷）
- 不需要時關掉閘道（立即 404）或停掉通道；用完撤銷 AI
- 只讀需求就不要勾「也允許送出」；就算勾了，送出仍要過白名單、AI 代聊名單、信任狀態（預設審核）、上限、緊急停止
- 獨立 gateway 靜態 token 功能預設關；開啟後只有持有該專用 token 的人可連，並受其到期／撤銷／scope 限制；不使用時保持關閉，不能用本機 MCP key 代替
- 一律拒絕：非設定網域的 Host、陌生 Origin、超過 256 KB 的 body；每分鐘 120 次請求、送出類 10 次

## 本機連線（同一支手機）

改用 [標準 stdio adapter 設定](local-mcp-channel.md)，先安裝專案及依賴，再填入腳本實際位置、該安裝的 `/mcp/secure` 位址與 MCP 專用 key 的受保護檔案。Review 使用 47833，正式配置 47823；不要把 Control key 或 gateway token 混用。

App 設定內的複製 JSON 是 stdio 範本，需修改本機腳本路徑。舊 HTTP Bearer JSON 已不是 App 預設支援入口，adapter 不會自動降級。key 顯示／複製仍需裝置驗證；輪換會使後續舊 key 請求失效，已開始的副作用不宣稱召回。本機寫入工具仍需在 App 明確啟用。

## 由連接器代聊（不需要 App 內 API key）

總控台 → 「誰來代聊？」選 **由連接器代聊**。外部 AI 用 `send_message` 回覆，App 端照樣把關：

1. 「AI 代聊總開關」要開
2. 聊天要同時在 **MCP 白名單** 和 **AI 代聊名單**
3. 信任狀態 **審核**（預設）→ 每則進確認佇列；**自動** → 延遲後直接送（上限 / 冷卻 / 緊急停止照樣有效）
4. 外部 AI 可以 `list_pending` / `edit_pending` / `reject_pending`；`approve_pending` 要在 App 開「允許 MCP 核准佇列」，`set_chat_trust` 升自動要開「允許 MCP 升級到自動」並傳 `confirm_auto=true`（降回審核永遠可以）
5. 每次呼叫都寫入稽核紀錄

## 反詐提醒

聊天 → AI 設定 → 「反詐即時提醒」（每群預設關，預設審核）。提醒文字可以自由寫（App 或 `compose_scam_warning`），範本只是參考：

```
⚠️ 這則疑似「{category}」詐騙：{tip}。@{admins} 請確認處理。
```

不能有連結、LINE ID，也不能抄詐騙原文（連續 10 字以上會被擋）；LINE 禁字自動替換。同一人同類型 30 分鐘冷卻、每群每天最多 10 則、信任成員不觸發。

雲端排程輪詢：`scan_scam_alerts(since)`，每次把回傳的 `next_since` 當下一次的 `since`。
