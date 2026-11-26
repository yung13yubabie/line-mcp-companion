# 本機 MCP 專用通道與 stdio adapter

基準：合併後 main `44a0e7452f89e8af569bf4213c606d5eca1968cf`。此改動處理自有應用的 MCP 通道，不存取真 LINE 資料，不使用沙箱繞過或第三方探測。它不是 TLS、Android Binder，也不是全面安全認證。

## 使用入口

在與 App 相同手機的 Node 24.22.3 相容環境中取得此專案，執行 `npm ci --ignore-scripts`。將 App「設定 → MCP 連線」經裝置驗證取得的 MCP 通道 key，儲存在用戶端自己控制、只有擁有者可讀的 regular file（Unix 0600 或 0400），不要把 Control key 給它。用戶端的標準 MCP 設定例如：

```json
{
  "mcpServers": {
    "line": {
      "command": "node",
      "args": ["/absolute/path/to/line-mcp-companion/scripts/mcp-stdio.ts", "http://127.0.0.1:47833/mcp/secure"],
      "env": {"LMA_MCP_CHANNEL_KEY_FILE": "/absolute/path/to/private-mcp-key"}
    }
  }
}
```

Review 使用 47833，正式配置為 47823；以該安裝的 App 顯示位址為準。腳本路徑需改成用戶端的實際路徑。App 複製的 JSON 使用相容的 `LMA_MCP_CHANNEL_KEY` 環境設定並含 key，仍需修改腳本路徑；該 JSON／剪貼簿是敏感設定，不要貼到公開對話。環境變數模式在啟動時刪除 JS process.env 的 key，但不宣稱能抹除 OS 啟動環境歷史；優先使用受保護檔案。檔案 mode／owner／symlink 檢查屬 Unix；Windows 檔案 ACL 需由使用者另行保護。

stdio 的 stdin/stdout 是標準 MCP JSON-RPC；應用端 `/mcp/secure` 是專用封裝，不能把一般 HTTP MCP 用戶端直接指向它。未測所有第三方用戶端與 Termux／Android 裝置，不將本機標準 SDK 測試當成這些平台已通過。

## 身分與資料保護

- 每個 RPC 先以新的 128-bit challenge 驗證 MCP key 的 possession proof，取得該 Node listener 啟動時隨機產生的 epoch。沒有傳輸 key。沒有快取「曾驗過所以之後信任」。
- key 以不同 HMAC-SHA256 domain 分別衍生 hello、request、response keys，與 Control 協定不互通。請求與回應均使用 AES-256-GCM，隨機 96-bit IV、128-bit tag，AAD 綁 version、方向、epoch、nonce、timestamp、固定 method/path 及回應 status。先驗證完整回應再釋出 MCP 資料。
- timestamp 接受窗與 bounded nonce ledger 防止同 epoch 重複請求；驗證密文成功後才 consume nonce，future skew 保留到完整接受窗終了。重啟產生新 epoch，舊 epoch 密文不再適用。容量滿拒絕。
- adapter 僅允許精確 `http://127.0.0.1:<port>/mcp/secure`，不接受 credentials/query/fragment，直接使用 node:http，不跟 redirect、不使用環境 proxy；每個 RPC 的 hello 與封裝交換共用 60 秒 deadline。請求上限 256 KiB，回應上限 24 MiB；stdio buffer 256 KiB，同時最多 8 個交換。
- `/mcp/secure` 在認證、schema 成功後才計入一般 request／send bucket，保留原送出限額。hello 另有上限，認證失敗沿用內容無關的彙總遙測。這些限額不構成同機資源耗盡的完整防禦。
- 每個 request 重新套用 `mcp_allow_write`（預設關）、白名單及既有工具政策。MCP key 不授予 Control 路由；雲端 gateway 仍走自己的 OAuth／專用 token 與 scope。已開始操作或已在途的外送不宣稱召回。

## 舊入口與剩餘限制

App 的 `src/main.ts` 預設停用原 `/mcp` HTTP Bearer。只有明確設定 `LMA_MCP_LEGACY_HTTP=1` 的開發相容環境才保留；它有原來的伺服器身分風險，不是 adapter 的降級路徑。`startMcpHttp` 低階 API 為既有合成開發 fixtures 保留 legacy 預設相容；正式應用 main 明確傳 false，其他呼叫者應同樣明確禁用。Review UI 不再複製舊 Bearer 設定。

這是共享 PSK 的受保護通道：持有同一 MCP key 的已授權用戶端處在同一信任範圍，不能藉它區分各 client 或作硬體裝置證明。純 HTTP MCP／雲端 tunnel 的內側、不同應用的匯出設定、每 client scoped credential、真機／背景／重啟驗收仍需後續設計與驗證。不能因此宣稱所有 G01 路徑已解除；native runtime、正式簽章與裝置門檻也仍為 NO-GO。

## 實際驗證範圍

`test/mcp-channel.test.ts` 使用合成 key、in-memory SQLite、fake sync、自有 loopback HTTP 和真正 SDK StdioClientTransport，驗 codec context、標準入口初始化／工具呼叫、預設只讀／啟用／降權與 legacy-disabled。沒有占埠、擷取秘密、漏洞利用、真 LINE 登入或雲端模型呼叫。獨立 reviewer 另設驗證，結果與固定提交放在本輪報告；編譯與單元測試不等於裝置驗收。
