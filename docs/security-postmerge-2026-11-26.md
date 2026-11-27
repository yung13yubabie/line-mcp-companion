# 合併後防禦改善與 main APK 里程碑

基準與實際 default branch：main `44a0e7452f89e8af569bf4213c606d5eca1968cf`。本輪從獨立 checkout 開發，MCP 與 native 分線，另由未修改 production code 的獨立 reviewer 檢查。沒有改 workflow 權限、合併後續 PR、建立 tag 或任何 Release；沒有真 LINE 資料、登入、第三方主動探測、漏洞利用或 Android 沙箱繞過。

## 合併後 main 的既有建置已驗證

沒有重複觸發；[Security checks 45791781817](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45791781817) 與 [Android review APK 45791781833](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45791781833) 都已成功。以下是合併後 main 的產物，**不是本輪尚待審查的新通道版本**。

[下載 main Review artifact 15103720814](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45791781833/artifacts/15103720814)，ZIP SHA-256 `7b2194d8df708b6b5ec51e3367638a6923428ea60b228d626c5f12f3b361b05e`，73,608,408 bytes。下載後 ZIP digest 與 API 一致，source-commit.txt 精確為上述 main SHA。

| ABI | APK bytes | APK SHA-256 |
| --- | ---: | --- |
| arm64-v8a | 39,921,320 | `ab004a7185ac0b931e1dae8aefdcf1ce98677fed8421bcadba54e52aa806ffdd` |
| x86_64 | 39,159,771 | `d9bb1221119053de0fe85109c750422062af3f4b010d59a5c3c13bc0768300d7` |

兩 APK 以官方 Google Build Tools 35 的 apksigner 重新真驗簽、aapt 重新 dump badging，輸出與同次 artifact 報告一致。皆為 `tw.linemcp.app.review`、`0.3.1-review`、versionCode 5、minSdk 29／targetSdk 35。新測試憑證 SHA-256 `a47e87b75b70bf27b7812c739316ebd4540c1634eb9af67505672d9c1b724ff4`；上一份 d4c6ca47 Review 為 `cf726294e6a3e57e3b3be53e1cd78ba4eb3f3b7532af165492b927372088e3e7`，不同，不能直接覆蓋舊 Review。正式 App 套件與簽章也不同，不能覆蓋正式安裝。這是封裝／簽章判斷，未在裝置執行安裝或升級。

## 本輪可驗收改善

### MCP 專用通道

新增標準 MCP stdio adapter，透過自有 `/mcp/secure` 通道連線。每 RPC 用新的 challenge 驗證持有 MCP PSK 的服務端，並取得本次啟動 epoch；請求與回應均以分向 domain key／隨機 IV 的 AES-256-GCM 認證加密，AAD 綁 version、方向、epoch、nonce、timestamp、固定 method/path 及 status。新 epoch 不接受舊 epoch 密文。body／deadline／nonce cap 與既有 request/send 限額保持獨立，認證後才扣正常請求額度。非同步 body 收集後及結果釋出前重查 MCP key 是否輪換。

App main 預設禁用舊 HTTP Bearer；UI 改複製 stdio 設定，提供真實的安裝前提，沒有 plaintext fallback。每 request 仍套用預設只讀、白名單與工具政策。通道 key 不提供 Control 權限；雲端 OAuth gateway 不由此取代。詳見 [協定、設定及限制](local-mcp-channel.md)。

這驗證的是對稱 PSK possession，不是 server 獨占公鑰或硬體證明；同 key 的 clients 共享信任範圍。低階 API／明確開啟的 legacy 相容路徑仍有舊風險，不宣稱所有 G01 路徑已解除，也不宣稱是 TLS。已開始的副作用與外送不宣稱可以召回。

### Native 來源與維護政策

開發線重新核對官方配方、公告與 ABI 相容條件；未找到已完成完整驗證的可替換 Android binary，因而**不替換 runtime**。新增獨立於 approval 布林的 lifecycle、patch floor、雙 ABI 精確版本及 signed snapshot 時效 gate；production CLI 重新驗 GPG→signed index→package metadata，並將 snapshot 時刻綁到簽署 Date。不能只把 ready 改 true／清空 blockers 便批准 EOL 元件。詳見 [官方依據、原始失敗與解除門檻](native-runtime-support-2026-11-26.md)。

## 測試與審查

主要回歸與新增測試使用合成資料、in-memory／暫存 SQLite、自有 loopback fixtures。`test/mcp-channel.test.ts` 以真 SDK StdioClientTransport 呼叫真正 adapter；獨立 reviewer 另驗真 main 子程序、無已存 LINE token、mock=false、全部動態 ports、合成 stdin secrets，再經 stdio 呼叫只讀同步狀態。沒有登入或向 LINE／模型發請求。

原始輸出保留在 `review-work/postmerge-20261126/`、`review-work/native-policy-20261126/` 與獨立報告目錄。已通過的本機清單：Node 158/158、TypeScript、native 43/43；獨立新 MCP 7/7、native policy 7/7，原獨立回歸 6/6 保留。Android release JavaScript bundle 與 no-mock gate 通過。新 PR 的 Android Kotlin/APK CI 以實際 workflow 結果為準，不把舊 main artifact 當新 patch 的 APK。

## 未完成的門檻

受支援且相容的原生 runtime、跨用戶端與裝置驗收、正式簽章、legacy／gateway 內側的身分設計仍未完成。沒有真機／模擬器啟動、背景、舊版升級或真實供應商驗收；合成與建置不算真機成功。**正式發布仍 NO-GO**，本輪只提出供審查的防禦 PR。
