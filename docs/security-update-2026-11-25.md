# 0.3.1 資安修復、覆驗與發布紀錄

本輪基準為 `99e3ebb88de4d57499d29eea27bdbee266dbe69a`。修補提交、遠端 checks 與 APK 的實際來源，以本 PR head、工作流程紀錄及產物 SHA-256 為準。既有基準 checkout 保留供對照，未使用真實 LINE 憑證或 AI API key 測試。

**交付目標是安全修補 PR 與 0.3.1-review APK。正式安全發布尚未通過。** Review 使用獨立套件名稱與本機連接埠，可以保留原 App；沒有原正式 keystore，不能將它當成既有 App 的覆蓋更新。原生 OpenSSL 3.6 已停止支援，正常 release 建置被 gate 阻擋，詳見下方剩餘風險。

## 分工與證據要求

沿用八個職責：Security Architect／Blue Team、Red Team／AI Security、DevSecOps／Threat Intelligence 分組執行，Purple Team 整合修前與修後證據，Independent Auditor 以另外的代理核對原始程式碼、自行設計測試並重跑。獨立審計員未修改 production code；審計發現由修補代理處理後再交回。

完整程序與分級規則見 [獨立資安審查規程](security-review-process.md)。本輪新增 CI、固定輸入與建置拒絕條件，尚未修改遠端主分支保護或管理規則。掃描零發現、單元測試通過及「編譯成功」各自只證明相應的檢查結果。

## 漏洞與修補對照

以下 ID 對應先前審查台帳。嚴重度是具備所述前提時的專案風險，不是將上游 CVSS 直接套用。`已修補` 表示程式碼與所列情境已處理，不等於產品所有路徑或正式部署已安全。

| ID／原風險 | 原始問題、影響與位置 | 本輪修補與回歸入口 |
| --- | --- | --- |
| F01／High | 社群草稿、local→cloud fallback、第二輪改寫可能繞過去識別化，傳送原始人名或其他可識別內容。`src/ai/service.ts` | 以整條模型鏈判斷雲端需求、各角色文字與 persona 使用同一去識別流程，待全部模型步驟結束才還原。`privacy-review.test.ts`、`revoked-read.test.ts`。規則式去識別仍可能漏掉個資。 |
| F02／High | Outbox 取出的排程快照可能在撤銷、降權或第一段送出後繼續使用；部分發送失敗重排可能重複送出。`src/ai/outbox.ts` | 每個 sender 呼叫與 mention fallback 前重查當前項目與權限，記錄部分送達與撤銷競態，發送統計採 `sent_at`。`outbox-revocation.test.ts`。已交給 LINE 的請求不能追回。 |
| F03／Medium | 搜尋、附件、反詐 alert 與可追溯 log snapshot 仍可能傳回被隱藏／收回的來源。`src/storage/db.ts`、`src/media/cache.ts`、`src/scam/detector.ts`、`src/mcp/tools.ts` | SQL／cache／工具出口重查來源狀態；log 只排除能連回已隱藏來源的項目。`privacy-review.test.ts`、`revoked-read.test.ts`。未宣稱刪除所有已儲存衍生內容。 |
| F04／Medium | 排程日報產生未完整要求 AI 總開關與個別聊天同意。`src/ai/service.ts` | 產生前、非同步等待後與模型步驟間重查同意；正例明確設定 `ai_allowed`。`privacy-review.test.ts`、續傳回歸。 |
| F05／Medium | 媒體、連結、建議與後續模型步驟在等待期間撤銷後仍可能回傳或開始新外送。`src/mcp/tools.ts`、`src/ai/service.ts`、`src/ai/provider.ts` | 來源 ID／hidden、白名單、同意及相關 `link_read` 於新操作前與結果釋出前重查。per-call guard 傳入 fallback 與 HTTP 400 相容重試；日報、社群改寫、圖片與選用反詐判讀使用各自的政策。詳見下節獨立反例。 |
| F06／Medium | `.zip`／`.mov`／`.md` 被當副檔名豁免，IPv6 URL 未完整觸發聯絡資訊確認。`src/ai/content-scan.ts` | 移除不適用的 TLD 豁免、補 IPv6，確認佇列保留人工決策。`privacy-review.test.ts`。部分真檔名可能多要求一次確認。 |
| F07／Medium | OAuth consent 的 send checkbox 能超過原請求 scope。需有效配對碼與 nonce，並非未認證越權。`src/mcp/oauth.ts` | 發出的 `line.send` 同時受原請求與使用者同意約束。`security-boundaries.test.ts`。 |
| F08／Medium | SSE session 曾以可自行命名的 client name 綁定，重名授權 client 可碰撞。`src/mcp/gateway.ts` | 改用經驗證的 OAuth client ID；靜態 token 以其世代身分隔離。`security-boundaries.test.ts`。未宣稱能直接讀出另一條 stream。 |
| F09／Medium | SDK 已升級，但未開啟工具輸入複雜度選項。`src/mcp/server.ts` | 設定最多 4096 elements，先於 schema 驗證拒絕過大結構，保留正常呼叫正例。`security-boundaries.test.ts`。沒有執行 OOM 或壓力攻擊。 |
| F10／Medium | 桌面既有可穿越目錄搭配 umask 可能產生 0644 WAL／SHM。`src/storage/db.ts` | 建立／重開資料檔及 sidecar 時限制 0600。`security-boundaries.test.ts`。Android 私有目錄的權限情境另外區分。 |
| F11／Low | Mock release gate 對缺檔或 APK 缺 bundle 曾回傳成功。`scripts/purge-mock-check.sh` | 缺檔、空檔、解壓／讀取失敗均拒絕；實際 bundle 與 APK 都需通過。`release-gate.test.ts`。 |
| F12／High（建置主機） | Gradle 8.11.1 在已公布的 daemon／registry GHSA 受影響範圍。`android/gradle/wrapper/` | 升到 8.14.8，核對官方 wrapper 與 distribution SHA-256，實際編譯 Android。Maven verification metadata 另外固定本輪下載雜湊。 |
| F13／Medium（條件式） | 圖片 API 回傳的 HTTPS URL 沒有私有位址／DNS pinning 控制。`src/ai/provider.ts` | 圖片下載與 API 認證 fetch 分離；HTTPS 443、完整解析結果檢查、固定 IP、TLS 原 hostname 驗證、不跟 redirect、不帶 key/cookie、總 deadline、20 MiB 上限及容器檢查。`image-download.test.ts`。 |
| F14／Medium | 未認證 MCP 請求可逐筆寫入共用 audit，淘汰重要操作紀錄。`src/mcp/server.ts`、`src/ai/audit.ts` | 固定 reason 計數、失敗回應額度、定時聚合，安全事件使用獨立 500 筆 ring。`architecture-hardening.test.ts`。這降低寫入與歷史淘汰風險，並非任意本機 DoS 的完整防禦。 |
| F15／Low | Control 認證失敗缺少遙測，Keepalive 把任意 HTTP 回應當健康。`src/control/server.ts`、Android `ControlClient.kt`／`Keepalive.kt` | 增加不記 token/body/nonce 的安全事件與受驗證 `/health`；Keepalive 核對 HMAC、完整 body 及健康結果。`architecture-hardening.test.ts`，另以 Android 編譯確認 Kotlin 配套。 |

## 獨立覆核補出的撤銷情境

審計員針對修補版另寫純 mock 反例，確認日報在 `links.read()` 等待期間撤銷來源或關閉連結讀取，仍會啟動下一次 link／模型呼叫；社群草稿在第一輪模型結束後撤銷同意或隱藏來源，仍會啟動 Lieflat 改寫。修前證據保留 4 個安全期望失敗與 2 個正常正例通過，均為合成內容與 fake 呼叫，沒有真模型外洩測試。

同樣檢查 `FallbackChain.chat()` 與 HTTP 400 token 欄位相容重試：外層 service 只包住整條 chain，無法自行阻止其內部下一次請求。因此修補使用每次呼叫的授權檢查，於任何新 attempt 前執行，且授權撤銷不被當成可重試的供應商錯誤。反詐判讀沿用 `scam_ai`、反詐範圍與來源狀態，沒有將 AI 代聊同意混入其政策。

圖片生成在 API 回應後若要下載 URL，也需重查授權；回傳後在本機寫入圖片檔之前再檢查。這些限制涵蓋尚未開始的操作與結果釋出，不宣稱能從供應商或 LINE 撤回已經在途的資料。

## 同步補強

- Control 的 CSV、貼圖與 outbox 圖片改為對完整 bytes 簽章，移除僅簽狀態而未綁 body 的降級；Android 限制回應大小並拒絕 redirect。
- Nonce 保存到簽署 timestamp 的接受期限結束，含 future clock skew，避免提早移除仍有效的 nonce；容量滿時拒絕。
- Android 秘密 get-or-create 同步化，持久化失敗會回報失敗。
- 連結讀取與圖片使用同一保守 public-address policy；總 deadline 涵蓋 DNS、轉址與串流，保存 chunk 前先限制大小。
- 新增安全檢查與 Review APK workflows，使用唯讀 repository 權限、固定 Action commit、關閉 checkout 憑證保留、`npm ci --ignore-scripts`、明確 Bash pipefail；沒有在 PR job 注入正式簽章或服務憑證。
- Node native packages 以簽署 APT snapshot 固定來源，repack 工具／輸出與 94 份授權文字都有 SHA-256，兩個 ABI 各 10 個 Node ELF，另各有 1 個來自固定 Google Maven AAR 的 AndroidX ELF。每個 APK 精確要求這 11 個檔案；檢查 16 KB ELF 對齊，但尚未在相應裝置啟動驗證。
- 正式簽章缺失、檔案權限過寬、alias／fingerprint 不符均拒絕；Review 有獨立 application ID 與 ports，且 `debuggable=false`、不含 Mock。

## 回歸與產物驗證

以下測試已由未修改 production code 的獨立審計員在凍結輸入上重跑。APK 的逐檔驗證紀錄另隨產物交付；CI 結果以實際工作流程執行為準。

| 檢查 | 實際結果 | 範圍與限制 |
| --- | --- | --- |
| 全套 Node 測試 | 155／155，0 failed／skipped | 既有功能與新增安全回歸；使用合成資料 |
| TypeScript | exit 0 | `npm run typecheck` |
| npm audit | 當次回報 0 個已知漏洞 | 僅 npm 相依公告；不涵蓋 Android、native 或自有邏輯 |
| 原樣保留的獨立額外測試 | 5／5 | 前輪審計自寫案例，沒有改成迎合實作 |
| 新增獨立撤銷測試 | 10／10 | 日報／社群6、fallback／retry4；修前失敗與正例紀錄保留 |
| Native gate 回歸 | 30／30 | 包含來源簽章、篡改、ABI、16 KB、授權檔、APK與發布阻擋 |
| 受控 loopback TLS | 6 子項全過（TAP含父項為7） | 真正本機TLS；沒有連真供應商或私網服務 |
| 基準 image／reader 缺陷觀測 | 3 項重現 | 只表示基準不安全行為被觀察到，不算安全測試通過 |
| Native 獨立重打包 | 20 Node ELF＋94 notices 逐byte一致；另驗2個Maven ELF | 16個已下載.deb逐個hash／metadata核對；不是從source重新編譯 |
| Maven下載hash基準 | 初次獨立核對384 components／685 artifacts，0缺失／不符；另補2份已核實的JUnit module，目前共687 artifacts | 以官方TLS下載建立checksum baseline；`verify-signatures=false`，不是JVM漏洞掃描 |
| Android clean build | `--offline --dependency-verification strict clean :app:assembleReview` 成功 | Gradle 8.14.8、JDK21、SDK35；未作裝置啟動驗收 |

初次凍結清單含133個非Markdown來源、測試與建置輸入，其manifest SHA-256為 `2751776f6b0da34306dc5d0354f0bafc583788306f69c22dbf3b08d3835fea09`，獨立核對無不符。補齊下述2份JUnit module之後，最新manifest SHA-256為 `92ba4de129705d58e11d9f9d374a67452417bd8ab938cf361e146d3a86b5ba9a`，唯變動輸入為 `android/gradle/verification-metadata.xml`。這些值識別測試與覆驗快照，不能當安全覆蓋率。

APK 下載必須搭配同次產物的 `SHA256SUMS`、`*-signature.txt`、`*-package.txt`、`native-runtime.lock.json` 與來源 commit。Review 的測試簽章可能隨乾淨建置環境改變，不能使用正式版既有 fingerprint 驗它，也不能將不同建置的 APK 混稱為同一產物。

來源綁定以同次工作流程的 `source-commit.txt`、Git tree 與產物SHA-256為準；PR工作流程可能使用GitHub產生的merge commit，push工作流程使用分支head，兩者必須分開記錄。本機AGP的 `META-INF/version-control-info.textproto` 實測只有 `NO_SUPPORTED_VCS_FOUND`，沒有revision；不將它當成已成功嵌入來源commit的證據。

首次GitHub Android工作流程在strict依賴驗證階段拒絕 `org.junit:junit-bom:5.9.2` 與 `5.9.3` 的 `.module`，原因是本機建立的清單漏列這兩份metadata。已從Maven Central兩個官方端點取得相同bytes，核對公開SHA-256／SHA-512後，只新增兩筆確切hash；沒有停用驗證、忽略失敗或放寬信任規則。原始失敗與修後工作流程紀錄均保留。

封裝覆核曾因原生清單漏列既有 `libandroidx.graphics.path.so` 而拒絕 APK。已從官方 Google Maven 取得 `graphics-path:1.0.1` AAR，與 Maven checksum 基準及 APK bytes 逐一對照後納入精確清單。原始失敗紀錄保留；未知或不符雜湊的原生檔仍會被拒絕。

## 剩餘風險與未測範圍

| 項目 | 判定與影響 | 發布要求／處理方式 |
| --- | --- | --- |
| 本機 MCP HTTP Bearer 的伺服器身分（G01） | 架構風險仍存在。Control 的 HMAC 不等於 MCP listener 已驗身；換 port 或 tunnel edge TLS 也不足。未做占埠／截取 token 驗證。 | 後續採可驗證 TLS、受保護 IPC 或標準 MCP stdio adapter 搭配獨立 MCP scoped 認證通道；正式發布前完成設計與獨立覆核。 |
| OpenSSL 3.6.5 EOL | 已確認維護狀態；新的上游公告未分析 EOL 3.6，未建立其在本 App 的可達利用。 | `production_ready=false`，正常 release 工作流程拒絕。更新至受支援且修補狀態核實的 runtime，完成 ABI/TLS/SQLite/裝置覆驗後再審核。 |
| 原正式簽章不存在於此環境 | 無法以原憑證產出既有安裝的覆蓋更新。 | 保留原 keystore，在受控簽署環境產生正式版；本輪只交付獨立 Review APK。不要為裝測試版刪除原 App。 |
| Android／LINE／雲端端到端 | 沒有真機或模擬器啟動、真實登入／同步／背景重啟、既有版本升級或真實供應商驗證。 | 用專用測試帳號補做；編譯、靜態 ELF 檢查與 fake 測試均不能代替。 |
| 資料生命週期與在途操作 | 既有日報／草稿、未連結來源的快照、附件、索引與保留日誌各有生命週期；去識別是啟發式；已送往外部的操作無法召回。 | 清楚呈現雲端／連接器資料流、保留政策與真正刪除／登出功能；kill switch 不等於 LINE 登出或資料清除。 |
| 圖片／網路相容性 | 容器驗證不等於完整安全解碼；保守 IPv6、只允許 443、拒動畫與環境 HTTP proxy，可能拒絕部分合法服務。 | 真實供應商、DNS64／VPN／企業代理情境另測；保持 TLS 驗證及 pinning，不以關閉驗證解相容性。 |
| LINE 媒體與跨程序可靠性 | LINEJS 的媒體下載仍可能先在依賴層緩衝完整資料；多程序 outbox 原子 claim、程序崩潰與 ambiguous delivery 未完整解決。 | 另做串流限制與多工作者／崩潰後送達語意設計；不宣稱 exactly-once。 |
| 供應鏈與 CI | 未獨立從原始碼重建 Termux binaries；Maven hash baseline 不等同上游作者簽章或完整 JVM SCA；主分支未強制 required checks。 | 審查 lock 更新與官方公告；設定受保護的發布流程；不得只改批准欄位或省略驗證來解除阻擋。 |

## 發布建議

修補 PR 可供原始碼與 Review APK 驗收；是否合併須參照最終獨立審計與實際 CI 結果。Review 僅供測試帳號、非敏感內容的驗證。**正式安全發布維持 NO-GO**，直到原生 runtime 維護風險、本機 MCP 伺服器身分、正式簽章及裝置驗收條件完成。

## 官方依據

- [NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)、[OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)、[MITRE CWE-367](https://cwe.mitre.org/data/definitions/367.html)、[CWE-862](https://cwe.mitre.org/data/definitions/862.html)。
- [MCP 安全實務](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)、[SDK 輸入複雜度公告 GHSA-46jr-4wx8-v453](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453)。本案是未啟用選項，不把 SDK 1.32.2 虛列成舊的受影響版本。
- [Gradle 8.14.8 release notes](https://docs.gradle.org/8.14.8/release-notes.html)、[官方 checksum](https://gradle.org/release-checksums/)、[GHSA-35pj-rg5r-8rpv](https://github.com/gradle/gradle/security/advisories/GHSA-35pj-rg5r-8rpv)。先前列出的 Gradle GHSA 沒有 CVE 的項目維持 GHSA 標識，不虛構 CVE。
- [OpenSSL 3.4／3.6 EOL](https://openssl-library.org/post/2026-11-01-eol34-36/)、[2026-11-10](https://openssl-library.org/news/secadv/20261110.txt)、[2026-11-17](https://openssl-library.org/news/secadv/20261117.txt)、[2026-11-24](https://openssl-library.org/news/secadv/20261124.txt) 官方公告。
- [c-ares 1.34.9 changelog](https://c-ares.org/changelog.html)、[SQLite 3.54.1](https://www.sqlite.org/releaselog/3_54_1.html)。只按原生 lock 實際版本核對，不把公告版本清單當成已在 App 成功利用的證據。
