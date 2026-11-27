# Android runtime 與 APK 封裝覆核（2026-11-26）

基準是未合併 PR #11 的 `e1b25d2dd960bf31363b073b92f9108e75f2d300`，tree `49a633dd53ad3400fd77a354561f8b3c7a8f2a73`；CI 使用同 tree 的 PR merge source `ec7acc84a1b241976c89778e33313a03514e8dd2`。本輪只補最終原生封裝檢查與收據，不更換 native bytes、lock、runtime 批准或簽章設定，不合併、發 tag／Release，不重跑 #12。

## 已核對的實際輸入

[既有產物15103578619](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45794541067/artifacts/15103578619) 實際下載 ZIP 為73,613,578 bytes，SHA-256 `0e62f61cc7fe7b572657110583285a9bcd46e4e73e4e88e727902bfd1542de43`；source-commit 與內嵌 lock 均已核對。

| ABI | APK SHA-256 |
| --- | --- |
| arm64-v8a | `ab91cf16b7a85fd575d8da5a6d7c2526312922df787d22c1d063fc1cd4fb922e` |
| x86_64 | `cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4` |

兩包均由官方 Build Tools35.0.0 的 apksigner／aapt 重驗：`tw.linemcp.app.review`、versionCode5、`0.3.1-review`、minSdk29／targetSdk35，ABI 各自精確相符。簽章檢查 exit0，公開憑證 SHA-256 `032c8b839478924d89f03c26da668289ab1d24b348cc2d5cb0894bb197fde046`。主機靜態驗簽階段沒有讀取或建立簽章私鑰；既有 CI 的 Review 簽章須另驗，不能假定可覆蓋舊 Review 或正式安裝，也不可藉卸載保留資料來冒稱升級成功。

## 原包實際封入什麼

每 ABI 各有10個固定 Node runtime ELF 與1個固定 AndroidX ELF。兩個 `libnode.so` 都直接 DT_NEEDED `libtx_ssl.so`、`libtx_crypto.so`；ssl 另直接依賴 crypto。所有非系統 NEEDED 在同 ABI 包內閉合，版本化需求的 provider 名稱已同步重新命名。每 ABI 的 Node617個、ssl553個 strong versioned OpenSSL imports，獨立核對均由其精確指定 provider 的 symbol+version 提供，不是把各 library 的 exports 混在一起猜。

`libtx_crypto.so` 的版本標記為 OpenSSL3.6.5；ssl 確實需求 crypto 的 `OPENSSL_3.6.0`。這與 signed package lock 一致，**沒有證據顯示已升級 TLS 卻漏封入 APK**。相反地，這就是仍受正式 gate 阻擋的3.6.5，而非受支援的新 TLS runtime。不能只替換同名 crypto 檔案或改 package label 就當作相容升級。

公開簽署 APT snapshot→signed index→package Version／Architecture／Filename／SHA-256／Size 皆已獨立核對。從原 `prepare` 入口實際重打包雙 ABI，輸出雜湊與 lock 相符。這是 signed binary authentication 與重打包重現，**不是上游 source build 重現或 source attestation**。`node_source_sha256` 屬未批准原始碼調查入口，既有 APK CI 不執行該 source-build 腳本。

ELF note 也必須和 package label 分開：libc++ package Version30，但實包 note 是 API21／NDKr28 build13004108；AndroidX 是 API21／r25c；其餘有 note 的 runtime 多為 API24／r30，icudata 沒有該 note。補充 NDKr30 NOTICE 不是 libc++ 由 r30 編譯的證明。觀察到的系統 symbol version 為 LIBC／LIBC_N；未做全部 API29 platform stub 的逐符號核對，更沒有 API29 裝置執行證據。

## 可驗收的封裝改善

原最終 `verify`／`verify-apk` 已比對精確 inventory、hash、ABI、LOAD 對齊與 notices，但沒有在最終位元組上獨立檢查動態圖。未來審查新 output hashes 時，不能把「同名 TLS 檔案存在」等同「Node 實際連到該 provider」。本輪將最終 linkage contract 加入既有驗證入口，保留精確 hash 與 production gate。新增版本檢查要求 VERNEED 的需求名稱由精確指定 provider 的 VERDEF 提供，並不取代完整 dynsym 逐符號解析或 Android platform stubs 比對；原包的完整 OpenSSL imports 已由獨立 reviewer 另核。JSON report 明列這次是否真的核對 signed provenance，靜態結果不冒稱 runtime success。

既有 Android-review 工作流保留 `contents: read`，仍用原 `assembleReview` 入口真實編譯。成功產物另保留 prepare／每 ABI linkage JSON 與官方 zipalign 輸出；report 沒有裝置執行結果、私鑰、token 或聊天資料。

## 16 KiB：靜態證據與真機分開

以 [Android 官方 page-size 指南](https://developer.android.com/guide/practices/page-sizes) 為準。

- 原兩 APK 的官方 `zipalign -v -c -P 16 4` 均 exit0。native entries 使用壓縮打包／解壓執行；ZIP gate 成功不代表 ELF 可執行，更不代表裝置驗收。
- 獨立解析22個 ELF 的全部 PT_LOAD，alignment 均至少0x4000，file offset／vaddr 的16 KiB餘數相符。沒有觀察到 writable+executable LOAD、executable GNU_STACK 或 DT_TEXTREL。
- RELRO 需檢查頁面保護是否覆蓋仍需寫入的資料。20個 runtime 的 RELRO end 已對齊或等於其 RW LOAD end。兩個 AndroidX 的 RELRO memsz 超出 RW LOAD 有效資料，差額是 padding；其下一 RW LOAD 在另一16 KiB頁。掃所有 RW LOAD 的完整 memory range（含 BSS），22個 ELF 均不與 RELRO end 到下一16 KiB邊界的 tail 重疊。不能僅因 padding 令 end 不等於 LOAD end 就報 crash，亦沒有執行 crash／漏洞重現。

真實16 KiB原生通過需同時保存：測試 APK SHA-256、ABI、實際 `getconf PAGE_SIZE` 回傳 `16384`，以及已授權隔離測試機上 **此 App 的 page-size compatibility mode 關閉** 的可核對證據，再執行此 App 的正常流程。只可開啟或沒看到警告都不足；ZIP／ELF 靜態通過也不足。本輪沒有已授權裝置，以上真機項目全部 **未測**，沒有更改使用者手機或全域屬性、刷機、預約、上傳外部裝置服務或花用雲端額度。

## 仍未解除的門檻

[Node v24.22.3 官方 BUILDING](https://github.com/nodejs/node/blob/v24.22.3/BUILDING.md#android) 仍標示 Android unsupported。[OpenSSL3.6 EOL](https://openssl-library.org/post/2026-11-01-eol34-36/) 與 [2026-11-24公告](https://openssl-library.org/news/secadv/20261124.txt) 仍適用；公告中的修補版本預告不能當作已發布、已封入、已相容或已驗收。

正式 gate 必須繼續拒絕。待另取得來源及修補狀態可驗證、與 Node headers／symbols 相容的 Android runtime 後，才有後續 runtime／lock 審查。仍需隔離裝置上的正常安裝、冷啟動、背景／前景、CA/TLS正負向、SQLite、合成資料本機 MCP、App程序重啟與整機重啟後狀態，以及真正16 KiB且App相容模式關閉的驗證。本輪不使用真實 LINE、第三方主動探測、沙箱繞過或漏洞利用。

原始本機輸出與獨立核對摘要見 `review-work/native-packaging-20261126/`。新固定提交的真實 CI 結果與產物下載連結另記於 PR #11；未取得新產物前不以舊 APK 冒充新改動的建置證據。

## 本機與獨立覆核結果

原 native43/43；新增後67/67，Node158/158、TypeScript exit0、原獨立 Node13/13與Python7/7。新 focused 獨立23/23，過程發現的 PT_DYNAMIC VA／offset／memory mapping 缺口已修正並重測。修前拒絕期望與修後原始輸出均保留，合成 fixture 結果不冒充 Android 執行。新 gate 下實際 prepare、兩份固定原APK均成功；production CLI 仍按預期exit1，failure JSON不留下passed狀態。npm advisory查詢為0，但不取代TLS支援狀態或裝置測試。
