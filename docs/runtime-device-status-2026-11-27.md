# Runtime / device evidence — 2026-11-27

基準 main `ee10869fc0f4f089ed4e2544c5fa9b98a8f95ed5`。本批查核 runtime 來源與裝置能力，將可核對狀態保存在此文件；沒有更換 runtime、lock、簽章或權限。**未識別一套已可批准的受支援相容 Android runtime，也沒有建立可用的已授權隔離 Android 執行環境。這兩個外部缺口不應阻擋可獨立完成的 Mock 封裝修補。**

## 可核對的 runtime 支持矩陣

| 路徑 | 已核來源／版本 | ABI／API／TLS／16 KiB 證據 | 判斷及缺口 |
| --- | --- | --- | --- |
| 現行 Review runtime | committed lock：Node24.22.3、OpenSSL1:3.6.5；signed snapshot2026-11-25；aarch64/x86_64 各自精確 package/output hashes | 既有 APK 覆核記錄有雙ABI依賴閉包、TLS provider、LOAD/RELRO；lock hash未變。這次沒有重新執行Android binary或把舊靜態檢查冒充新裝置驗收 | OpenSSL3.6於2026-11-01 EOL；production_ready=false。真入口 `verify --production` 本線實際exit1：OPENSSL_36_EOL / OPENSSL_BRANCH_UNSUPPORTED |
| Termux 當前配方 | official master 固定 `2c85acb42b2ca1f884566cbd45aa716c37b3426b`：nodejs-lts仍24.22.3（明確shared OpenSSL），openssl仍1:3.6.5 | 配方包含aarch64/x86_64建置路徑與source SHA，但配方不是已取得／驗簽／驗依賴的替代APK binary。本線沒有刷新當前binary APT index或下載新deb | 沒有從這次配方查核得到可替換的受支援TLS閉包；不要把master配方當新的signed binary snapshot |
| Node24.22.3 upstream | [固定版本BUILDING](https://github.com/nodejs/node/blob/v24.22.3/BUILDING.md#android) | 官方仍明示Android unsupported、upstream CI沒有Android測試；有cross-build說明不等於平台支援 | Node24主版本壽命／Linux arm64 binary不證明Android bionic運行支援 |
| Node26.13.1／upstream main | [固定26版BUILDING](https://github.com/nodejs/node/blob/v26.13.1/BUILDING.md#android)、[main BUILDING](https://github.com/nodejs/node/blob/main/BUILDING.md#android) | 兩份亦明示Android unsupported；沒有為本App取得雙ABI/SQLite/headers/API/裝置證據 | 換Node major不能宣稱解除Android支援門檻；不替換runtime賭運氣 |
| OpenSSL3.5 LTS source | [官方下載](https://openssl-library.org/source/)當日列已發布3.5.9，branch到2030-04-08；[11/24公告](https://openssl-library.org/news/secadv/20261124.txt)修補3.5.10預定12/01 | source release不是相容Android package set。既有ssl需求crypto的OPENSSL_3.6.0；不能只換同名.so.3或降換headers/runtime | 現有production政策floor3.5.10 + available-from12/01仍必要但不充分；今天不能把公告版本當已發布、已封入或已驗收 |
| OpenSSL4.0／4.1 source | 當日官方下載列4.0.3/4.1.0；公告4.0.4/4.1.1預定12/01 | major4不符合目前.so.3/inventory/provider/Node headers契約；無雙ABI相容重建與裝置結果 | 不進行改檔名式替換；不能把branch維護中當本App已安全可出貨 |
| 自建Node + 相容受支援TLS | repo保留NOT APPROVED source-build調查入口 | 本線沒有建立新的source/toolchain/patch/output閉包，也未編譯/執行候選 | 日後須可核來源、正確headers整組重建、signed metadata、API29+/ABI/CA/TLS/node:sqlite/MCP及4KiB/16KiB驗收；沒有自動production批准 |

OpenSSL官方[3.6 EOL公告](https://openssl-library.org/post/2026-11-01-eol34-36/)仍成立。11/24公告排除EOL3.6的分析；沒有列出3.6不代表不受影響。本線沒有做可達性或漏洞重現，也不將公告中的問題虛列為已確認App漏洞。新政策/候選仍需獨立覆核；不得只修改approval Boolean、blocker或版本字串。

四份官方純文字來源的固定URL與SHA-256由獨立調查保存；主線另從官方Node24 BUILDING、Termux固定openssl配方與OpenSSL公告獨立核對關鍵判斷。Termux配方source不執行，沒有下載候選runtime binary。實際production CLI在lifecycle gate早期拒絕，不能宣稱該次重新做過GPG或Android輸出驗證。

## 現有 Android 能力與最早阻點

本環境PATH未找到 `adb`、`emulator`、官方 `android`、`gcloud`、`firebase`、`avdmanager`、`sdkmanager`；ANDROID_HOME/ANDROID_SDK_ROOT未設，六個常見SDK/Studio路徑不存在，`/dev/kvm`不存在。這是明確的探查範圍，**不是掃描全磁碟或證明所有地方都不可能有SDK**。既有官方Build Tools只足以host APK靜態核對，不等於ADB、device streaming登入或裝置權限。

[官方Android CLI](https://developer.android.com/tools/agents/android-cli/commands/device_remote)的正常remote路徑需要已登入帳號和已啟用device streaming的Cloud project。本線沒有現成CLI或可核對連線，因此在**工具／現成連線**處停止：未查帳號、專案、IAM、API啟用、剩餘免費額度或裝置預約，不新增登入、不讀憑證、不建立/改專案或用量、不上傳APK、不重新跑#12模擬器。

[官方公開額度](https://firebase.google.com/docs/test-lab/usage-quotas-pricing#android-device-streaming-quotas)當日為每project每月30分鐘免費streaming；不能解讀成此用戶還有30分鐘。本線remaining_project_quota=not_verified。一般[Device Streaming操作文件](https://developer.android.com/studio/run/android-device-streaming)說明可在Android Studio/Cloud console查看專案用量；有免費方案不等於已授權可使用。Firebase官方頁亦說明Test Lab日後停用不等於Device Streaming停用，不能混為沒有官方服務。

## 日後最小合成真機驗收順序（皆未執行）

1. 先具備專用隔離裝置的明確授權與現成可用通道；不得使用用戶日常手機。記裝置型號、OS/API、ABI、實際page size，及candidate/baseline的來源SHA、APK SHA-256、package、versionCode、signer。
2. 只在baseline可明確識別、相同package/ABI/合法signer continuity且candidate versionCode嚴格增加時測覆蓋。先核最終無Mock/manifest/assets/JS/native/signature gates；不同signer/同版/未知baseline立即停止覆蓋路徑。不能以重簽、降版、卸載/清資料讓流程看似通過。
3. 在已授權專用隔離裝置正常安裝baseline，以App正常支援的設定/資料途徑建立合成canary；不啟用LINE登入、不取真聊天、不用root/run-as/沙箱繞過灌資料。若正常產品沒有支援的合成資料入口，只測可正常建立的設定canary，其餘項目保留未測。
4. 記錄正常冷啟動、服務ready、預設只讀、App自有端點/stdio正常工作流（合成key、空資料或合法canary）；驗證CA/TLS與SQLite的受控正常正/負向流程，無第三方探測或漏洞輸入。
5. 以candidate正常覆蓋安裝，**不得 uninstall/clear-data**。冷啟動後讀回合成canary、設定及schema狀態，核版本、service/readiness與日誌不含secret；無法讀回不能稱資料保留成功。
6. **App程序／服務重啟**：在正常自有App控制流程重啟後重讀canary及本機只讀連通；另測背景→前景、預定等待與服務狀態。這不等同整機重啟。
7. **整機重啟**：僅在專用測試機另有授權時正常reboot，再解鎖、冷啟動/檢查預期啟動政策、讀回canary、重新驗身及只讀連通。不能用App重啟結果替代。
8. 真正16KiB原生通過需同份APK SHA/ABI、裝置 `getconf PAGE_SIZE=16384`，及**此App page-size compatibility mode關閉的可核對證據**，再跑上述正常流程。依[官方16KiB文件](https://developer.android.com/guide/practices/page-sizes)，ZIP/ELF對齊須分開記錄；只開得起來、沒有警告、模擬器或4KiB結果都不足。不得改用戶手機或全域屬性；沒適用裝置/compat-off證據就記未測。

目前所有裝置執行、真實升級/資料保留、UI/裝置驗證/剪貼簿、前後景、App重啟、整機重啟及16KiB/compat-off均NOT TESTED。正式production NO-GO保留；本線不構成發布或安裝批准，也不應延遲其他已能切實驗收的獨立批次。
