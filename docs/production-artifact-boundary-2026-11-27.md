# Production／Review 無 App QA 封裝邊界（2026-11-27）

本批承接 PR #13 合併後 main `4a77dbcbbe2e53ff6b813260ce8ae0f867d3a269`；最初審查的已交付基準為 PR #11/main ee10869。它修正正式來源／實包的 QA 邊界，不更換 runtime、app 版本、簽章或 workflow 權限。正式 APK 仍須通過既有 production/runtime/signing 門檻；未達門檻時不發布、不重簽假裝可升級。

## 實際基準與修補原因

先前 Review APK 的已知假聊天 seed／ID 與可啟用環境旗標已移除，但主 JS 仍包含 App 的 `MockSource`／`MockAiProvider` stubs、`goMockOnline` 空函式；DEX 也有條件式 QA badge 文案。這是「已無已知假資料」與「未帶 App QA 模組／介面 scaffold」的落差，不能據此宣稱 Mock 可被啟用，也不能宣稱程式已完全移除。

舊 gate 只對 `assets/nodeapp/main.mjs` 做七個 marker grep；對 markerless App stub、其他 asset、manifest、DEX、版本與 ABI 的覆蓋不足。獨立靜態 fixture 證實這些拒絕缺口，沒有執行或攻擊 APK。

## 真正的來源邊界

| 部分 | debug QA | production／Review |
| --- | --- | --- |
| Node runtime policy | `src/runtime-mode.ts` 可載入 `src/mock/runtime.ts`，保留隔離假資料與正常 QA | compiler 明確使用完整 `src/runtime-mode.production.ts`；不以 Mock stub 替代，不接受 QA source closure |
| 資料金鑰 | QA 的 ephemeral／QA-only 清理邏輯在 `src/mock/data-key.ts` | 正常 data-key resolver 不帶 QA Boolean 或 QA 清資料分支，舊 QA 環境不能改 home 或免除金鑰要求 |
| 假 AI provider | constructor-only extension 由 debug policy 提供 preset／factory／no-key／validator | 沒有 App QA provider 清單、假 URL／model preset、factory 或可啟用開關；共有服務只有一般 extension 介面，外部設定不能建立它 |
| Android QA 介面 | `android/app/src/debug/` 保存偏好、環境注入、假 provider 選項及清除自己的 QA 資料 | release／Review 僅編入 `src/production/` 固定功能實作；主 source-set 不再包含 MockMode、QA 面板或注入旗標 |

repo 的測試、fixture、debug QA 與隔離資料程式保留；它們不屬正式出貨內容。第三方 undici 的 MockAgent／MockPool 與 Kotlin DebugProbes 並非本 App 假資料，不用泛 `Mock` 字比對誤殺；gate 精確針對 App QA 來源／入口／資料與完整封裝結構。固定 `mock:false` 的相容狀態不是可啟用 QA 開關。

### 舊／未知 provider 的正常恢復

production 對不支援的已存 provider 回傳明確 unavailable、空 endpoint/model/fallback 並停用 AI，不默選 cloud，不建立或呼叫 provider。待審 pending 草稿及內容保留；可能自動執行的 approved 舊排程標為 expired 並記原因／稽核，保留內容，不刪資料庫。使用者可經正常 Control／設定明確選合法 provider 儲存，AI 維持停用，舊 approved 不因修設定自動重送。合成記憶體資料庫與真正自有 loopback Control GET／POST 已覆核此流程；不是接觸使用者資料。

## 失敗即擋的實際門檻

1. 真正 Bun compiler 的 production dependency closure 禁止 `src/mock/` 或 debug policy；失敗時移除前次 bundle／receipt，不能沿用舊成功檔。每次輸出 production receipt，綁 recipe、全部 loaded source hashes 與最後 JS SHA-256。
2. `production-artifact.py` 再核最後 JS bytes、來源 hash／路徑、production mode 與 receipt；缺檔、空檔、stale recipe/source、QA stub／seed／環境旗標／假 provider preset 都拒絕。receipt 是一致性證據，不是安全簽章或 publisher attestation。
3. 最終 APK 檢查所有 ZIP names、非 native／META-INF payload、精確 assets allowlist、必要 license／lock、全部標準 DEX string tables 與 checksum、官方 aapt manifest/badging。缺 DEX、重複／未知／超限／加密／不安全 entry、額外 fixture/asset、App QA 文案、debuggable/testOnly、非預期 package/version/ABI/SDK 皆非零失敗。native bytes／簽章分別仍由既有 native/apksigner gates 驗證，不能由此替代。
4. `assembleReview`／`assembleRelease` 完成時逐 ABI 驗最終 APK；正常 npm 入口與 CI 使用相同 gate。手動執行必須明確提供官方 Build Tools 與實際預期 package/version/ABI，不能靠檔名。AAB 的最終打包驗收未做，不把 APK gate 延伸宣稱 AAB 通過。
5. Security CI 實跑 scanner fixture／正常服務回歸、真正 debug／production compiler，以及最後 production JS 的 host 入口。Android CI strict dependency verification、debug Kotlin 編譯、Review JVM tests 與雙 ABI APK 建置／實包核對；成功工件保留 XML、封裝收據、原生／簽章／版本與 SHA256SUMS。權限仍 contents:read，只 upload Actions Review artifacts，沒有建立正式 Release／tag／上架步驟。

## 實際測試與不可替代的驗收

主線本地已實跑 TypeScript、完整 Node165／0skip、scanner10／0skip、真正 compiler2／0skip、production bundle host entry1／0skip。host entry 使用 NodeService 同一份生成 main.mjs，私有空資料目錄、合成 stdin secrets，刻意給舊 QA flags 仍 mock=false、正常 home、0聊天／0訊息、預設只讀；驗 Control hello/HMAC／完整 response proof，再經真正標準 SDK stdio 只讀同步狀態。未登入 LINE、未讀訊息、未呼叫第三方服務或 Android 裝置。正向合成 APK parser fixture 不是真 APK 成功。

本地 production bundle SHA-256 `4eafb54451f1a9f23209158bd386f3544372e4bc9036724237b87714cbe5b63c`，source closure564份。CI 需核自己的固定 source／recipe／bundle／實際 APK；Bun 可能在 undici `__filename` 留建置路徑，不能把不同路徑的 raw bundle 宣稱 bit-reproducible。最終新提交、CI 與實包 hashes 以 PR 本次收據為準，舊 APK 不能替新版來源背書。

尚未執行 Android 安裝／UI／裝置驗證／剪貼簿、前後景、App 程序與整機重啟、真實覆蓋與資料保留、真正16 KiB＋此 App compatibility mode 關閉的驗收。ZIP／ELF 靜態對齊與 host smoke 不替代它們。沒有已授權可用 device executor，未重跑 #12／登入／預約或上傳外部裝置服務。正常覆蓋仍需[明確 baseline、合法 signer、版本與合成 canary 條件](apk-upgrade-preflight-2026-11-27.md)。

現行 OpenSSL3.6.5 EOL／Node Android 支援缺口與正式簽章流程未解除；[runtime／device 狀態矩陣](runtime-device-status-2026-11-27.md)分開記錄。正式 APK 未建、未發布；Review 與本批編譯成功不代表正式可出貨或可覆蓋舊版。
