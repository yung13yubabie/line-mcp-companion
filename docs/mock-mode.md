# Debug QA 與 production 的來源邊界

QA 資料、測試組與正常開發流程保留在 repo；不能因為正式不出貨 QA，就刪除隔離測試。

- Android 的 Mock 偏好、環境注入、假 provider 選項與設定介面位於 `android/app/src/debug/`。只有 debug variant 編入該實作，資料仍在 `filesDir/mock/`；既有 QA 清除動作只處理自己的隔離目錄。
- release／Review 編入 `src/production/` 的固定功能實作，不讀 QA 偏好、不注入 `LINE_MCP_MOCK`、沒有 QA 面板或 provider 選項。這不只是以 BuildConfig.DEBUG=false 隱藏主來源的 QA 功能。
- `npm start`／`node src/main.ts` 是桌面 debug/source 入口，仍可選 QA；它們不是 production runtime。正式 host 驗證須先 `npm run bundle:android:release`，再執行生成的 `android/app/src/main/assets/nodeapp/main.mjs`。
- Node debug runtime policy 可以載入 `src/mock/runtime.ts` 與既有假資料；`npm run bundle:android` 是保留 QA 的開發 bundle。不要把它交給正式／Review。
- `npm run bundle:android:release` 以完整 production policy module 建置，禁止 App QA module 進入真正 compiler source closure；不再替換成 Mock stub。production 忽略舊 QA 環境，沒有切到 mock home 或可啟用的假 provider。舊／不支援 provider 設定必須安全停用，不能自動轉成 cloud 或送出。
- 每份 production bundle 產生 hash 與 source closure receipt；最終 JS bytes 還須獨立掃描。receipt 是一致性收據，不是安全簽章、publisher 證明或真機驗收。
- `scripts/purge-mock-check.sh` 現轉交完整靜態封裝檢查器；無有效 receipt、缺檔／空檔、App QA marker/scaffold、未知 assets、DEX／manifest／ABI／版本不符都非零失敗。APK 必須明確指定官方 Build Tools 與預期 package/version/ABI，不能只 grep 主 JS。

`npm run android:review` 會建 production bundle、正常 strict Gradle JVM／debug Kotlin compile／Review APK，最後逐 ABI 檢實包。`npm run android:release` 保留原 production native 與簽章門檻；目前未通過，不產生或公開正式更新。不能將 Review、host fixture、SDK smoke 或合成 metadata 測試當真實裝置驗收。見[完整邊界與證據](production-artifact-boundary-2026-11-27.md)。
