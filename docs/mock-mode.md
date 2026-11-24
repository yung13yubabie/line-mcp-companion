# Mock 模式（僅 debug）與完全移除

- 開關：設定 → 開發者（僅 debug 版）→ Mock 模式。存在 SharedPreferences `app.xml: mock_mode`，`BuildConfig.DEBUG=false` 時恆為關閉。
- 隔離：Node 收到 `LINE_MCP_MOCK=1` 時，資料庫在 `filesDir/mock/`（與真實 `line.db` 分開），所有假資料 ID 以 `u_mock_`/`c_mock_` 開頭，標記 `LMA_MOCK_DATA_v1`。
- App 內清除：「清除全部 Mock 資料」= 關閉開關 + 刪除 `filesDir/mock/` + 重啟 Node。
- Release 建置完全移除：`npm run android:release`
  1. `bundle.ts --release` 以 plugin 把 `src/mock/mock-source.ts` 換成 `mock-stub.ts`（假資料與程式碼不進 bundle）。
  2. `scripts/purge-mock-check.sh` 檢查 bundle 與每個 release APK，發現任何 mock 標記即失敗。
