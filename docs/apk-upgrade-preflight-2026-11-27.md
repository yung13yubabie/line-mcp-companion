# APK 覆蓋升級：基準、只讀門檻與未測項目（2026-11-27）

基準 main `ee10869fc0f4f089ed4e2544c5fa9b98a8f95ed5`，PR #11 已合併。這批補交付前檢查，不更換簽章、不改版本、不安裝／卸載、不碰使用者手機或真 LINE 資料，不公開發行。Mock 封裝修補、runtime 與裝置驗收分批處理。

## 哪一份「舊版」已被辨識

本輪 GitHub Releases 查詢為空，公開 git tag 列表也為空；這只表示在該次查詢沒有這些發行記錄，不能推論從未有其他發行或使用者手機沒有正式版。可取得的既有 APK 都是 Actions 的 `tw.linemcp.app.review`。README 記錄的正式公開憑證 `75e72fe9bc01b9e89f78a9425312581c1d4daa92e9cbe21463f8761897eca90a` 只是 declared reference，本輪沒有相符的正式基準 APK 或可核對的合法正式簽章流程。不得把某次乾淨 CI Review signer 當正式 signer，也不向使用者索取私鑰。

明確已交付的 baseline 是上一輪 [artifact15165393549](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45923477601/artifacts/15165393549)，head d49af8c、來源同 tree 的 a99c2d6。合併後 main 另已正常下載 [artifact15166365379](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45924530784/artifacts/15166365379)，ZIP 73,642,078 bytes、SHA-256 `fc345e077569ec836098dde8d96726efe843f23b83a56437db5e78b2c28e9fd7`，18 entries，source-commit 確為 ee10869。二者只屬 Review 交付基準，不證明目前安裝在任何裝置上的版本。

| ABI | 已交付 baseline APK SHA-256 | 合併後 main APK SHA-256 |
| --- | --- | --- |
| arm64-v8a | `166f933ca6ed675fd54a31b1442ef20df9eea7b31e986d357c361ba07a1d9883` | `a3995ed41e4b48ff2095fd6eb59911d834ff8673679f80d8fd016cc3652353a9` |
| x86_64 | `e1a4de7d9bfc99e5d18db0c8e9f72dfadd8723d8eb9a482fcaec2f79ec3f14e9` | `7f14fec0581cab6455f339b6382003efb009f6a4c07c5d01d5ad0d25fa774f22` |

兩代各 ABI 都是 `tw.linemcp.app.review`、`0.3.1-review`、versionCode5、minSDK29／targetSDK35、nondebuggable。已交付 signer 是 `cc7a985049e1ca9838b9e1a5e2a82804ae224ced90c363ca8b897b928cc007f3`，main signer 是 `a8f601897ce8e9f34cbac5c961783407d8c29ac1803d1ff1b8bfb7faf0103f26`。經官方 apksigner/aapt 重新核對的實檔比較應明確 blocked：簽章不同、版本碼未增加。這是正確拒絕，不是升級成功。沒有為了消除這些結果重簽、降版、卸載或清資料。

[Android 簽章文件](https://developer.android.com/studio/publish/app-signing)將更新身分與 app signing certificate 相連；upload certificate 不等於 Play 發到裝置的 app signer。[版本文件](https://developer.android.com/studio/publish/versioning)說明 versionCode 的更新／降版規則。此工具額外採嚴格增加作為升級測試必要條件，不宣稱 Android 一般禁止同版重裝。

## 顯式 profile 與檔案綁定

舊 `scripts/review-apk.py` CLI 仍只接受 Review，預設與既有15項回歸保持不變。新 `scripts/apk-upgrade.py` 只讀使用指定的官方 Build Tools；沒有 sign/keytool/adb/裝置或上傳指令。它要求：

- `--package-kind review` 精確限 `.review` 與 `-review`；`release` 精確限 `tw.linemcp.app` 且非 review/debug 版名。正式 profile 不會把 Review APK 改稱正式版。
- `--expected-signer-sha256` 是呼叫者經獨立來源確認的公開憑證指紋；compare 的 baseline/candidate 必須共同符合它。這個輸入本身不證明 publisher 或來源。
- 每個輸入都有顯式 `--…-sha256`，再以自有私有唯讀 snapshot、官方 apksigner/aapt、前後 SHA/stat 和完成時重新核對原檔。只讀實檔，不接受既有 receipt JSON 冒充輸入。
- compare 除 pin 外仍要求同 package／單 ABI／同 current signer／versionCode 嚴格前進；split、versionCodeMajor、未知簽章 scheme、rotation lineage 等不明資料維持 fail-closed。report 安全路徑／原子更新沿用舊工具，不能覆寫輸入 APK 或 tools；任何非零結果都不得沿用舊成功 JSON。

```sh
python3 scripts/apk-upgrade.py compare --package-kind release \
  --build-tools /absolute/verified/build-tools/35.0.0 \
  --expected-signer-sha256 <independently-verified-public-certificate-sha256> \
  --baseline /absolute/previous.apk --baseline-sha256 <fixed-baseline-sha256> \
  --candidate /absolute/candidate.apk --candidate-sha256 <fixed-candidate-sha256> \
  --report /absolute/existing-private-output/upgrade.json
```

這是待具備真正正式基準及合法簽章流程後的指令範本，不是本輪已執行的正式版測試。`signature_metadata_verified`／`metadata_conditions_satisfied`／`eligible_for_authorized_isolated_upgrade_test` 只表示指定檔案的保守 metadata 條件；publisher、source_provenance、runtime、device、data_preservation、upgrade_runtime 均維持 `not_tested`。不等於發布／安裝授權、實際覆蓋或資料保留成功。

## 本輪可重跑證據與界線

12項合成 profile／pin／signer／version／ABI／檔案變動／安全 report／timeout 回歸使用明確 synthetic runner，沒有建立或簽署 APK；正向 eligible 只有此合成判斷測試。runner 在 skipped>0、tests=0 或 errors/failures 時非零；既有 Review 15項照跑。Security CI 新增正常入口並保留結果，無權限或 signer 管理變更。

主線另對上表兩 ABI 的真 main APK 逐一經新 CLI 執行 Review inspect，exit0；與已交付 baseline 真 compare 各 exit1，聚合 `candidate:expected_signer_mismatch`、`signer_mismatch`、`version_not_advanced`。再把真 Review 包交 release profile 各 exit1 `release_package_and_version_required`。沒有真實正向正式版 baseline/candidate、安裝、覆蓋或資料保留測試。新 PR 的 CI APK 仍只是 Review；它也不能自動承接先前 signer。

## 正常覆蓋與資料保留的未執行門檻

先辨識實際正式 baseline（來源、APK hash、每 ABI package/version/current certificate）與合法既有 app signing 流程；核候選無 Mock／manifest/assets/JS/native/signature，且候選版本碼確實高於該 baseline。正式基準未知時不能只看 README 指紋或任意 bump6。

只在已有授權的專用隔離 Android 環境、相同 package／ABI／合法 signer continuity 和正確版本時，以正常 UI 建立無真 LINE 的合成 canary（如可支援的設定），記錄正常安裝 baseline → 候選覆蓋（不 uninstall／clear-data）→ 冷啟動 → 讀回 canary。產品沒有正常合成資料入口就保留資料測試未做，不注入私有資料庫、不用 Mock 代替。之後分開測背景／前景、App 程序／服務重啟及整機重啟，重讀同一 canary 與本機只讀流程。

本環境沒有現成可用的已授權 Android 執行通道（未找到可用 adb／emulator／官方 Android CLI 或已授權 device executor；既有官方 Build Tools 僅供靜態驗包，未登入或啟用外部服務／額度）。不重跑 #12，不上傳 APK 到別的裝置服務，不繞過。16 KiB ZIP／ELF 靜態通過不等於真機；真正原生通過另須同 APK hash/ABI、`getconf PAGE_SIZE=16384`、此 App compatibility mode 關閉證據，再跑正常流程。這些裝置／升級／資料保留均未測。

正式 production gate 仍拒絕 OpenSSL3.6.5 EOL，Node Android 無官方支援保證；沒有通過的相容替代閉包。已預告12/1的修補版不是今天已發布且已封入的候選。不等待這些外部條件才能交本批安全工具／文件，但它們仍阻擋正式出貨。沒有公開發行或換裝使用者手機。
