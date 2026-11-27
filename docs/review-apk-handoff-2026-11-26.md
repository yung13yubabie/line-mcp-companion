# Review APK 交付與設備驗收（2026-11-26）

本輪接續未合併 PR #11 head `79f791719a6d7b2c89b7ba374c6f137cae04f8d8`。該 head 的 Security45834425711／Android45834425832 仍為成功，artifact15124517109未過期；來源為同tree的 `f1b69091e7d9f0072e0a5b6fc320ad71bb3a0190`。新變更只補只讀交付檢查，不更換 runtime、版本、簽章設定，不安裝或卸載。

## 已確認的簽章缺口

| 輸入 | versionCode | 公開 signer SHA-256 |
| --- | --- | --- |
| 原 #11 artifact15103578619 | 5 | `032c8b839478924d89f03c26da668289ab1d24b348cc2d5cb0894bb197fde046` |
| head79 artifact15124517109 | 5 | `5de076edcbe627b325814a8e08ed024db98fd3fc988b6d7286fef9fbe9443113` |

兩組都是 `tw.linemcp.app.review`、0.3.1-review，含arm64-v8a與x86_64各自APK。不同signer且versionCode沒有前進，不能被本交付流程標為原地升級候選。先前已驗簽與ZIP/ELF/native gate的結果仍有效，但不是安裝或升級驗收。完整原包hash與native證據見 [封裝覆核](native-apk-packaging-review-2026-11-26.md)。

[Android官方簽章說明](https://developer.android.com/studio/publish/app-signing#considerations) 將更新身分與簽章連續性相連；[版本說明](https://developer.android.com/studio/publish/versioning) 區分整數versionCode與顯示用versionName。本工具採更保守的「versionCode必須嚴格前進」升級測試準備條件，不把同版重裝當升級。這不是宣稱Android一般禁止同版重裝。

## 只讀工具

工具只使用呼叫者明確指定、已核對來源的官方 Build Tools；既有CI使用35.0.0。只有 `apksigner verify` 和 `aapt dump badging`，沒有sign、keytool、adb、安裝、卸載或雲端裝置呼叫。APK來源身分仍須先綁定可信的固定提交／artifact SHA-256；有效的自簽憑證本身不證明publisher、程式安全或來源。

```bash
python3 scripts/review-apk.py inspect \
  --build-tools "$ANDROID_HOME/build-tools/35.0.0" \
  --apk candidate-review.apk --report candidate-review.json

python3 scripts/review-apk.py compare \
  --build-tools "$ANDROID_HOME/build-tools/35.0.0" \
  --baseline previous-review.apk --candidate candidate-review.apk \
  --report comparison.json
```

inspect重新驗簽、雜湊與manifest，限精確Review package、單ABI與單一明確current signer；它的upgrade_decision必須是not_assessed。compare直接重新驗兩個實際APK，不相信輸入JSON。只有相同package／ABI／signer且versionCode嚴格上升，才能得到 `eligible_for_authorized_isolated_upgrade_test`；簽章不同、降版、同版、模糊／缺失資料均blocked並非零退出。合法簽章rotation lineage不在此工具支援範圍，不能以不同signer自動批准。

工具不查裝置上已安裝的套件，也不證明baseline檔案對應目前安裝狀態。eligible只代表兩個指定檔案的保守metadata條件成立，**不是已授權安裝、升級成功、資料保留、runtime相容或正式出貨**。正向decision的合成fixture僅驗證判斷邏輯，不冒充真APK升級或真機驗收。實際CLI驗證與拒絕結果另留於 `review-work/apk-handoff-20261126/`。安全的report路徑會在檢查前及失敗時原子更新為blocked；若路徑不安全（例如指向輸入APK或工具），只輸出blocked並非零退出，不為寫收據覆蓋受保護檔案。任何非零exit都不得沿用舊passed收據，不能只看原有JSON。

現有 Android-review 在原 assembleReview 之後逐ABI產生receipt，和APK、source-commit、SHA256SUMS、native-linkage／zipalign／signature報告放在同一artifact。workflow權限不變，仍contents:read。這沒有解決長期Review signer連續性。本工具及本機inspect/compare不讀取、建立、持久化、替換或傳送簽章金鑰，只讀APK內的公開憑證；既有CI仍沿原Review簽章流程，沒有新增或變更金鑰管理，簽章可能不連續。

## 不可替代的設備驗收

目前Codex環境沒有已授權且可用的隔離Android裝置入口；沒有android/adb/gcloud/firebase CLI可用於現成裝置連線。未重跑#12，未預約／上傳外部裝置服務，也未使用雲端裝置額度。以下順序是未執行的清單：

1. 固定測試APK提交、SHA-256、package、版本、ABI與公開signer。先核實授權專用測試機、API／ABI／頁面大小與空白或純合成資料；不接觸使用者手機、真LINE帳號、聊天或其他App私有資料。
2. 正常安裝與冷啟動，記錄此App的畫面、程序及受限診斷。只經正常支援介面加入合成資料；若無可用介面，空結果就是空結果，不植入私有資料庫。
3. 以正常UI配置自有本機MCP，驗服務身分、唯讀工具與預設權限；204或程序存在不代表認證／工具成功。不得把key或token放進公開收據。
4. 背景／前景，再獨立驗App程序停止與重啟後的合成狀態。這不能代替整機重啟。
5. 另驗受支援、已授權測試機的整機重啟與重連後狀態；不支援就保留未測，不刷機、不改全域屬性或繞過平台限制。
6. 真正16 KiB原生通過另需相同APK雜湊、ABI、實際 `getconf PAGE_SIZE` 為 `16384`，以及此App page-size compatibility mode **關閉**的可核對證據，再跑正常流程。只可開啟、沒警告、ZIP／ELF對齊或合成fixture都不足。[官方16 KiB指南](https://developer.android.com/guide/practices/page-sizes)
7. 真正原地升級還需可信的baseline、持續簽章／可核對版本前進、實際資料保留與重啟驗證。現在的不同Review signers不具備該條件；不藉卸載清除既有資料來冒稱升級成功。

本輪仍未完成裝置安裝／冷啟動、背景／前景、CA/TLS、SQLite、本機MCP、App與整機重啟、升級資料保留及16 KiB原生執行。OpenSSL3.6.5／Node Android support與正式簽章的既有阻擋也未解除。PR #11不合併，不發tag或Release。

## 本機可完成的結果

新工具15項合成測試與獨立34項檢查皆通過；正向eligible分支只有合成wrapper測試。主線另透過CLI與官方工具實際核對四份既有APK，全部inspect exit0；兩ABI原包→head79包的compare都exit1，明列signer_mismatch與version_not_advanced。實包比較成功指正確拒絕，不是升級成功。新固定提交仍需既有CI真編譯與其實際APK收據再核，完成後結果放PR #11。
