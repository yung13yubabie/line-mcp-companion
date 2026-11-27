# Review APK交付檢查證據

- synthetic-tests.txt：15項合成parser、decision、wrapper與檔案邊界測試，wrapper使用stub；不是APK簽章或裝置執行結果。
- actual-apk-comparisons.json：主線以指定官方BuildTools35.0.0直接執行新CLI，四份實際Review APK inspect成功；兩ABI原artifact15103578619→head79 artifact15124517109比較均非零blocked，原因同時為signer_mismatch及version_not_advanced。沒有真實正向升級候選或裝置升級測試。
- independent/：獨立34項檢查，歷史官方文字輸入與合成mock-wrapper清楚分開。before是新工具開發中的aggregate input validation gap，非已發布App漏洞或Android重現；after凍結source161df...並確認來源不變。

獨立實驗原稿固定sourcehash，非一般CI入口。重跑需先備妥已驗證的歷史官方reports於build/input/pr11/及build/audit/independent-new-ci/（各ABI的signature/package.txt）；腳本不下載、不簽章、不安裝或執行APK。標準可重跑unit入口為 python3 test/review-apk.test.py。

工具尚未實作時的TDD缺檔log僅留ignored build，不冒充既有產品的修前缺陷證據。本輪真實新CI與新APK結果另見PR #11固定提交與artifact；舊產物不可冒稱新建置。
