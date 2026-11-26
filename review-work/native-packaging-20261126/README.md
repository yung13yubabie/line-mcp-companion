# 封裝覆核證據

本目錄區分固定舊APK、合成拒絕測試、作者回歸與獨立靜態覆核。未有Android或真機執行。

`independent-cases.py` 是獨立審計的靜態實驗原稿，不是CI入口。重跑需先核對文件中的固定APK雜湊，僅將其 `lib/{ABI}/*.so` 提取到已忽略的 `build/audit/elfs/{ABI}/`。腳本只讀取這些自有檔案並在記憶體變更metadata，不執行或載入ELF。結果應查 `build/audit/independent-patch-cases.json` 的 passed=total=23 與source hash穩定欄，不能只看程序exit。正式native回歸入口仍為 `python3 test/native-runtime.test.py`，失敗會非零退出。

原fixed source是e1b25d2d／artifact merge ec7acc84。新修補的真實CI輸出與APK須從PR #11的新固定提交另核，不能用本目錄舊APK收據冒充。
