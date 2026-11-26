# Native runtime 支援與發布政策覆核（2026-11-26）

基準：合併後 main `44a0e7452f89e8af569bf4213c606d5eca1968cf`。本輪在獨立 native checkout 開發，沒有改動 MCP 程式、原生 binaries、native lock、workflow 權限或發布狀態。所有新增測試使用合成 metadata／ELF fixture 及既有公開簽署 snapshot；沒有執行 Android binaries、真 LINE 登入／資料或外部主動測試。

## 官方來源與替換判斷

- [Termux 官方 OpenSSL 配方](https://github.com/termux/termux-packages/blob/8e1eeb821248696f7967c08aa2f7e6d464f5a531/packages/openssl/build.sh) 在本次查核的 master commit `8e1eeb821248696f7967c08aa2f7e6d464f5a531` 仍選 `1:3.6.5`；[Node LTS 配方](https://github.com/termux/termux-packages/blob/8e1eeb821248696f7967c08aa2f7e6d464f5a531/packages/nodejs-lts/build.sh) 選 `24.22.3`，使用 shared OpenSSL、c-ares、ICU、SQLite、zlib 等相依。本輪沒有取得另一套已完成來源、ABI、符號與裝置覆驗的可替換 binary。
- [OpenSSL 官方維護策略](https://openssl-library.org/policies/releasestrat/) 列出 3.5 LTS 至 2030-04-08，4.0 至 2027-05-14，4.1 至 2027-11-23；[3.6 EOL 公告](https://openssl-library.org/post/2026-11-01-eol34-36/) 維持既有阻擋。
- [2026-11-24 官方公告](https://openssl-library.org/news/secadv/20261124.txt) 明確表示包含修補的 releases 預定 **2026-12-01**，建議 3.5.10／4.0.4／4.1.1。**在本次 11 月 26 日覆核時，不能把公告列出的版本當作已取得及驗過的替換產物。** 公告與生命週期風險不等於本 App 已可達利用；本輪沒有做漏洞重現。
- [Node 官方時程](https://github.com/nodejs/Release/blob/main/schedule.json) 的 Node 24 EOL 是 2028-04-30；[Node v24.22.3 BUILDING.md](https://github.com/nodejs/node/blob/v24.22.3/BUILDING.md) 說明平台支援與 Android 建置限制。Linux arm64 的官方 binary 不能直接當成 Android／bionic 產物。Node 主版本仍受支援，不能推論其所有 shared libraries 或下游 Android build 都已驗收。

OpenSSL 4 與目前的 `.so.3` inventory、依賴符號及 repack mapping 不相容，不能只改檔名或換 major。3.5 的 branch 維護狀態也不能證明已用 3.6 headers 建置的 Node 可直接降換 shared library。本輪因此**保留原 runtime 並維持 NO-GO**，交付可驗收的 gate 改善。

## 實作：把維護判斷與批准布林分開

原 `verify_policy` 只要求 `production_ready` 為布林、blockers 為 list；把前者改 true 並清空 blockers，會使原 EOL runtime 通過該 production gate。這是防誤配置／政策完整性的 confirmed 缺口；有修改原碼能力的維護者仍可改 gate，沒有宣稱此檢查能對抗 repo 管理者。

現在 production 必須同時滿足：

1. Node／OpenSSL package manifest 各完整列出 aarch64 與 x86_64，Architecture 與 indexArch 一致，無缺漏／重複，同 component 版本一致；Node 與 top-level node_version 一致。只解析 stable 版本及數字 Debian revision，預發布／未知格式拒絕。
2. 目前相容政策只允許候選 OpenSSL 3.5 branch，patch floor 為 3.5.10，且不早於公告的 2026-12-01。EOL 3.6 與未覆驗的其他 major／branch 不能沿用 ready 批准。此為保守的必要條件，**不是 3.5.10 的可用性、相容性或獨立批准證明**。
3. Node 24 與 OpenSSL 3.5 維護期限仍有效，官方 lifecycle／advisory review 日期必須在 2026-11-26 至 2026-12-26。這是 30 天內需重新查核的上限，不是自動 CVE 掃描或保證該期間無新公告。
4. production 的 signed snapshot 不超過 30 天且不在未來（以 UTC 時刻比較，非僅日期）。`snapshot_date` 不能自行換成新日期：`verify_provenance` 在 GPG 驗簽後要求它與 InRelease 的唯一 Date header 為相同 UTC 時刻。
5. `production_ready` 與 unresolved blockers 的原有拒絕條件仍保留。`main --production` 在任何 prepare／verify／verify-apk 動作前均重新驗 GPG → snapshot indices → package metadata，不能讓驗證既有 cached output 的正式流程省略 source metadata 驗證。

現有輸出 hash、精確 ELF／ABI／授權 inventory、16 KiB alignment、Maven baseline 與正式簽章檢查不放寬。Review prepare／verify 在鎖定輸入上可繼續使用，不會把 lifecycle 測試的合成正例包進 APK。

## 測試與原始證據

- `review-work/native-policy-20261126/before.txt`：同一個安全期望（修改 approval 布林與清空 blocker 仍應拒絕 EOL）在 baseline 失敗，exit 1。
- `review-work/native-policy-20261126/after-initial.txt`：首次修補 30/31；唯一失敗為原測試要求既有 OPENSSL_36_EOL 診斷碼，新增 branch gate 先拋另一碼。已保留原碼並對 3.6 同時回報既有 EOL 與 branch 診斷，沒有刪除安全期望。
- `review-work/native-policy-20261126/after.txt`：43/43，0 failed／skipped，exit 0。新增情境涵蓋 approval 變更、預告修補尚未發布、patch floor、未知／EOL branch、維護查核過期、clock rollback、snapshot 過期／同日未來秒數／無 timezone、雙 ABI 缺漏／重複／upstream 與 Debian revision 不一致、prerelease 版本、signed Date 偽裝與 production main CLI 重查 source metadata。
- 合成 3.5.10 fixture 只在明確的測試日期進行 lifecycle 正例；它不符合目前 signed Termux index，走 production CLI 會因 package metadata 不符而拒絕，沒有形成任何可接受的 Android runtime。
- `production-cli.txt` 保留當前真入口 `python3 scripts/node-android/native-runtime.py verify --production` 的實際 exit 1，因 OPENSSL_36_EOL／OPENSSL_BRANCH_UNSUPPORTED 拒絕。沒有執行真正正式建置。

## 解除 native NO-GO 的門檻

需另取得已發布且修補狀態核實的來源，固定 archive／source commit／toolchain／patch hashes；從正確 headers 重建 Node 與整組相依或取得可信、完整且相容的雙 ABI package sets。需重新產生、獨立核對 ELF／symbols／dependencies／notices 及來源簽章，驗證 Android API 29+ 與 4 KiB／16 KiB 頁面、CA/TLS 正負向、node:sqlite、啟動／背景／重啟行為。裝置驗證只使用合成資料及本地受控端點，不需要真 LINE 或敏感憑證。

只有上述證據完成、政策查核刷新、獨立 reviewer 核對後才可提出 runtime／lock 的後續 PR；本輪不變更 native 批准、tag、Release 或 main。
