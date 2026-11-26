# Android 建置、原生來源與發布限制

這一版的可交付目標是 **0.3.1-review 審查 APK**。正式 `release` 目前由建置流程主動阻擋：鎖定的 Termux runtime 含 OpenSSL 3.6.5，而 OpenSSL 3.6 已於 2026-11-01 結束公開維護。驗證下載來源與雜湊只能確認使用了預定的檔案，不能證明它們沒有漏洞。

## 建置環境

目前原生重打包支援 Linux x86_64 主機，單獨執行 `scripts/node-android/native-runtime.py` 需 Python 3.9+、GnuPG、`dpkg-deb`、`readelf`、Bash、`unzip`。CI 的工具安裝程式 `scripts/ci-tools.py` 使用 `tarfile` 的安全解壓 filter，請使用 Python 3.12+；目前 workflow 使用 Ubuntu 24.04 runner。兩個 Python 程式都使用標準函式庫，不需要 `pip install`。Node 須符合 `package.json` 的 engines；本次 bundle 使用 Bun 1.4.5。Android 需 JDK 17 或相容更新版、Android SDK Platform 35、Build Tools 35.0.0。本次編譯環境使用 JDK 21。

設定 `JAVA_HOME`、`ANDROID_HOME`，將 Node、npm、Bun 與 JDK 放入 `PATH`。SDK 的安裝位置亦可寫入不納入版本控制的 `android/local.properties`。不要把 SDK、keystore 或密碼加入 Git。

Gradle wrapper 已固定為 8.14.8。執行 wrapper 前可核對：

| 項目 | SHA-256 |
| --- | --- |
| `gradle-8.14.8-bin.zip` | `94da89692fc3ca6d2d0ce6bb48548762ea0f1897ba444286f5c7f3759c7af651` |
| `android/gradle/wrapper/gradle-wrapper.jar` | `ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0` |

雜湊來源為 [Gradle 官方 release checksums](https://gradle.org/release-checksums/)。distribution 雜湊也寫入 `gradle-wrapper.properties`，下載不符時 wrapper 會失敗。Gradle 外掛與 Maven 相依套件仍需另外做版本與安全公告檢查；wrapper 校驗不涵蓋整棵 JVM 相依樹。

## 建立審查版

以下從 repo 根目錄執行。所有回歸測試都使用本機或合成資料，不需要真實 LINE token 或 AI API key。

```bash
npm ci --ignore-scripts
npm run typecheck
npm test
python3 test/native-runtime.test.py
python3 scripts/node-android/native-runtime.py prepare
npm run bundle:android:release
cd android
./gradlew --no-daemon clean :app:assembleReview
```

`prepare` 下載固定版本的公開 `.deb` 與 patchelf，對照已提交的簽章資料和雜湊後，只抽取 package data，不執行 Debian maintainer scripts。預設快取在 repo 內已忽略的 `build/native-runtime`；可用 `--work /absolute/cache/path` 指定其他位置。既有 `scripts/android-libnode.sh` 與 `scripts/node-android/termux-repack.sh` 都轉交同一個驗證流程，不再接受任意資料夾的 `.so` 備案。

預期輸出為：

- `android/app/build/outputs/apk/review/app-arm64-v8a-review.apk`
- `android/app/build/outputs/apk/review/app-x86_64-review.apk`

實際輸出名稱與版本須以該次 Gradle `output-metadata.json` 核對。完成 build 後，回到 repo 根目錄，對兩個 APK 分別執行：

```bash
for apk in android/app/build/outputs/apk/review/*.apk; do
  python3 scripts/node-android/native-runtime.py verify-apk --apk "$apk"
  bash scripts/purge-mock-check.sh "$apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --verbose --print-certs "$apk"
  sha256sum "$apk"
done
```

APK 驗證要求 native inventory、每個 ELF 的 SHA-256、ABI 與 APK 內的 provenance lock 全部一致，並拒絕重複 ZIP entry。每個 split APK 必須恰有 10 個 Node runtime ELF 與 1 個已核對的 AndroidX ELF；其他未知 `.so` 仍拒絕。清除 mock gate 對缺檔、空檔及讀取失敗一律回傳失敗。成功產出 APK 尚未證明 Android 程序啟動、LINE 同步或 AI 連線已通過真機驗證；這些結果須另留實測證據。

## 審查版與正式版的差異

| 項目 | `review` | `release` |
| --- | --- | --- |
| Application ID | `tw.linemcp.app.review` | `tw.linemcp.app` |
| 畫面名稱 | LINE MCP Review | LINE MCP |
| 版本 | 0.3.1-review / versionCode 5 | 0.3.1 / versionCode 5 |
| MCP / Control / Connector ports | 47833 / 47834 / 47835 | 47823 / 47824 / 47825 |
| 簽章 | 建置環境的 Android debug key | 指定且指紋相符的正式 key |
| Debuggable / Mock | false / 排除 | false / 排除 |
| 原生正式發布審核 | 允許產出審查 artifact | 目前阻擋 |

審查版繼承 release 的最佳化設定，`BuildConfig.DEBUG` 為 false。它使用不同 application ID 與 ports，因此可與原 App 並存；私有資料與 LINE 登入狀態也各自獨立。它不能直接覆蓋原 App，更不代表沿用原發布憑證。不同建置環境的 debug key 也可能不同，審查 APK 的後續更新須重新核對簽章。只以測試資料和專用測試帳號進行隔離驗證，不把這個 artifact 當成正式安全發布。

## 原生套件的信任鏈

`android/native-runtime.lock.json` 記錄 Node 24.22.3、套件版本、下載位置、package 雜湊、重打包工具與兩個 ABI 的輸出雜湊。Node runtime 共 20 個 ELF（每個 ABI 各 10 個），另外有 2 個 AndroidX ELF（每個 ABI 各 1 個），分別記錄於 `outputs` 與 `maven_native_artifacts`。`scripts/node-android/provenance/` 保留此次 2026-11-25 07:12:38 UTC 的公開 APT snapshot。

驗證順序如下：

1. 核對已提交的 Termux 公鑰、InRelease 與兩份 Packages.gz 的 SHA-256。
2. 以獨立 GnuPG home 和明確指定的 keyring 驗證 InRelease，要求簽署者 fingerprint 為 `CC72CF8BA7DBFA0182877D045A897D96E57CF20C`。
3. 對照簽章內的 SHA-256 驗證各架構的 Packages.gz，並核對每個選定 package 的版本、架構、檔名、大小與 SHA-256。
4. 下載並核對 `.deb` 的 SHA-256，再抽取資料。沿著 `DT_NEEDED` 收集 runtime 閉包，未知的非 Android 系統相依直接失敗。
5. 使用固定 SHA-256 的 patchelf 0.18.0 改寫相依名稱、SONAME 與 `$ORIGIN` 搜尋路徑。每次改寫明確指定 16 KiB page size。
6. 對照已審查的輸出雜湊，要求 arm64-v8a 與 x86_64 都存在。ELF 的每個 PT_LOAD 必須 `p_align >= 16384`，且 file offset 與 virtual address 對 16384 同餘。

Termux key 的公開來源是 [termux-packages 固定 commit](https://github.com/termux/termux-packages/tree/0e0d1929ab4047ce7407d881fa1b6ff421024640)，不是主機既有的私密 keyring。這個做法固定了此次信任來源，未宣稱驗證了 Termux 建置主機或從原始碼獨立重現其 binary。patchelf 的雜湊來自此次 [官方 0.18.0 release](https://github.com/NixOS/patchelf/releases/tag/0.18.0) 的下載核對，未取得額外的上游 detached signature。

### Maven 帶入的 AndroidX 原生 library

既有的 `androidx.graphics:graphics-path:1.0.1` 會由 Gradle 帶入 `libandroidx.graphics.path.so`。它不屬於 Node/Termux 閉包，來源另以 [Google Maven 官方 AAR](https://dl.google.com/dl/android/maven2/androidx/graphics/graphics-path/1.0.1/graphics-path-1.0.1.aar) 核對。AAR SHA-256 為 `8ca4032b6d79b351f0b59ad4b580eddbb9423e1652f7c958830687f1eee2ec03`，與 `android/gradle/verification-metadata.xml` 中的值一致。

| ABI | `libandroidx.graphics.path.so` SHA-256 |
| --- | --- |
| arm64-v8a | `41e9a793c43a0f4fddb19e33f346bace464f30f888ba7b9eaf96294ea115bfb6` |
| x86_64 | `4e56c996f13670e70082658de7880c4020eabf4f25e43387f88ed78a713fc9f0` |

`prepare` 會核對 AAR 整檔雜湊、各 ABI 的精確 native inventory、ELF 雜湊、機種與 16 KiB PT_LOAD 對齊，不把 AAR 的 library 再複製到 `jniLibs`，避免與 Gradle merge 重複。本機 `verify` 仍只要求每個 ABI 的 10 個 Node JNI 檔案；`verify-apk` 則要求 Node 與已核對 Maven library 的聯集全部存在且精確相符。原 inventory 曾漏列這個合法相依套件；修正的是完整來源清單，未知 ELF 的拒絕規則維持不變。

此次重打包已有兩次相同輸入得到相同 ELF bytes 的檢查。這不等於整個 APK 可逐位元重現：JDK、SDK、Gradle 相依、Bun、ZIP metadata 與簽章環境仍可能影響 APK。ELF 對齊檢查也不取代 Android 16 KB page 裝置上的啟動測試。

### 授權與 notices

APK 內 `assets/native-runtime/licenses/` 保留各套件的原文 notices，以及相同簽章 snapshot 中 `termux-licenses 2.2` 的共用授權文字。共用目錄是 Termux 的授權文字集合，個別套件採用的條款應以該套件 copyright/notice 判讀。為修補上游 package 的 notices 缺口，另外固定兩份官方來源：

- ICU 79.1：Termux package 的 LICENSE 只有 `404: Not Found`；改放 [官方 release commit 的完整 LICENSE](https://github.com/unicode-org/icu/blob/ddc6b66926bfac6036144ca9902992a0d6d50af9/LICENSE)。原文 SHA-256 為 `e09827667e0bb3c808b2a463548ba814a5e6249b67353234d70c8dfc2bcc417d`。
- libc++ 30：保留 Termux 的 NCSA notice，並加入 [官方 NDK r30 的完整 toolchain notices](https://android.googlesource.com/toolchain/prebuilts/ndk/r30/+/92537cd408ece74f1a3d0fe608932c14221e796e/NOTICE.toolchain)，含 LLVM exceptions 與歷史授權文字。其 SHA-256 為 `6b8633011d874b75629180e60de13ebfd546a10e56dc7d0380a35f6609f30617`。

這些補充原文保存在 provenance 目錄，來源與雜湊寫入 lock 的 `notice_overrides`。重打包後每一份授權檔另外列入 `license_outputs`；本機與 APK gate 都會拒絕缺檔、增加未知檔或內容不符。

## 正式發布的阻擋與解鎖條件

目前 lock 的 `production_ready` 為 false，阻擋代碼是 `OPENSSL_36_EOL`。[OpenSSL 官方 EOL 公告](https://openssl-library.org/post/2026-11-01-eol34-36/) 明確指出 3.6 已不再接收公開安全修補；[2026-11-24 安全公告](https://openssl-library.org/news/secadv/20261124.txt) 也明確說明沒有分析已停止維護的 3.6。不能把公告沒有列出 3.6 解讀成不受影響。本次未建立這些新公告在 App 中的可達利用路徑，因此不把該批 CVE 虛列為已確認的 App 遠端漏洞。

```bash
python3 scripts/node-android/native-runtime.py verify --production
```

這個命令目前必須失敗。Gradle 的正式 preReleaseBuild、packageRelease、assembleRelease、bundleRelease 皆依賴相同 gate。正常 release workflow 未提供專用略過參數，但有權修改原始碼或 Gradle 命令的人仍可刻意改變流程，因此必須搭配獨立審查與受保護的 CI，不能只修改 `production_ready`。之後需要更新為受支援且修補狀態已核實的 Android runtime，重新檢查 ABI、TLS/CA、SQLite、原生啟動與 4 KB / 16 KB 裝置行為，並由獨立審查者核對 evidence，才能修改 lock 的批准狀態；也不要把舊 OpenSSL library 換成未測試的另一個 major/minor 版本。

正式簽章另外要求 `LMA_KEYSTORE`、`LMA_KEYSTORE_PASS_FILE` 指向可讀檔案；POSIX 系統禁止 group/others 存取權。密碼不經 command line 傳入。可用 `LMA_KEY_ALIAS` 指定 alias（預設 `lma-release`）。建置會載入憑證並核對 SHA-256 fingerprint，預設為 repo 原有正式簽章指紋 `75E72FE9BC01B9E89F78A9425312581C1D4DAA92E9CBE21463F8761897ECA90A`，若有明確的簽署政策變更才設定 `LMA_SIGNER_SHA256`。正式私鑰缺失時不以新產生的 key 冒充原 key。

## 更新 lock 與原始碼建置

正常 CI 只跑 `prepare`，不能自動接受新的輸出雜湊。維護者更新 package snapshot 時，需先從官方來源取得並核對新的 key、簽章、index 與安全公告，再建立變更供審查。`prepare --record-output-hashes` 是明確的維護者操作，會更新待審查的 lock；它本身不代表核准，更不會清除 production blocker。

`scripts/node-android/build-node-android.sh` 保留從原始碼交叉編譯的調查入口，要求明確提供官方 Node 24.22.3 tar.xz 與 NDK r27d zip。Node 使用官方 SHA-256；NDK r27d 目前使用 Android SDK repository XML 公布的 SHA-1。腳本在核對 archive 後建立新的工作目錄，使用 repo 內的 patch，將輸出標記為 **NOT APPROVED**，不自動放入 APK。這條原始碼流程本次未完成實際編譯，不能當成已通過的替代 runtime。

本機回歸入口 `python3 test/native-runtime.test.py` 使用合成 ELF、合成 AAR 與已提交的公開簽章資料，檢查 30 個案例：簽章與 package 版本綁定、cache 竄改、缺少或多出 ABI/library、檔案及目錄 symlink、架構、16 KB 對齊與 offset、截斷 headers、APK provenance 與重複 entry、授權檔完整性、production approval，以及 Maven library 正例、竄改、漏檔、未知額外檔案與來源驗證。本機 Node JNI 與 Maven merge 的分工也有回歸案例。這些測試不執行 Android binary，也不連到 package server。

## 2026-11-26 接手覆核

本機 MCP 現在預設只讀；需要寫入工具時，在 App 設定的 MCP 連線區明確啟用，既有會話與確認 gate 仍生效。資料最小化、診斷限額與未完成的正式發布條件見 [本輪紀錄](security-followup-2026-11-26.md)。

## 原生 linkage 與16 KiB驗收

最終 APK 的 TLS provider、動態相依、RELRO、ZIP 對齊與實際工具鏈 note 必須分開核對；package version／補充授權文字不代表編譯 NDK。新增 report 與原固定產物的實測邊界見 [2026-11-26封裝覆核](native-apk-packaging-review-2026-11-26.md)。真正16 KiB裝置通過還需相同APK雜湊、ABI、`PAGE_SIZE=16384` 與此App相容模式關閉的證據；本輪裝置未測。
