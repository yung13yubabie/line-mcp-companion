plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "tw.linemcp.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "tw.linemcp.app"
        minSdk = 29          // Android 10+
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    // 正式簽章：keystore 放在 repo 外（預設 ../../../keys/release.jks，密碼在權限 0600 的檔案）。
    // 可用環境變數 LMA_KEYSTORE / LMA_KEYSTORE_PASS_FILE 覆寫。找不到就不簽（release 建置會失敗，不會退回 debug 金鑰）。
    val ksFile = file(System.getenv("LMA_KEYSTORE") ?: "${rootDir}/../../keys/release.jks")
    val ksPassFile = file(System.getenv("LMA_KEYSTORE_PASS_FILE") ?: "${rootDir}/../../keys/keystore.pass")
    signingConfigs {
        if (ksFile.exists() && ksPassFile.exists()) {
            create("release") {
                val pass = ksPassFile.readText().trim()
                storeFile = ksFile
                storePassword = pass
                keyAlias = "lma-release"
                keyPassword = pass
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true; buildConfig = true }
    // 每個 ABI 各出一個 APK：arm64-v8a（真機）、x86_64（模擬器）
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }
    // libnode.so 必須解壓到 nativeLibraryDir 才能 exec（Android 10+ W^X 限制）
    packaging { jniLibs { useLegacyPackaging = true } }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")        // 把 LINE QR URL 畫成 QR 圖
    implementation("androidx.security:security-crypto:1.1.0-alpha06") // token / 資料金鑰加密保存
    implementation("androidx.biometric:biometric:1.1.0")                // 顯示 / 複製 token 前驗證本人
    implementation("androidx.fragment:fragment-ktx:1.8.5")
}
