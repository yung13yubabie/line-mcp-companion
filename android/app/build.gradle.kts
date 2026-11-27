import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "tw.linemcp.app"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    defaultConfig {
        applicationId = "tw.linemcp.app"
        minSdk = 29          // Android 10+
        targetSdk = 35
        versionCode = 5
        versionName = "0.3.1"
        buildConfigField("int", "MCP_PORT", "47823")
        buildConfigField("int", "CONTROL_PORT", "47824")
        buildConfigField("int", "CONNECTOR_PORT", "47825")
    }
    // 正式簽章：keystore 放在 repo 外（預設 ../../../keys/release.jks，密碼在權限 0600 的檔案）。
    // 可用環境變數 LMA_KEYSTORE / LMA_KEYSTORE_PASS_FILE 覆寫；release 任務另有 fail-closed 驗證。
    val ksFile = file(System.getenv("LMA_KEYSTORE") ?: "${rootDir}/../../keys/release.jks")
    val ksPassFile = file(System.getenv("LMA_KEYSTORE_PASS_FILE") ?: "${rootDir}/../../keys/keystore.pass")
    val releaseKeyAlias = System.getenv("LMA_KEY_ALIAS") ?: "lma-release"
    signingConfigs {
        if (ksFile.exists() && ksPassFile.exists()) {
            create("release") {
                val pass = ksPassFile.readText().trim()
                storeFile = ksFile
                storePassword = pass
                keyAlias = releaseKeyAlias
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
        create("review") {
            initWith(getByName("release"))
            applicationIdSuffix = ".review"
            versionNameSuffix = "-review"
            buildConfigField("int", "MCP_PORT", "47833")
            buildConfigField("int", "CONTROL_PORT", "47834")
            buildConfigField("int", "CONNECTOR_PORT", "47835")
            resValue("string", "app_name", "LINE MCP Review")
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += listOf("release")
            // A separate package with production behavior; never enable the mock/debug surface.
            isDebuggable = false
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
    packaging {
        jniLibs {
            useLegacyPackaging = true
            // These prebuilt artifacts are already stripped and content-locked.
            keepDebugSymbols += "**/*.so"
        }
    }

    val verifyReleaseSigning = tasks.register("verifyReleaseSigning") {
        group = "verification"
        description = "Require the intended release signer before packaging a release APK."
        doLast {
            if (!ksFile.isFile || !ksFile.canRead() || !ksPassFile.isFile || !ksPassFile.canRead()) {
                throw GradleException("Release signing requires readable LMA_KEYSTORE and LMA_KEYSTORE_PASS_FILE; use assembleReview for a separately signed review APK.")
            }
            for (secretFile in listOf(ksFile, ksPassFile)) {
                if (Files.getFileStore(secretFile.toPath()).supportsFileAttributeView("posix")) {
                    val permissions = Files.getPosixFilePermissions(secretFile.toPath())
                    if (permissions.any { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") }) {
                        throw GradleException("Release signing files must be accessible only to their owner.")
                    }
                }
            }
            val pass = ksPassFile.readText().trim().toCharArray()
            try {
                if (pass.isEmpty()) throw GradleException("Release signing password is empty.")
                val keyStore = KeyStore.getInstance(ksFile, pass)
                if (!keyStore.isKeyEntry(releaseKeyAlias)) throw GradleException("Release signing key alias is missing.")
                val certificate = keyStore.getCertificate(releaseKeyAlias)
                    ?: throw GradleException("Release signing certificate is missing.")
                val fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) }
                val expected = (System.getenv("LMA_SIGNER_SHA256")
                    ?: "75E72FE9BC01B9E89F78A9425312581C1D4DAA92E9CBE21463F8761897ECA90A")
                    .replace(":", "").lowercase()
                if (!Regex("[0-9a-f]{64}").matches(expected) || fingerprint != expected) {
                    throw GradleException("Release signing certificate does not match LMA_SIGNER_SHA256.")
                }
            } finally { pass.fill('\u0000') }
        }
    }
    tasks.configureEach {
        if (name == "preReleaseBuild" || name == "validateSigningRelease" || name == "packageRelease" || name == "assembleRelease" || name == "bundleRelease") {
            dependsOn(verifyReleaseSigning)
        }
    }
}

val verifyNativeRuntime = tasks.register<Exec>("verifyNativeRuntime") {
    group = "verification"
    description = "Reject missing, unreviewed, or changed native runtime bytes."
    commandLine("python3", rootProject.file("../scripts/node-android/native-runtime.py"), "verify")
}
val verifyProductionBundle = tasks.register<Exec>("verifyProductionBundle") {
    group = "verification"
    description = "Require a nonempty production bundle with mock data removed."
    commandLine("bash", rootProject.file("../scripts/purge-mock-check.sh"), file("src/main/assets/nodeapp/main.mjs"))
}
val verifyProductionRuntime = tasks.register<Exec>("verifyProductionRuntime") {
    group = "verification"
    description = "Reject a production release until native runtime blockers are resolved and reviewed."
    commandLine("python3", rootProject.file("../scripts/node-android/native-runtime.py"), "verify", "--production")
}
tasks.configureEach {
    if (name == "preBuild") dependsOn(verifyNativeRuntime)
    if (name == "preReleaseBuild" || name == "preReviewBuild") dependsOn(verifyProductionBundle)
    if (name == "preReleaseBuild" || name == "packageRelease" || name == "assembleRelease" || name == "bundleRelease") {
        dependsOn(verifyProductionRuntime)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")        // 把 LINE QR URL 畫成 QR 圖
    implementation("androidx.security:security-crypto:1.1.0") // token / 資料金鑰加密保存
    implementation("androidx.biometric:biometric:1.1.0")                // 顯示 / 複製 token 前驗證本人
    implementation("androidx.fragment:fragment-ktx:1.8.5")
}
