package tw.linemcp.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.util.Log
import java.io.File
import kotlin.concurrent.thread

/**
 * Foreground Service：執行內嵌的 Node 24（libnode.so = 為 Android arm64 編好的 node 執行檔）
 * 跑 assets/nodeapp/main.mjs（由 ../ 的 TypeScript 用 esbuild/bun 打包）。
 * Node 掛了就 30 秒後重啟。
 */
class NodeService : Service() {
    @Volatile private var proc: Process? = null
    @Volatile private var stopping = false
    @Volatile private var started = false
    @Volatile private var restartSoon = false

    companion object { const val ACTION_RESTART = "tw.linemcp.app.RESTART_NODE" }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) android.os.StrictMode.setThreadPolicy(android.os.StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        // 越早呼叫越好：Android 要求 startForegroundService 後 5 秒內 startForeground
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_RESTART) { restartSoon = true; proc?.destroy() }
        if (!started) { started = true; thread(name = "node-supervisor") { supervise() } }
        return START_STICKY
    }

    private fun supervise() {
        while (!stopping) {
            try {
                val node = File(applicationInfo.nativeLibraryDir, "libnode.so")
                val appDir = extractNodeApp()
                // Use Node's bundled CA roots; the packaged runtime has no Termux-prefix CA store.
                val pb = ProcessBuilder(node.absolutePath, "--use-bundled-ca", File(appDir, "main.mjs").absolutePath)
                    .directory(appDir)
                    .redirectErrorStream(true)
                pb.environment().apply {
                    // libnode.so 若依賴 libc++_shared.so 等，放在同一個 nativeLibraryDir
                    put("LD_LIBRARY_PATH", applicationInfo.nativeLibraryDir)
                    put("LINE_MCP_HOME", filesDir.absolutePath)
                    put("LINE_MCP_PORT", BuildConfig.MCP_PORT.toString())
                    put("LINE_CONTROL_PORT", BuildConfig.CONTROL_PORT.toString())
                    put("LINE_CONNECTOR_PORT", BuildConfig.CONNECTOR_PORT.toString())
                    // secreview SR-07：秘密改經 stdin 傳入（環境變數即使在 Node 端 delete，仍留在 /proc/<pid>/environ）
                    put("LMA_SECRETS_STDIN", "1")
                    // H-1：控制 API 只接受 HMAC 簽章請求（UI 從不送 Bearer）
                    put("LMA_CONTROL_HMAC_ONLY", "1")
                    put("HOME", filesDir.absolutePath)
                    VariantFeatures.configureEnvironment(this@NodeService, this)
                    put("TMPDIR", cacheDir.absolutePath)
                    // bionic 下 Node 讀不到系統時區（實測 Etc/Unknown），由 Java 傳入
                    put("TZ", java.util.TimeZone.getDefault().id)
                }
                val secrets = org.json.JSONObject()
                    .put("mcp_token", Secrets.mcpToken(this@NodeService))
                    .put("control_token", Secrets.controlToken(this@NodeService))
                    .put("data_key", Secrets.dataKeyB64(this@NodeService))
                    .apply { Secrets.aiKey(this@NodeService)?.let { put("ai_key", it) } }
                val p = pb.start().also { proc = it }
                p.outputStream.use { it.write((secrets.toString() + "\n").toByteArray(Charsets.UTF_8)) }
                val log = BoundedNodeLog(File(filesDir, "node.log"))
                log.append("--- start ${System.currentTimeMillis()} ---\n".toByteArray(Charsets.UTF_8))
                p.inputStream.use { input ->
                    val chunk = ByteArray(4096)
                    while (true) {
                        val count = input.read(chunk)
                        if (count < 0) break
                        if (count > 0) log.append(chunk, count)
                    }
                }
                Log.w("node", "exited ${p.waitFor()}")
            } catch (e: Exception) {
                Log.e("node", "failed to start", e)
            }
            proc = null
            if (!stopping) { Thread.sleep(if (restartSoon) 500 else 30_000); restartSoon = false }
        }
    }

    /** 每次版本更新時把 assets/nodeapp 複製到 filesDir（node 需要真實檔案路徑）。 */
    private fun extractNodeApp(): File {
        // 以安裝時間當版本：每次重新安裝 APK 都會重新解出 main.mjs
        val stamp = packageManager.getPackageInfo(packageName, 0).lastUpdateTime
        val dest = File(filesDir, "nodeapp-$stamp")
        if (File(dest, ".done").exists()) return dest
        filesDir.listFiles { f -> f.name.startsWith("nodeapp-") }?.forEach { it.deleteRecursively() }
        dest.mkdirs()
        assets.list("nodeapp")?.forEach { name ->
            assets.open("nodeapp/$name").use { i -> File(dest, name).outputStream().use { i.copyTo(it) } }
        }
        File(dest, ".done").writeText("ok")
        return dest
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("sync", "同步", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, "sync")
            .setContentTitle("LINE MCP 同步中")
            .setContentText("MCP 只在本機 127.0.0.1 提供")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .build()
    }

    override fun onDestroy() {
        stopping = true
        proc?.destroy()
        super.onDestroy()
    }
}
