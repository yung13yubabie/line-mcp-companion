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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        if (proc == null) thread(name = "node-supervisor") { supervise() }
        return START_STICKY
    }

    private fun supervise() {
        while (!stopping) {
            try {
                val node = File(applicationInfo.nativeLibraryDir, "libnode.so")
                val appDir = extractNodeApp()
                val pb = ProcessBuilder(node.absolutePath, File(appDir, "main.mjs").absolutePath)
                    .directory(appDir)
                    .redirectErrorStream(true)
                pb.environment().apply {
                    // libnode.so 若依賴 libc++_shared.so 等，放在同一個 nativeLibraryDir
                    put("LD_LIBRARY_PATH", applicationInfo.nativeLibraryDir)
                    put("LINE_MCP_HOME", filesDir.absolutePath)
                    put("LINE_MCP_PORT", "47823")
                    put("LINE_MCP_TOKEN", Secrets.mcpToken(this@NodeService))
                    put("LINE_CONTROL_PORT", "47824")
                    put("LINE_CONTROL_TOKEN", Secrets.controlToken(this@NodeService))
                    put("HOME", filesDir.absolutePath)
                    put("TMPDIR", cacheDir.absolutePath)
                }
                val p = pb.start().also { proc = it }
                val logFile = File(filesDir, "node.log")
                if (logFile.length() > 2_000_000) logFile.delete()
                logFile.appendText("--- start ${System.currentTimeMillis()} ---\n")
                p.inputStream.bufferedReader().forEachLine {
                    Log.i("node", it)
                    logFile.appendText(it + "\n")
                }
                Log.w("node", "exited ${p.waitFor()}")
            } catch (e: Exception) {
                Log.e("node", "failed to start", e)
            }
            proc = null
            if (!stopping) Thread.sleep(30_000)
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
