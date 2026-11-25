package tw.linemcp.app

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * 每 15 分鐘檢查一次本機服務還在不在；不在就重新啟動 Foreground Service。
 * Android 12+ 從背景啟動前景服務需要「忽略電池最佳化」豁免（設定頁有按鈕引導）。
 */
class KeepaliveWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val alive = runCatching {
            val c = URL("http://127.0.0.1:47824/control/state").openConnection() as HttpURLConnection
            c.connectTimeout = 2000; c.readTimeout = 2000
            c.responseCode // 401 也代表活著
            true
        }.getOrDefault(false)
        if (!alive) runCatching {
            val i = Intent(applicationContext, NodeService::class.java)
            if (Build.VERSION.SDK_INT >= 26) applicationContext.startForegroundService(i) else applicationContext.startService(i)
        }
        return Result.success()
    }
}

object Keepalive {
    fun schedule(ctx: Context) {
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("node-keepalive", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<KeepaliveWorker>(15, TimeUnit.MINUTES).build())
    }
}
