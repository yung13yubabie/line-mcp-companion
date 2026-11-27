package tw.linemcp.app

import android.content.Context
import java.io.File

/**
 * Mock 模式（僅 debug 建置）。資料在 filesDir/mock/，與真實 line.db 完全分開。
 * 此來源僅編入 debug source set；production/Review 不編入此類別。
 */
object MockMode {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("app", Context.MODE_PRIVATE)
    fun enabled(ctx: Context) = BuildConfig.DEBUG && prefs(ctx).getBoolean("mock_mode", false)
    fun set(ctx: Context, on: Boolean) { prefs(ctx).edit().putBoolean("mock_mode", on && BuildConfig.DEBUG).commit() }
    /** 完全清除 mock 資料（關閉 mock + 刪除 filesDir/mock） */
    fun purge(ctx: Context) {
        set(ctx, false)
        File(ctx.filesDir, "mock").deleteRecursively()
    }
}
