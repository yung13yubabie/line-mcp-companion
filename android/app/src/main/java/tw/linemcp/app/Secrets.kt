package tw.linemcp.app

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * 所有秘密都放在 EncryptedSharedPreferences（主金鑰在 Android Keystore，AES-256-GCM，不可匯出）。
 *  - control_token / mcp_token：本機 API 的 Bearer token
 *  - data_key：32-byte 資料金鑰；Node 用它以 AES-GCM 加密 SQLite 裡的 LINE token / E2EE 金鑰。
 *    只在啟動 Node 時經環境變數傳入（Node 讀完立即刪除），不會以明文寫到任何檔案。
 *  - ai_key：使用者自己的 AI API key（選用）
 * 注意：這些呼叫會碰 Keystore，很慢，一律在背景執行緒呼叫。
 */
object Secrets {
    @Volatile private var cached: android.content.SharedPreferences? = null
    private fun prefs(ctx: Context) = cached ?: synchronized(this) {
        cached ?: EncryptedSharedPreferences.create(
            ctx, "secrets",
            MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ).also { cached = it }
    }

    private fun random(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }

    private fun token(ctx: Context, key: String): String {
        val p = prefs(ctx)
        p.getString(key, null)?.let { return it }
        val t = random(24).joinToString("") { "%02x".format(it) }
        p.edit().putString(key, t).commit()
        return t
    }

    fun controlToken(ctx: Context) = token(ctx, "control_token")
    fun mcpToken(ctx: Context) = token(ctx, "mcp_token")
    fun setMcpToken(ctx: Context, t: String) { prefs(ctx).edit().putString("mcp_token", t).commit() }

    fun dataKeyB64(ctx: Context): String {
        val p = prefs(ctx)
        p.getString("data_key", null)?.let { return it }
        val k = Base64.encodeToString(random(32), Base64.NO_WRAP)
        p.edit().putString("data_key", k).commit()
        return k
    }

    fun aiKey(ctx: Context): String? = prefs(ctx).getString("ai_key", null)
    fun setAiKey(ctx: Context, k: String?) {
        prefs(ctx).edit().apply { if (k.isNullOrBlank()) remove("ai_key") else putString("ai_key", k.trim()) }.commit()
    }
}
