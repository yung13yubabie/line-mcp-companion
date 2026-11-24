package tw.linemcp.app

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/** 控制 API / MCP 的隨機 token，以 Android Keystore 加密保存。 */
object Secrets {
    private fun prefs(ctx: Context) = EncryptedSharedPreferences.create(
        ctx, "secrets",
        MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private fun token(ctx: Context, key: String): String {
        val p = prefs(ctx)
        p.getString(key, null)?.let { return it }
        val b = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val t = b.joinToString("") { "%02x".format(it) }
        p.edit().putString(key, t).apply()
        return t
    }

    fun controlToken(ctx: Context) = token(ctx, "control_token")
    fun mcpToken(ctx: Context) = token(ctx, "mcp_token")
}
