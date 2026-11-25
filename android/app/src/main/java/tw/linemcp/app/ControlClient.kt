package tw.linemcp.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class ControlError(val status: Int, val code: String, message: String) : Exception(message)

/** 呼叫 Node 端控制 API（src/control/server.ts）。全部在 Dispatchers.IO。 */
class ControlClient(private val token: String, private val base: String = "http://127.0.0.1:${BuildConfig.CONTROL_PORT}/control") {
    // secreview SR-01 / H-1：其他 App 可以搶先佔用 127.0.0.1:47824。先用 /hello 挑戰確認伺服器持有 token，
    // 請求本身也不帶 token（見 raw()）。
    private fun hmacHex(msg: String): String {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(token.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return m.doFinal(msg.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
    private fun nonce(): String = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
    private fun same(a: String?, b: String): Boolean = a != null && MessageDigest.isEqual(a.toByteArray(), b.toByteArray())

    /** 不帶 token 的身分挑戰；失敗代表連到的不是我們的 Node 服務 */
    private fun verifyServer() {
        val n = nonce()
        val c = URL("$base/hello").openConnection() as HttpURLConnection
        c.instanceFollowRedirects = false
        c.connectTimeout = 3000; c.readTimeout = 3000
        c.setRequestProperty("x-lma-nonce", n)
        val ok = runCatching { c.responseCode == 200 && same(c.getHeaderField("x-lma-proof"), hmacHex("hello:$n")) }.getOrDefault(false)
        runCatching { (if (c.responseCode < 400) c.inputStream else c.errorStream)?.close() }
        c.disconnect()
        if (!ok) throw ControlError(0, "server_untrusted", "本機服務身分驗證失敗：可能有其他 App 佔用了連接埠，已停止連線")
    }

    @Volatile private var verifiedAt = 0L
    private fun hmacBytes(msg: String): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(token.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return m.doFinal(msg.toByteArray(Charsets.UTF_8))
    }
    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /**
     * H-1 / N-05：不送 Bearer token。每個請求用一次性 HMAC 簽章（綁 nonce、時間、method、path、本體雜湊），
     * 本體用 AES-256-GCM 加密（金鑰由 token 與 nonce 推導）。冒牌伺服器拿不到 token、AI 金鑰或其他設定值。
     * 回應必須帶綁 nonce / method / path / status / 本體的 proof，否則丟棄。
     */
    private suspend fun raw(method: String, path: String, body: JSONObject? = null, timeoutMs: Int = 5000): Pair<Int, ByteArray> = withContext(Dispatchers.IO) {
        if (System.currentTimeMillis() - verifiedAt > 60_000) { verifyServer(); verifiedAt = System.currentTimeMillis() }
        val n = nonce()
        val u = URL(base + path)
        val fullPath = u.file // path + ?query，跟伺服器看到的 req.url 一樣
        val pathOnly = u.path
        val payload: ByteArray = if (body != null) {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(hmacBytes("body:$n"), "AES"), javax.crypto.spec.GCMParameterSpec(128, iv))
            cipher.updateAAD("$method:$pathOnly".toByteArray(Charsets.UTF_8))
            val ct = cipher.doFinal(body.toString().toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(iv + ct, android.util.Base64.NO_WRAP).toByteArray(Charsets.UTF_8)
        } else ByteArray(0)
        val ts = System.currentTimeMillis()
        val sig = hmacHex("req:$n:$ts:$method:$fullPath:${sha256Hex(payload)}")
        val c = u.openConnection() as HttpURLConnection
        c.instanceFollowRedirects = false
        c.requestMethod = method
        c.setRequestProperty("x-lma-nonce", n)
        c.setRequestProperty("x-lma-auth", "v1 $ts.$sig")
        c.connectTimeout = 3000
        c.readTimeout = timeoutMs
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("content-type", "application/octet-stream")
            c.setRequestProperty("x-lma-enc", "1")
            c.outputStream.use { it.write(payload) }
        }
        try {
            val code = c.responseCode
            // JSON、CSV、圖片都必須驗 body；不接受舊版的「只簽 header」降級。
            if (c.getHeaderField("x-lma-proof-body") != "1") {
                verifiedAt = 0
                throw ControlError(0, "server_untrusted", "本機服務回應缺少完整內容驗證，已停止連線")
            }
            if (c.contentLengthLong > MAX_RESPONSE_BYTES) throw ControlError(0, "response_too_large", "本機服務回應超過大小限制")
            val bytes = (if (code < 400) c.inputStream else c.errorStream)?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size().toLong() + count > MAX_RESPONSE_BYTES) throw ControlError(0, "response_too_large", "本機服務回應超過大小限制")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            val ok = same(c.getHeaderField("x-lma-proof"), hmacHex("resp:$n:$method:$fullPath:$code:${sha256Hex(bytes)}"))
            if (!ok) { verifiedAt = 0; throw ControlError(0, "server_untrusted", "本機服務回應未通過驗證，已丟棄（可能有其他 App 佔用連接埠）") }
            code to bytes
        } finally {
            c.disconnect()
        }
    }

    private suspend fun call(method: String, path: String, body: JSONObject? = null, timeoutMs: Int = 5000): String {
        val (code, bytes) = raw(method, path, body, timeoutMs)
        val text = String(bytes)
        if (code >= 400) {
            val j = runCatching { JSONObject(text) }.getOrNull()
            throw ControlError(code, j?.optString("error") ?: "error", j?.optString("message")?.ifEmpty { null } ?: j?.optString("error") ?: "HTTP $code")
        }
        return text
    }

    suspend fun getObj(path: String) = JSONObject(call("GET", path))
    suspend fun getArr(path: String) = JSONArray(call("GET", path))
    suspend fun getBytes(path: String, timeoutMs: Int = 20_000): ByteArray {
        val (code, bytes) = raw("GET", path, null, timeoutMs)
        if (code >= 400) throw ControlError(code, "error", "HTTP $code")
        return bytes
    }
    suspend fun post(path: String, body: JSONObject = JSONObject(), timeoutMs: Int = 5000): String = call("POST", path, body, timeoutMs)
    suspend fun postObj(path: String, body: JSONObject = JSONObject(), timeoutMs: Int = 5000) = JSONObject(post(path, body, timeoutMs))

    suspend fun image(path: String): Bitmap? {
        val (code, bytes) = runCatching { raw("GET", path) }.getOrNull() ?: return null
        if (code >= 400) return null
        return withContext(Dispatchers.Default) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
    }

    suspend fun state() = getObj("/state")
    /** Keepalive must prove server identity and authenticate the response, not merely receive HTTP. */
    suspend fun health(): Boolean = getObj("/health").optBoolean("ok", false)
    suspend fun startQrLogin() = postObj("/login/qr")
    suspend fun chats() = getArr("/chats")
    suspend fun info() = getObj("/info")
    suspend fun messages(chatId: String, around: String? = null) = getArr("/messages?chat_id=" + enc(chatId) + "&limit=100" + (around?.let { "&around=" + enc(it) } ?: ""))
    suspend fun setAllowed(chatId: String, allowed: Boolean) = post("/chats/allow", JSONObject().put("chat_id", chatId).put("allowed", allowed))

    companion object {
        private const val MAX_RESPONSE_BYTES = 24 * 1024 * 1024
        fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")
    }
}
