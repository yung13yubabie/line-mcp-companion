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

class ControlError(val status: Int, val code: String, message: String) : Exception(message)

/** 呼叫 Node 端控制 API（src/control/server.ts）。全部在 Dispatchers.IO。 */
class ControlClient(private val token: String, private val base: String = "http://127.0.0.1:47824/control") {
    private suspend fun raw(method: String, path: String, body: JSONObject? = null, timeoutMs: Int = 5000): Pair<Int, ByteArray> = withContext(Dispatchers.IO) {
        val c = URL(base + path).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.setRequestProperty("authorization", "Bearer $token")
        c.connectTimeout = 3000
        c.readTimeout = timeoutMs
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("content-type", "application/json")
            c.outputStream.use { it.write(body.toString().toByteArray()) }
        }
        val code = c.responseCode
        val bytes = (if (code < 400) c.inputStream else c.errorStream)?.use { it.readBytes() } ?: ByteArray(0)
        code to bytes
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
    suspend fun post(path: String, body: JSONObject = JSONObject(), timeoutMs: Int = 5000): String = call("POST", path, body, timeoutMs)
    suspend fun postObj(path: String, body: JSONObject = JSONObject(), timeoutMs: Int = 5000) = JSONObject(post(path, body, timeoutMs))

    suspend fun image(path: String): Bitmap? {
        val (code, bytes) = runCatching { raw("GET", path) }.getOrNull() ?: return null
        if (code >= 400) return null
        return withContext(Dispatchers.Default) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
    }

    suspend fun state() = getObj("/state")
    suspend fun startQrLogin() = postObj("/login/qr")
    suspend fun chats() = getArr("/chats")
    suspend fun info() = getObj("/info")
    suspend fun messages(chatId: String) = getArr("/messages?chat_id=" + enc(chatId) + "&limit=100")
    suspend fun setAllowed(chatId: String, allowed: Boolean) = post("/chats/allow", JSONObject().put("chat_id", chatId).put("allowed", allowed))

    companion object { fun enc(s: String): String = URLEncoder.encode(s, "UTF-8") }
}
