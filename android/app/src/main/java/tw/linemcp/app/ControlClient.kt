package tw.linemcp.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** 呼叫 Node 端控制 API（src/control/server.ts）。 */
class ControlClient(private val token: String, private val base: String = "http://127.0.0.1:47824/control") {
    private suspend fun call(method: String, path: String, body: JSONObject? = null): String = withContext(Dispatchers.IO) {
        val c = URL(base + path).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.setRequestProperty("authorization", "Bearer $token")
        c.connectTimeout = 3000
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("content-type", "application/json")
            c.outputStream.use { it.write(body.toString().toByteArray()) }
        }
        (if (c.responseCode < 400) c.inputStream else c.errorStream).bufferedReader().readText()
    }

    suspend fun state() = JSONObject(call("GET", "/state"))
    suspend fun startQrLogin() = JSONObject(call("POST", "/login/qr"))
    suspend fun chats() = JSONArray(call("GET", "/chats"))
    suspend fun info() = JSONObject(call("GET", "/info"))
    suspend fun messages(chatId: String) = JSONArray(call("GET", "/messages?chat_id=" + java.net.URLEncoder.encode(chatId, "UTF-8") + "&limit=100"))
    suspend fun setAllowed(chatId: String, allowed: Boolean) =
        call("POST", "/chats/allow", JSONObject().put("chat_id", chatId).put("allowed", allowed))
}
