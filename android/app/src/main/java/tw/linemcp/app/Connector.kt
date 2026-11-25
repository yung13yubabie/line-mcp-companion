package tw.linemcp.app

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * 雲端連接器（ChatGPT / Claude / Grok / Gemini 的自訂 MCP 連接器）。
 * 預設關。開了以後 127.0.0.1:47825 提供 OAuth 2.1 + MCP，要自己用 HTTPS 通道轉出去。
 * 配對碼要先過指紋 / 螢幕鎖才顯示；連上的 AI 可以一鍵撤銷。
 */
@Composable
fun ConnectorSection(client: ControlClient, withAuth: (String, () -> Unit) -> Unit) {
    val scope = rememberCoroutineScope()
    var c by remember { mutableStateOf<JSONObject?>(null) }
    var tick by remember { mutableIntStateOf(0) }
    var showCode by remember { mutableStateOf(false) }
    var urlText by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(tick) {
        var last = ""
        while (true) {
            runCatching { client.getObj("/connector") }.onSuccess { val s = it.toString(); if (s != last) { last = s; c = it; if (urlText.isEmpty()) urlText = it.optString("public_url").takeIf { u -> u != "null" } ?: "" } }
            delay(5000)
        }
    }
    LaunchedEffect(showCode) { if (showCode) { delay(60_000); showCode = false } }
    fun post(path: String, body: JSONObject) = scope.launch {
        busy = true
        runCatching { client.postObj(path, body, timeoutMs = 60_000) }.onSuccess { msg = null }.onFailure { msg = friendly(it) }
        busy = false; tick++
    }
    val d = c ?: return Section("雲端連接器") { Loading() }
    val enabled = d.optBoolean("enabled")
    Section("雲端連接器", "給 ChatGPT、Claude、Grok、Gemini 的「自訂連接器」。預設關。") {
        ToggleRow("開啟連接器閘道", enabled, "OAuth 2.1 登入 + 配對碼；本機 ${d.optString("gateway")}，要自己用 HTTPS 通道轉出去") { v ->
            if (v) withAuth("開啟雲端連接器") { post("/connector", JSONObject().put("enabled", true)) } else post("/connector", JSONObject().put("enabled", false))
        }
        if (enabled) {
            OutlinedTextField(urlText, { urlText = it.trim() }, label = { Text("公開網址（https://…）", fontSize = 12.sp) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { post("/connector", JSONObject().put("public_url", urlText)) }) { Text("儲存網址") }
                val tun = d.optJSONObject("tunnel")
                val up = tun?.optString("state") == "up"
                OutlinedButton(enabled = !busy, onClick = { post("/connector/tunnel", JSONObject().put("action", if (up) "stop" else "start")) }) { Text(if (up) "關閉通道" else "開 Cloudflare 通道") }
            }
            d.optJSONObject("tunnel")?.let { t -> if (t.optString("error").let { it.isNotEmpty() && it != "null" }) Text("通道：${t.optString("error")}", color = Warn, fontSize = 12.sp) }
            val mcpUrl = d.optString("mcp_url").takeIf { it.isNotEmpty() && it != "null" }
            if (mcpUrl != null) {
                Text("貼到 AI 用戶端的網址：", fontSize = 12.sp, color = Color.Gray)
                Text(mcpUrl, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                Text("舊版 SSE：${d.optString("sse_url")}", fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = Color.Gray)
            }
            HorizontalDivider()
            Text("配對碼（AI 用戶端跳出授權頁時輸入，10 分鐘、用一次就換）", fontSize = 12.sp, color = Color.Gray)
            val code = d.optJSONObject("pairing")?.optString("code") ?: ""
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (showCode) code.chunked(4).joinToString(" ") else "•••• ••••", fontFamily = FontFamily.Monospace, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                OutlinedButton(onClick = { if (showCode) showCode = false else withAuth("顯示連接器配對碼") { showCode = true } }) { Text(if (showCode) "遮起來" else "顯示") }
                TextButton(onClick = { post("/connector/pairing", JSONObject()) }) { Text("換一組") }
            }
            ToggleRow("也接受 MCP token（Bearer header）", d.optBoolean("allow_static"), "給 Claude Code、Gemini CLI、xAI API 這種可以自己帶 header 的用戶端；關掉只剩 OAuth") { v ->
                post("/connector", JSONObject().put("allow_static", v))
            }
            HorizontalDivider()
            val clients = d.optJSONArray("clients")?.objs() ?: emptyList()
            Text("已連線的 AI（${clients.count { it.optBoolean("active") }}）", fontWeight = FontWeight.Bold)
            if (clients.isEmpty()) Text("還沒有", fontSize = 13.sp, color = Color.Gray)
            clients.take(10).forEach { cl ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(cl.optString("name"), fontSize = 14.sp)
                        Text("${cl.optString("redirect_host")} · ${if (cl.optBoolean("active")) (if (cl.optString("scope").contains("line.send")) "可讀 + 可送" else "只讀") else "未授權"} · ${fmtDateTime(cl.optLong("last_used_at", cl.optLong("created_at")))}", fontSize = 12.sp, color = Color.Gray)
                    }
                    TextButton(onClick = { post("/connector/revoke", JSONObject().put("client_id", cl.optString("client_id"))) }) { Text("撤銷") }
                }
            }
            if (clients.isNotEmpty()) OutlinedButton(onClick = { post("/connector/revoke", JSONObject().put("client_id", "all")) }) { Text("全部撤銷") }
        }
        msg?.let { Text(it, color = Warn, fontSize = 13.sp) }
    }
}
