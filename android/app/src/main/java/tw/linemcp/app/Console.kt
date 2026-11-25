package tw.linemcp.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

fun JSONArray.objs(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

val MODE_LABEL = mapOf("off" to "關閉", "suggest" to "僅建議", "auto" to "代聊")

@Composable
fun Page(title: String, onBack: (() -> Unit)?, action: (@Composable () -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().background(Soft)) {
        TopBar(title, onBack = onBack, action = action)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 14.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp), content = content)
    }
}

// ============================ 總控台 ============================
@Composable
fun ConsoleScreen(client: ControlClient, go: (Screen) -> Unit) {
    var d by remember { mutableStateOf<JSONObject?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    var tick by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(tick) { while (true) { runCatching { client.getObj("/dashboard") }.onSuccess { d = it; err = null }.onFailure { err = friendly(it) }; delay(3000) } }
    fun post(path: String, body: JSONObject) = scope.launch { runCatching { client.post(path, body) }.onFailure { err = friendly(it) }; tick++ }
    Page("總控台", null) {
        val dash = d ?: run { Loading(); return@Page }
        err?.let { Text(it, color = Danger, fontSize = 12.sp) }
        val ai = dash.optJSONObject("ai")
        val kill = ai?.optBoolean("kill_switch") == true
        // ---- 緊急停止 ----
        Card(colors = CardDefaults.cardColors(containerColor = if (kill) Danger.copy(alpha = 0.12f) else Color.White), shape = RoundedCornerShape(14.dp)) {
            Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(if (kill) "🛑 緊急停止中" else "一切正常 👌", fontWeight = FontWeight.Bold)
                    Text(if (kill) "所有自動送出、代聊、反詐提醒都先停住" else "按下去會立刻停掉所有自動送出", fontSize = 12.sp, color = Color.Gray)
                }
                Button(onClick = { post("/kill", JSONObject().put("on", !kill)) }, colors = ButtonDefaults.buttonColors(containerColor = if (kill) LineGreen else Danger)) { Text(if (kill) "解除" else "緊急停止") }
            }
        }
        // ---- 服務狀態 ----
        Section("服務狀態") {
            val login = dash.optJSONObject("login"); val sync = dash.optJSONObject("sync"); val info = dash.optJSONObject("info")
            StatusLine("LINE", when (login?.optString("phase")) { "online" -> "已連線（${login.optJSONObject("profile")?.optString("displayName")}）"; "error" -> "需要處理：${login.optString("error")}"; else -> "尚未登入" }, login?.optString("phase") == "online")
            StatusLine("同步", sync?.let { "${it.optString("state")} · ${it.optJSONObject("counts")?.optInt("messages")} 則訊息" } ?: "離線", sync?.optString("state") != "error")
            StatusLine("已讀回條", if (info?.optString("read_receipts") == "blocked") "封鎖中（不會標已讀）" else "已開啟", info?.optString("read_receipts") == "blocked")
            if (info?.optBoolean("mock") == true) Pill("Mock 示範資料", Warn)
        }
        // ---- 代聊方式 ----
        Section("誰來代聊？", "用外部 AI（Claude、ChatGPT…經 MCP）就不需要在 App 裡放 API key") {
            val driver = ai?.optString("driver") ?: "connector"
            Chips(listOf("connector" to "由連接器代聊", "builtin" to "App 內建 AI"), driver) { post("/ai", JSONObject().put("driver", it)) }
            Text(if (driver == "connector") "外部 AI 透過 MCP 的 send_message 幫你回；一樣受白名單、確認佇列和上限管" else "App 用你設定的 API key 自己產生建議${if (ai?.optBoolean("has_key") != true) "（還沒設定 key）" else ""}",
                fontSize = 12.sp, color = Color.Gray)
            ToggleRow("AI 代聊總開關", ai?.optBoolean("enabled") == true, "關掉時所有送出工具都會被擋") { post("/ai", JSONObject().put("enabled", it)) }
            val c = ai?.optJSONObject("counters")
            Text("今天送出 ${c?.optInt("sent_today") ?: 0} / ${c?.optInt("daily_cap") ?: 0} 則", fontSize = 13.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { go(Screen.Queue) }) { Text("確認佇列（${ai?.optInt("pending") ?: 0}）") }
                OutlinedButton(onClick = { go(Screen.AiSettings) }) { Text("AI 設定") }
            }
        }
        // ---- 每個聊天 ----
        Section("開放的聊天", "點一下調整 AI 模式、頻率和反詐提醒") {
            val chats = dash.optJSONArray("chats")?.objs().orEmpty()
            if (chats.isEmpty()) Text("還沒有開放任何聊天，到「聊天」勾選吧", color = Color.Gray, fontSize = 13.sp)
            chats.forEach { c ->
                Row(Modifier.fillMaxWidth().clickable { go(Screen.ChatAi(c.getString("chat_id"), c.optString("name"), "GROUP")) }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(c.optString("name"), fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("今天 ${c.optInt("sent_today")} / ${c.optInt("max_per_day")}", fontSize = 12.sp, color = Color.Gray)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                            TrustPill("AI", c.optString("ai_trust"))
                            if (c.optString("ai_trust") == "auto") TextButton(onClick = { post("/trust", JSONObject().put("chat_id", c.getString("chat_id")).put("feature", "ai").put("state", "review")) }, contentPadding = PaddingValues(horizontal = 4.dp)) { Text("降回審核", fontSize = 12.sp) }
                            if (c.optBoolean("warn_enabled")) {
                                TrustPill("反詐", c.optString("scam_trust"))
                                if (c.optString("scam_trust") == "auto") TextButton(onClick = { post("/trust", JSONObject().put("chat_id", c.getString("chat_id")).put("feature", "scam").put("state", "review")) }, contentPadding = PaddingValues(horizontal = 4.dp)) { Text("降回審核", fontSize = 12.sp) }
                            }
                        }
                    }
                    Pill(if (!c.optBoolean("ai_allowed")) "未加入代聊" else MODE_LABEL[c.optString("mode")] ?: "", if (c.optBoolean("ai_allowed") && c.optString("mode") != "off") LineGreen else Color.Gray)
                }
            }
        }
        // ---- 信任狀態 ----
        Section("信任狀態", "審核＝每則先進確認佇列（預設）；自動＝直接送，上限 / 冷卻 / 緊急停止照樣有效。按緊急停止會全部降回審核") {
            val anyAuto = dash.optJSONArray("chats")?.objs().orEmpty().any { it.optString("ai_trust") == "auto" || it.optString("scam_trust") == "auto" }
            OutlinedButton(enabled = anyAuto, onClick = { post("/trust/demote_all", JSONObject()) }) { Text("全部降回審核") }
            ToggleRow("允許 MCP 核准佇列", dash.optBoolean("mcp_allow_approve"), "預設關：外部 AI 只能擬稿 / 修改 / 退回，送出要你按") { post("/mcp/permissions", JSONObject().put("mcp_allow_approve", it)) }
            ToggleRow("允許 MCP 升級到自動", dash.optBoolean("mcp_allow_promote"), "預設關；降回審核永遠可以") { post("/mcp/permissions", JSONObject().put("mcp_allow_promote", it)) }
            val log = dash.optJSONArray("trust_log")?.objs().orEmpty()
            if (log.isNotEmpty()) Text("最近變更", fontSize = 12.sp, color = Color.Gray)
            log.take(6).forEach { l ->
                Text("${fmtDateTime(l.optLong("ts"))} ${chatName(dash, l.optString("chat_id"))}｜${if (l.optString("feature") == "ai") "AI" else "反詐"} ${trustLabel(l.optString("from_state"))}→${trustLabel(l.optString("to_state"))}（${actorLabel(l.optString("actor"))}${l.optString("reason").takeIf { it.isNotEmpty() && it != "null" }?.let { "，$it" } ?: ""}）", fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
        // ---- 反詐 ----
        dash.optJSONObject("scam")?.let { sc ->
            Section("反詐雷達", "本機規則偵測，不需要 AI") {
                val t = sc.optJSONObject("today")
                Text("今天：${t?.optInt("total") ?: 0} 則可疑（高風險 ${t?.optInt("high") ?: 0}，未看 ${t?.optInt("new") ?: 0}）")
                sc.optJSONArray("recent")?.objs()?.take(3)?.forEach { a ->
                    Text("• ${a.optString("chat_name")}｜疑似「${a.optString("category")}」— ${a.optString("sender")}", fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                val w = sc.optJSONArray("warnings")?.objs().orEmpty()
                if (w.isNotEmpty()) Text("最近發出的提醒：${w.size} 則（最後 ${fmtDateTime(w.first().optLong("created_at"))}，${statusLabel(w.first().optString("status"))}）", fontSize = 12.sp, color = Color.Gray)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { go(Screen.Scam) }) { Text("看全部警示") }
                    OutlinedButton(onClick = { go(Screen.Logs) }) { Text("紀錄") }
                }
            }
        }
        // ---- MCP ----
        dash.optJSONObject("mcp")?.let { m ->
            Section("MCP 連線") {
                Text(dash.optJSONObject("info")?.optString("mcp_url") ?: "", fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                val rej = m.optJSONObject("rejected")
                Text("請求 ${m.optInt("requests")} 次 · 擋下：未授權 ${rej?.optInt("unauthorized")}、太頻繁 ${rej?.optInt("rate_limited")}、太大 ${rej?.optInt("too_large")}、來源不符 ${rej?.optInt("forbidden")}", fontSize = 12.sp, color = Color.Gray)
                m.optJSONArray("clients")?.objs()?.forEach { c -> Text("🔌 ${c.optString("name")} · ${c.optInt("calls")} 次 · ${fmtDateTime(c.optLong("last_seen"))}", fontSize = 13.sp) }
                m.optJSONArray("recent")?.objs()?.take(6)?.forEach { r ->
                    Text("${fmtTime(r.optLong("ts"))} ${r.optString("tool")} ${if (r.optBoolean("ok")) "✓" else "✗ ${r.optString("code")}"}", fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = if (r.optBoolean("ok")) Color.DarkGray else Danger)
                }
                if (m.optJSONArray("recent")?.length() == 0) Text("還沒有 AI 用戶端呼叫過", fontSize = 12.sp, color = Color.Gray)
            }
        }
        // ---- 稽核紀錄 ----
        Section("稽核紀錄") {
            dash.optJSONArray("audit")?.objs()?.take(15)?.forEach { a ->
                Text("${fmtTime(a.optLong("ts"))} [${a.optString("actor")}] ${a.optString("action")}${if (a.optInt("ok") == 0) " ✗" else ""}", fontSize = 12.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        OutlinedButton(onClick = { go(Screen.Social) }, modifier = Modifier.fillMaxWidth()) { Text("📝 社群貼文草稿（只草稿，不會發布）") }
        Spacer(Modifier.height(16.dp))
    }
}

fun trustLabel(s: String) = if (s == "auto") "自動" else "審核"
fun actorLabel(s: String) = when (s) { "ui" -> "你"; "mcp" -> "MCP"; "system" -> "系統"; else -> s }
fun chatName(dash: JSONObject, id: String) = dash.optJSONArray("chats")?.objs()?.firstOrNull { it.optString("chat_id") == id }?.optString("name") ?: id.take(8)

@Composable
fun TrustPill(label: String, state: String) = Pill("$label：${trustLabel(state)}", if (state == "auto") Warn else Color.Gray)

fun statusLabel(s: String) = when (s) { "sent" -> "已送出"; "pending" -> "待確認"; "approved" -> "排程中"; "rejected" -> "已取消"; "failed" -> "失敗"; "expired" -> "過期"; else -> s }

@Composable
fun StatusLine(label: String, value: String, ok: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(RoundedCornerShape(50)).background(if (ok) LineGreen else Warn))
        Text("  $label", fontWeight = FontWeight.Medium, modifier = Modifier.width(90.dp))
        Text(value, fontSize = 13.sp, color = Color.DarkGray)
    }
}

// ============================ 確認佇列 ============================
@Composable
fun QueueScreen(client: ControlClient, onBack: () -> Unit) {
    var items by remember { mutableStateOf<List<JSONObject>?>(null) }
    var tick by remember { mutableIntStateOf(0) }
    var err by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(tick) { while (true) { items = runCatching { client.getArr("/queue").objs() }.getOrDefault(items ?: emptyList()); delay(4000) } }
    Page("確認佇列", onBack) {
        Text("AI 擬好的訊息會先放這裡，你點「送出」才會真的送。", fontSize = 13.sp, color = Color.Gray)
        err?.let { Text(it, color = Danger, fontSize = 12.sp) }
        val list = items ?: run { Loading(); return@Page }
        if (list.isEmpty()) Text("目前沒有要確認的訊息 ☕", modifier = Modifier.padding(vertical = 24.dp))
        list.forEach { it ->
            key(it.getInt("id")) {
                var text by remember { mutableStateOf(it.optString("text")) }
                Section(it.optString("chat_name"), "${originLabel(it.optString("origin"))} · ${fmtDateTime(it.optLong("created_at"))}") {
                    if (!it.isNull("reply_preview")) Text("↪ 回覆：${it.optString("reply_preview")}", fontSize = 12.sp, color = Color.Gray, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    when (it.optString("kind")) {
                        "sticker" -> { Text("貼圖", fontSize = 12.sp, color = Color.Gray); runCatching { JSONObject(it.optString("sticker_json")) }.getOrNull()?.let { s -> StickerImage(client, s.getString("sticker_id"), 72.dp) } }
                        "image" -> Text("🖼 生成的圖片${if (it.optBoolean("has_image")) "" else "（檔案不見了）"}", fontSize = 13.sp)
                    }
                    if (it.optString("kind") != "sticker" || text.isNotEmpty()) OutlinedTextField(text, { v -> text = v }, modifier = Modifier.fillMaxWidth())
                    if (it.optString("origin") == "scam_warn") Text("可以自由改寫；不能有連結、LINE ID 或引用詐騙內容，禁字會自動替換", fontSize = 11.sp, color = Color.Gray)
                    val flags = it.optString("flags")
                    if (flags.isNotEmpty() && flags != "null") Text("⚠️ 幫你標出來：${flagText(flags)}", fontSize = 12.sp, color = Warn)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { scope.launch { runCatching { client.post("/queue/approve", JSONObject().put("id", it.getInt("id")).put("text", text)) }.onFailure { e -> err = friendly(e) }; tick++ } }) { Text("送出") }
                        OutlinedButton(onClick = { scope.launch { runCatching { client.post("/queue/reject", JSONObject().put("id", it.getInt("id"))) }; tick++ } }) { Text("不要") }
                        if (text != it.optString("text")) TextButton(onClick = { scope.launch { runCatching { client.post("/queue/edit", JSONObject().put("id", it.getInt("id")).put("text", text)) }.onSuccess { err = null }.onFailure { e -> err = friendly(e) }; tick++ } }) { Text("先存") }
                    }
                }
            }
        }
    }
}

fun originLabel(o: String) = when (o) { "mcp" -> "外部 AI（MCP）"; "auto" -> "自動代聊"; "suggest" -> "AI 建議"; "ui" -> "你自己"; "scam_warn" -> "反詐提醒"; else -> o }
fun flagText(f: String) = f.split(",").joinToString("、") { when (it) {
    "injection_suspected" -> "對方訊息像在下指令給 AI"; "url_in_output" -> "回覆裡有連結"; "suspicious_output" -> "回覆內容怪怪的"; "unknown_sticker_dropped" -> "AI 想用你沒有的貼圖"
    else -> if (it.startsWith("limited:")) "已到頻率上限" else it } }

// ============================ AI 設定 ============================
@Composable
fun AiSettingsScreen(client: ControlClient, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var cfg by remember { mutableStateOf<JSONObject?>(null) }
    var msg by remember { mutableStateOf<String?>(null) }
    var key by remember { mutableStateOf("") }
    var detecting by remember { mutableStateOf(false) }
    suspend fun load() { cfg = runCatching { client.getObj("/ai") }.getOrNull() }
    LaunchedEffect(Unit) { load() }
    Page("AI 設定", onBack) {
        val c = cfg ?: run { Loading(); return@Page }
        val conf = c.getJSONObject("config")
        var provider by remember { mutableStateOf(conf.optString("provider")) }
        var baseUrl by remember { mutableStateOf(conf.optString("base_url")) }
        var model by remember { mutableStateOf(conf.optString("model")) }
        var imageModel by remember { mutableStateOf(conf.optString("image_model")) }
        var mtf by remember { mutableStateOf(conf.optString("max_tokens_field").takeIf { it != "null" } ?: "") }
        var fallbacks by remember { mutableStateOf(conf.optJSONArray("fallback")?.objs().orEmpty()) }
        var fbUrl by remember { mutableStateOf("http://127.0.0.1:8080/v1") }
        var fbModel by remember { mutableStateOf("") }
        var fbKey by remember { mutableStateOf(false) }
        var persona by remember { mutableStateOf(c.optString("persona")) }
        var cap by remember { mutableIntStateOf(c.optInt("daily_cap", 20)) }
        Text("只有選「App 內建 AI」才需要這裡。用外部連接器代聊的話可以略過 🙂", fontSize = 13.sp, color = Color.Gray)
        Section("供應商", "OpenAI 相容 API：OpenAI、Grok（xAI）、Claude（Anthropic）或自訂") {
            val opts = mutableListOf("openai" to "OpenAI", "xai" to "Grok", "anthropic" to "Claude", "custom" to "自訂")
            if (BuildConfig.DEBUG) opts += "mock" to "Mock"
            Chips(opts, provider) { p ->
                provider = p
                c.optJSONObject("presets")?.optJSONObject(p)?.let { baseUrl = it.optString("base_url"); model = it.optString("model"); imageModel = it.optString("image_model") }
            }
            OutlinedTextField(baseUrl, { baseUrl = it }, label = { Text("API 網址（必須 https）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(model, { model = it }, label = { Text("文字模型") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(imageModel, { imageModel = it }, label = { Text("圖片模型（選填）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Text("max tokens 欄位（遇到 HTTP 400 會自動換另一個重試）", fontSize = 12.sp, color = Color.Gray)
            Chips(listOf("" to "自動", "max_completion_tokens" to "max_completion_tokens", "max_tokens" to "max_tokens"), mtf) { mtf = it }
            Button(onClick = { scope.launch {
                runCatching { client.post("/ai", JSONObject().put("provider", provider).put("base_url", baseUrl).put("model", model).put("image_model", imageModel).put("max_tokens_field", mtf.ifEmpty { JSONObject.NULL })) }
                    .onSuccess { msg = "存好了"; load() }.onFailure { msg = friendly(it) }
            } }) { Text("儲存") }
        }
        Section("備援模型", "主模型連不上、沒額度時依序改問；可以放本機 llama-server（http://127.0.0.1:8080/v1，免 key、免費）") {
            fallbacks.forEachIndexed { i, f ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(f.optString("model"), fontWeight = FontWeight.Medium)
                        Text("${f.optString("base_url")}${if (f.optBoolean("use_key")) " · 帶主 key" else ""}", fontSize = 11.sp, color = Color.Gray)
                    }
                    TextButton(onClick = { fallbacks = fallbacks.filterIndexed { j, _ -> j != i } }) { Text("移除") }
                }
            }
            if (fallbacks.size < 3) {
                OutlinedTextField(fbUrl, { fbUrl = it.trim() }, label = { Text("備援 API 網址") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(fbModel, { fbModel = it.trim() }, label = { Text("備援模型") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                ToggleRow("帶主 API key（同一家供應商）", fbKey) { fbKey = it }
                TextButton(enabled = fbUrl.isNotEmpty() && fbModel.isNotEmpty(), onClick = { fallbacks = fallbacks + JSONObject().put("base_url", fbUrl).put("model", fbModel).put("use_key", fbKey); fbUrl = ""; fbModel = "" }) { Text("＋ 加入") }
            }
            Button(onClick = { scope.launch {
                runCatching { client.post("/ai", JSONObject().put("fallback", JSONArray(fallbacks))) }.onSuccess { msg = "備援存好了"; load() }.onFailure { msg = friendly(it) }
            } }) { Text("儲存備援") }
        }
        Section("隱私") {
            ToggleRow("送到雲端模型前去識別化", conf.optBoolean("deidentify", true), "人名換成「成員A」，電話、網址、帳號、LINE ID、地址遮掉；回覆裡的代號會換回人名。本機模型不需要") {
                scope.launch { runCatching { client.post("/ai", JSONObject().put("deidentify", it)) }.onSuccess { load() }.onFailure { e -> msg = friendly(e) } }
            }
        }
        Section("API key", "用 Android Keystore 加密存在這支手機；只在記憶體交給本機服務，不會寫進資料庫") {
            Text(if (c.optBoolean("has_key")) "目前：${c.optString("key_hint").ifEmpty { "已設定" }}" else "目前：還沒設定", fontSize = 13.sp)
            OutlinedTextField(key, { key = it.trim() }, label = { Text("貼上新的 key") }, singleLine = true, visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = key.length >= 8, onClick = { scope.launch {
                    val k = key
                    runCatching { withContext(Dispatchers.IO) { Secrets.setAiKey(ctx, k) }; client.post("/ai/key", JSONObject().put("key", k)) }
                        .onSuccess { key = ""; msg = "key 存好了"; load() }.onFailure { msg = friendly(it) }
                } }) { Text("儲存 key") }
                OutlinedButton(onClick = { scope.launch {
                    runCatching { withContext(Dispatchers.IO) { Secrets.setAiKey(ctx, null) }; client.post("/ai/key", JSONObject().put("key", JSONObject.NULL)) }.onSuccess { msg = "已刪除 key"; load() }
                } }) { Text("刪除") }
            }
        }
        Section("能力偵測") {
            val caps = c.optJSONObject("capabilities")
            if (caps != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("text" to "文字", "vision" to "看圖", "image_gen" to "生圖", "voice" to "語音").forEach { (k, l) -> Pill((if (caps.optBoolean(k)) "✓ " else "✗ ") + l, if (caps.optBoolean(k)) LineGreen else Color.Gray) }
                }
                caps.optString("error").takeIf { it.isNotEmpty() }?.let { Text(it, color = Danger, fontSize = 12.sp) }
            } else Text("還沒偵測過", fontSize = 13.sp, color = Color.Gray)
            OutlinedButton(enabled = !detecting && c.optBoolean("has_key"), onClick = { detecting = true; scope.launch {
                runCatching { client.post("/ai/detect", timeoutMs = 60_000) }.onFailure { msg = friendly(it) }; load(); detecting = false
            } }) { Text(if (detecting) "偵測中…" else "偵測能力") }
        }
        Section("語氣", "空白＝溫暖、簡短、口語的台灣繁中") {
            OutlinedTextField(persona, { persona = it.take(300) }, placeholder = { Text("例如：講話直接一點，常用「哈哈」") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                NumberField("全部聊天每日上限", cap, 150.dp) { cap = it }
                Button(onClick = { scope.launch { runCatching { client.post("/ai", JSONObject().put("persona", persona).put("daily_cap", cap)) }.onSuccess { msg = "存好了" } } }) { Text("儲存") }
            }
        }
        Section("風格模組") {
            c.optJSONArray("styles")?.objs()?.forEach { m ->
                Text(m.optString("name"), fontWeight = FontWeight.Medium)
                Text("授權：${m.optString("license")} · ${m.optString("source")}", fontSize = 11.sp, color = Color.Gray)
            }
        }
        msg?.let { Text(it, color = LineGreen) }
        Spacer(Modifier.height(16.dp))
    }
}

fun hhmm(min: Int?): String = if (min == null) "" else "%02d:%02d".format(min / 60, min % 60)
fun parseHhmm(s: String): Int? = Regex("^(\\d{1,2}):(\\d{2})$").find(s.trim())?.let { val h = it.groupValues[1].toInt(); val m = it.groupValues[2].toInt(); if (h < 24 && m < 60) h * 60 + m else null }

// ============================ 每個聊天的 AI / 反詐設定 ============================
@Composable
fun ChatAiScreen(client: ControlClient, chatId: String, name: String, type: String, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var cfg by remember { mutableStateOf<JSONObject?>(null) }
    var warn by remember { mutableStateOf<JSONObject?>(null) }
    var members by remember { mutableStateOf(listOf<JSONObject>()) }
    var msg by remember { mutableStateOf<String?>(null) }
    suspend fun load() {
        cfg = runCatching { client.getObj("/chat_ai?chat_id=" + ControlClient.enc(chatId)) }.getOrNull()
        warn = runCatching { client.getObj("/scam/warn?chat_id=" + ControlClient.enc(chatId)) }.getOrNull()
    }
    LaunchedEffect(Unit) { load(); members = runCatching { client.getArr("/scam/members?chat_id=" + ControlClient.enc(chatId)).objs() }.getOrDefault(emptyList()) }
    fun patch(p: JSONObject) = scope.launch {
        runCatching { client.postObj("/chat_ai", p.put("chat_id", chatId)) }.onSuccess { cfg = it; msg = null }.onFailure { msg = friendly(it) }
    }
    fun setTrust(feature: String, state: String) = scope.launch {
        runCatching { client.post("/trust", JSONObject().put("chat_id", chatId).put("feature", feature).put("state", state)) }.onSuccess { msg = null; load() }.onFailure { msg = friendly(it) }
    }
    fun patchWarn(p: JSONObject) = scope.launch {
        runCatching { client.postObj("/scam/warn", p.put("chat_id", chatId)) }.onSuccess { warn = it; msg = null }.onFailure { msg = friendly(it) }
    }
    Page(name, onBack) {
        val c = cfg ?: run { Loading(); return@Page }
        msg?.let { Text(it, color = Danger, fontSize = 13.sp) }
        Section("AI 代聊", "跟 MCP 白名單分開：兩邊都勾才會生效") {
            ToggleRow("加入 AI 代聊名單", c.optBoolean("ai_allowed")) { patch(JSONObject().put("ai_allowed", it)) }
            Text("模式", fontSize = 13.sp)
            Chips(listOf("off" to "關閉", "suggest" to "僅建議回覆", "auto" to "AI 代聊"), c.optString("mode")) { patch(JSONObject().put("mode", it)) }
            Text("信任狀態", fontSize = 13.sp)
            Chips(listOf("review" to "審核（每則先確認）", "auto" to "自動（直接送）"), c.optJSONObject("trust")?.optString("ai") ?: "review") { st -> setTrust("ai", st) }
            Text("自動仍受間隔、上限、活躍時段和緊急停止限制；緊急停止會自動降回審核", fontSize = 11.sp, color = Color.Gray)
            ToggleRow("去 AI 味", c.optBoolean("style_lieflat"), "送出前把太像 AI 的句子修自然一點（Lieflat 規則）") { patch(JSONObject().put("style_lieflat", it)) }
            ToggleRow("允許生成圖片並發送", c.optBoolean("allow_image")) { patch(JSONObject().put("allow_image", it)) }
        }
        Section("回覆頻率", "就算是代聊也不要太勤快") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                NumberField("間隔（秒）", c.optInt("min_interval_sec")) { patch(JSONObject().put("min_interval_sec", it)) }
                NumberField("延遲（秒）", c.optInt("delay_sec")) { patch(JSONObject().put("delay_sec", it)) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                NumberField("每小時最多", c.optInt("max_per_hour")) { patch(JSONObject().put("max_per_hour", it)) }
                NumberField("每天最多", c.optInt("max_per_day")) { patch(JSONObject().put("max_per_day", it)) }
            }
            var start by remember(c) { mutableStateOf(hhmm(if (c.isNull("active_start")) null else c.optInt("active_start"))) }
            var end by remember(c) { mutableStateOf(hhmm(if (c.isNull("active_end")) null else c.optInt("active_end"))) }
            Text("活躍時段（空白＝不限，可以跨午夜，例如 22:00–07:00）", fontSize = 12.sp, color = Color.Gray)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(start, { start = it }, label = { Text("開始") }, singleLine = true, modifier = Modifier.width(100.dp))
                OutlinedTextField(end, { end = it }, label = { Text("結束") }, singleLine = true, modifier = Modifier.width(100.dp))
                TextButton(onClick = { patch(JSONObject().put("active_start", parseHhmm(start) ?: JSONObject.NULL).put("active_end", parseHhmm(end) ?: JSONObject.NULL)) }) { Text("套用") }
            }
        }
        val w = warn
        if (type != "USER" && w != null) {
            val wc = w.getJSONObject("config")
            Section("反詐即時提醒", "偵測到詐騙 / 換群訊息時，馬上引用那則回一句提醒（不用 AI、不會引用詐騙內容）") {
                ToggleRow("在這個群組開啟", wc.optBoolean("enabled"), "預設關閉") { patchWarn(JSONObject().put("enabled", it)) }
                Text("信任狀態", fontSize = 13.sp)
                Chips(listOf("review" to "審核（先進確認佇列）", "auto" to "自動（直接送）"), c.optJSONObject("trust")?.optString("scam") ?: "review") { st -> setTrust("scam", st) }
                Text("觸發門檻", fontSize = 13.sp)
                Chips(listOf("high" to "只有高風險", "suspicious" to "可疑就提醒"), wc.optString("min_level")) { patchWarn(JSONObject().put("min_level", it)) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    NumberField("同一人冷卻（分）", wc.optInt("cooldown_min"), 140.dp) { patchWarn(JSONObject().put("cooldown_min", it)) }
                    NumberField("每天最多", wc.optInt("daily_cap")) { patchWarn(JSONObject().put("daily_cap", it)) }
                }
                ToggleRow("@ 管理員", wc.optBoolean("mention_admins"), "最多 3 位；@ 失敗會自動改送不含 @ 的版本") { patchWarn(JSONObject().put("mention_admins", it)) }
                var tpl by remember(wc) { mutableStateOf(if (wc.isNull("template")) "" else wc.optString("template")) }
                OutlinedTextField(tpl, { tpl = it.take(300) }, label = { Text("這個群的範本（空白＝用預設）") }, placeholder = { Text(w.optString("global_template"), fontSize = 12.sp) }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                Text("可用：{category} 類型、{tip} 一句提示、{admins} 管理員、{sender} 發送者暱稱", fontSize = 11.sp, color = Color.Gray)
                TextButton(onClick = { patchWarn(JSONObject().put("template", tpl.ifBlank { JSONObject.NULL })) }) { Text("儲存範本") }
                Text("預覽", fontSize = 12.sp, color = Color.Gray)
                Text(w.optJSONObject("preview")?.optString("text") ?: "", modifier = Modifier.clip(RoundedCornerShape(10.dp)).background(Soft).padding(10.dp), fontSize = 13.sp)
            }
            Section("管理員 / 信任成員", "他們的訊息不會被當成詐騙；勾 @ 的人會在提醒裡被標註") {
                w.optJSONArray("admins")?.objs()?.forEach { a ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(a.optString("name").ifEmpty { a.optString("mid") }, modifier = Modifier.weight(1f))
                        Text("@", fontSize = 12.sp); Checkbox(a.optBoolean("mention"), { v -> scope.launch { client.post("/scam/admin", JSONObject().put("chat_id", chatId).put("mid", a.getString("mid")).put("name", a.optString("name")).put("mention", v)); load() } })
                        TextButton(onClick = { scope.launch { client.post("/scam/admin", JSONObject().put("chat_id", chatId).put("mid", a.getString("mid")).put("remove", true)); load() } }) { Text("移除") }
                    }
                }
                val existing = w.optJSONArray("admins")?.objs()?.map { it.getString("mid") }?.toSet().orEmpty()
                val candidates = members.filter { it.getString("mid") !in existing }
                if (candidates.isNotEmpty()) {
                    Text("從最近發言的成員加入：", fontSize = 12.sp, color = Color.Gray)
                    candidates.take(8).forEach { m ->
                        Text("＋ ${m.optString("name")}", color = LineGreen, modifier = Modifier.clickable { scope.launch { client.post("/scam/admin", JSONObject().put("chat_id", chatId).put("mid", m.getString("mid")).put("name", m.optString("name"))); load() } }.padding(vertical = 2.dp))
                    }
                }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

// ============================ 反詐警示 ============================
@Composable
fun ScamScreen(client: ControlClient, onBack: () -> Unit, onChat: (String, String) -> Unit) {
    val scope = rememberCoroutineScope()
    var alerts by remember { mutableStateOf<List<JSONObject>?>(null) }
    var tpl by remember { mutableStateOf<String?>(null) }
    var sample by remember { mutableStateOf("") }
    var tick by remember { mutableIntStateOf(0) }
    var msg by remember { mutableStateOf<String?>(null) }
    var composeFor by remember { mutableStateOf<JSONObject?>(null) }
    composeFor?.let { a ->
        var t by remember(a) { mutableStateOf("") }
        AlertDialog(onDismissRequest = { composeFor = null }, title = { Text("自訂提醒") },
            text = { Column {
                Text("會引用那則訊息送出；空白＝用群組範本。不能有連結、LINE ID 或引用詐騙內容。", fontSize = 12.sp, color = Color.Gray)
                OutlinedTextField(t, { t = it.take(300) }, modifier = Modifier.fillMaxWidth(), minLines = 3, placeholder = { Text("例如：大家先別點連結，等管理員確認 🙏") })
            } },
            confirmButton = { TextButton(onClick = { scope.launch {
                runCatching { client.postObj("/scam/compose", JSONObject().put("chat_id", a.getString("chat_id")).put("message_id", a.getString("message_id")).put("text", t.ifBlank { JSONObject.NULL })) }
                    .onSuccess { r -> msg = if (r.optString("status") == "pending") "放進確認佇列了" else "排程送出了"; composeFor = null }.onFailure { e -> msg = friendly(e) }
            } }) { Text("送出 / 排入") } },
            dismissButton = { TextButton(onClick = { composeFor = null }) { Text("取消") } })
    }
    LaunchedEffect(tick) {
        alerts = runCatching { client.getArr("/scam/alerts?limit=50").objs() }.getOrDefault(emptyList())
        if (tpl == null) tpl = runCatching { client.getObj("/scam/warn?chat_id=").optString("global_template") }.getOrNull() ?: ""
    }
    Page("反詐警示", onBack) {
        Text("只掃描你開放給 MCP 的群組。規則改作自 mars-tw/anti-scam-helper（Apache-2.0）。", fontSize = 12.sp, color = Color.Gray)
        msg?.let { Text(it, color = LineGreen, fontSize = 13.sp) }
        val list = alerts ?: run { Loading(); return@Page }
        if (list.isEmpty()) Text("目前很平靜 🌿", modifier = Modifier.padding(vertical = 16.dp))
        list.forEach { a ->
            Section("${a.optString("chat_name")}｜疑似「${a.optString("category")}」", "${a.optString("sender")} · ${fmtDateTime(a.optLong("sent_at"))} · ${if (a.optString("level") == "high") "高風險" else "可疑"}${if (a.optString("status") == "new") " · 新" else ""}") {
                Text(a.optString("text"), fontSize = 13.sp, maxLines = 4, overflow = TextOverflow.Ellipsis)
                Text(a.optJSONArray("rules")?.let { r -> (0 until r.length()).joinToString("、") { r.getString(it) } } ?: "", fontSize = 11.sp, color = Color.Gray)
                if (!a.isNull("ai_verdict")) Text("AI 判讀：${a.optString("ai_verdict")}｜${a.optString("ai_reason")}", fontSize = 12.sp)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { scope.launch { client.post("/scam/alert_status", JSONObject().put("id", a.getInt("id")).put("status", "seen")); tick++ } }) { Text("看過了") }
                    TextButton(onClick = { scope.launch { runCatching { client.postObj("/scam/false_positive", JSONObject().put("id", a.getInt("id")).put("trust_member", true)) }.onSuccess { msg = "已標成誤判，${a.optString("sender")} 加入信任成員" }.onFailure { msg = friendly(it) }; tick++ } }) { Text("誤判→信任此人") }
                    TextButton(onClick = { composeFor = a }) { Text("寫提醒") }
                    TextButton(onClick = { onChat(a.getString("chat_id"), a.optString("chat_name")) }) { Text("群組設定") }
                }
            }
        }
        Section("預設提醒範本", "每個群組也可以自己改") {
            var t by remember(tpl) { mutableStateOf(tpl ?: "") }
            OutlinedTextField(t, { t = it.take(300) }, modifier = Modifier.fillMaxWidth(), minLines = 2)
            TextButton(onClick = { scope.launch { runCatching { client.postObj("/scam/template", JSONObject().put("template", t)) }.onSuccess { tpl = it.optString("template"); msg = "範本存好了" } } }) { Text("儲存") }
        }
        Section("新增詐騙範例", "看到新話術可以加進來，之後相似的訊息會被抓出來") {
            OutlinedTextField(sample, { sample = it.take(500) }, modifier = Modifier.fillMaxWidth(), minLines = 2, placeholder = { Text("貼上詐騙訊息（記得把電話、ID 遮掉）") })
            TextButton(enabled = sample.length >= 4, onClick = { scope.launch { runCatching { client.post("/scam/samples", JSONObject().put("text", sample).put("label", "SCAM")) }.onSuccess { sample = ""; msg = "加好了" }.onFailure { msg = friendly(it) } } }) { Text("加入範例") }
        }
        msg?.let { Text(it, color = LineGreen) }
        Spacer(Modifier.height(16.dp))
    }
}

// ============================ 社群貼文草稿 ============================
@Composable
fun SocialScreen(client: ControlClient, chats: List<ChatItem>, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var chat by remember { mutableStateOf(chats.firstOrNull()?.id ?: "") }
    var platform by remember { mutableStateOf("facebook") }
    var mode by remember { mutableStateOf("A") }
    var note by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var draft by remember { mutableStateOf<JSONObject?>(null) }
    var msg by remember { mutableStateOf<String?>(null) }
    Page("社群貼文草稿", onBack) {
        Text("從聊天內容整理成你的口吻草稿。只產生草稿，App 不會幫你發文。改作自 Hao0321/claude-skill-social-post（MIT）。", fontSize = 12.sp, color = Color.Gray)
        if (chats.isEmpty()) { Text("先把聊天加入 AI 代聊名單才能用喔", modifier = Modifier.padding(vertical = 16.dp)); return@Page }
        Section("素材") {
            Column { chats.forEach { c -> Row(Modifier.clickable { chat = c.id }, verticalAlignment = Alignment.CenterVertically) { RadioButton(chat == c.id, { chat = c.id }); Text(c.name) } } }
            Chips(listOf("facebook" to "FB", "instagram" to "IG", "threads" to "Threads", "x" to "X"), platform) { platform = it }
            Chips(listOf("A" to "心得", "B" to "重點整理", "C" to "短評"), mode) { mode = it }
            OutlinedTextField(note, { note = it.take(500) }, label = { Text("想強調什麼？（選填）") }, modifier = Modifier.fillMaxWidth())
            Button(enabled = !busy && chat.isNotEmpty(), onClick = { busy = true; scope.launch {
                runCatching { client.postObj("/social/draft", JSONObject().put("chat_id", chat).put("platform", platform).put("mode", mode).put("note", note), timeoutMs = 90_000) }
                    .onSuccess { draft = it; msg = null }.onFailure { msg = friendly(it) }
                busy = false
            } }) { Text(if (busy) "整理中…" else "產生草稿") }
        }
        draft?.let { d ->
            Section("草稿") {
                Text(d.optString("text"))
                d.optJSONArray("warnings")?.let { w -> (0 until w.length()).forEach { Text("⚠️ ${w.getString(it)}", fontSize = 12.sp, color = Warn) } }
                OutlinedButton(onClick = { copyPlain(ctx, "草稿", d.optString("text")) }) { Text("複製草稿") }
            }
        }
        msg?.let { Text(it, color = Danger) }
    }
}
