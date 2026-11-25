package tw.linemcp.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import java.util.TimeZone

private val Ink = Color(0xFF222222)
private val Paper = Color(0xFFFBF8F1)
private val TPE: TimeZone = TimeZone.getTimeZone("Asia/Taipei")
private fun ymd(c: Calendar) = SimpleDateFormat("yyyy-MM-dd", Locale.TAIWAN).apply { timeZone = TPE }.format(c.time)
private fun ymdLabel(c: Calendar) = SimpleDateFormat("yyyy 年 M 月 d 日（E）", Locale.TAIWAN).apply { timeZone = TPE }.format(c.time)

// ============================ 日報 ============================
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DigestScreen(client: ControlClient, chats: List<ChatItem>, onJump: (ChatItem, String) -> Unit) {
    val scope = rememberCoroutineScope()
    var day by remember { mutableStateOf(Calendar.getInstance(TPE)) }
    var filter by remember { mutableStateOf<String?>(null) }
    var data by remember { mutableStateOf<JSONObject?>(null) }
    var schedules by remember { mutableStateOf(listOf<JSONObject>()) }
    var msg by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var pickDate by remember { mutableStateOf(false) }
    var postFor by remember { mutableStateOf<JSONObject?>(null) }
    var editSchedule by remember { mutableStateOf<JSONObject?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    val allowed = chats.filter { it.allowed }
    LaunchedEffect(ymd(day), filter, reload) {
        val q = "/digests?date=" + ymd(day) + (filter?.let { "&chat_ids=" + ControlClient.enc(it) } ?: "")
        runCatching { client.getObj(q) }.onSuccess { data = it; msg = null }.onFailure { msg = friendly(it) }
        schedules = runCatching { client.getObj("/digests/schedules").getJSONArray("schedules").objs() }.getOrDefault(schedules)
    }
    fun shift(n: Int) { day = (day.clone() as Calendar).apply { add(Calendar.DAY_OF_MONTH, n) } }

    Page("日報", null) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { shift(-1) }) { Text("◀") }
            Text(ymdLabel(day), modifier = Modifier.weight(1f).clickable { pickDate = true }, fontWeight = FontWeight.Medium, fontSize = 15.sp)
            TextButton(onClick = { pickDate = true }) { Text("📅") }
            TextButton(onClick = { shift(1) }) { Text("▶") }
        }
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(filter == null, { filter = null }, label = { Text("全部") })
            allowed.forEach { c -> FilterChip(filter == c.id, { filter = if (filter == c.id) null else c.id }, label = { Text(c.name, maxLines = 1) }) }
        }
        msg?.let { Text(it, color = Danger, fontSize = 13.sp) }
        val d = data
        if (d == null) Loading() else {
            val names = d.optJSONObject("chat_names") ?: JSONObject()
            val list = d.optJSONArray("digests")?.objs() ?: emptyList()
            if (list.isEmpty()) Text("這天還沒有日報。可以請 AI 助理（Claude / ChatGPT…）透過 MCP 的 save_digest 寫回，或用下面的按鈕產生。", fontSize = 13.sp, color = Color.Gray, modifier = Modifier.padding(vertical = 12.dp))
            list.forEach { dg -> DigestCard(dg, names, chats, onJump, onPost = { postFor = dg }, onDelete = {
                scope.launch { runCatching { client.post("/digests/delete", JSONObject().put("id", dg.getInt("id"))) }.onFailure { msg = friendly(it) }; reload++ }
            }) }
            if (d.optBoolean("can_generate")) {
                val target = filter ?: allowed.firstOrNull()?.id
                OutlinedButton(enabled = !busy && target != null, onClick = {
                    busy = true
                    scope.launch {
                        runCatching { client.postObj("/digests/generate", JSONObject().put("chat_id", target).put("date", ymd(day)), timeoutMs = 120_000) }.onFailure { msg = friendly(it) }
                        busy = false; reload++
                    }
                }) { Text(if (busy) "AI 整理中…" else "✨ 用 App 內建 AI 產生「${allowed.firstOrNull { it.id == target }?.name ?: ""}」這天的日報") }
            }
        }
        Section("定時貼到群組", "每天到點把當天日報貼到指定群組。一律走確認佇列 / 信任狀態、上限與緊急停止；網址會被拿掉") {
            if (schedules.isEmpty()) Text("還沒有排程", fontSize = 13.sp, color = Color.Gray)
            schedules.forEach { s ->
                Row(Modifier.fillMaxWidth().clickable { editSchedule = s }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("每天 ${s.optString("time_hhmm")} → ${s.optString("target_name")}", fontSize = 14.sp)
                        val src = s.optJSONArray("source_chats")?.let { a -> (0 until a.length()).map { i -> chats.firstOrNull { it.id == a.getString(i) }?.name ?: a.getString(i) } } ?: emptyList()
                        Text("來源：" + (if (src.isEmpty()) "所有白名單聊天" else src.joinToString("、")) + (if (s.optBoolean("generate")) "・沒有日報時先用 AI 產生" else ""), fontSize = 12.sp, color = Color.Gray)
                    }
                    Pill(if (s.optBoolean("enabled")) "啟用" else "暫停", if (s.optBoolean("enabled")) LineGreen else Color.Gray)
                }
            }
            TextButton(onClick = { editSchedule = JSONObject() }) { Text("＋ 新增排程") }
        }
    }
    if (pickDate) {
        val st = rememberDatePickerState(initialSelectedDateMillis = day.timeInMillis)
        DatePickerDialog(onDismissRequest = { pickDate = false },
            confirmButton = { TextButton(onClick = { st.selectedDateMillis?.let { ms -> day = Calendar.getInstance(TPE).apply { timeInMillis = ms } }; pickDate = false }) { Text("好") } },
            dismissButton = { TextButton(onClick = { pickDate = false }) { Text("取消") } }) { DatePicker(st) }
    }
    postFor?.let { dg -> PostDigestDialog(client, dg, chats.filter { it.allowed && it.aiAllowed }, onDone = { postFor = null; it?.let { m -> msg = m } }) }
    editSchedule?.let { s -> ScheduleDialog(client, s, allowed, chats.filter { it.allowed && it.aiAllowed }, onDone = { editSchedule = null; reload++ }) }
}

@Composable
fun DigestCard(dg: JSONObject, names: JSONObject, chats: List<ChatItem>, onJump: (ChatItem, String) -> Unit, onPost: () -> Unit, onDelete: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(6.dp)).background(Paper).padding(14.dp)) {
        val scope = dg.optJSONArray("chats")?.let { a -> (0 until a.length()).map { names.optString(a.getString(it), a.getString(it)) } } ?: emptyList()
        Text((if (dg.isNull("chat_id")) "跨聊天・" else "") + scope.joinToString("・"), fontSize = 11.sp, color = Color.Gray, letterSpacing = 1.sp)
        Text(dg.optString("title"), fontFamily = FontFamily.Serif, fontWeight = FontWeight.Bold, fontSize = 21.sp, color = Ink, modifier = Modifier.padding(vertical = 4.dp))
        HorizontalDivider(color = Ink, thickness = 2.dp)
        dg.optJSONArray("items")?.objs()?.forEachIndexed { i, it ->
            Column(Modifier.padding(top = 10.dp)) {
                Text("${i + 1}. " + it.optString("headline"), fontFamily = FontFamily.Serif, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, color = Ink)
                if (it.optString("body").isNotBlank()) Text(it.optString("body"), fontSize = 14.sp, color = Color(0xFF444444), modifier = Modifier.padding(top = 2.dp))
                val srcs = it.optJSONArray("sources")?.objs() ?: emptyList()
                if (srcs.isNotEmpty()) Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    srcs.take(6).forEach { s ->
                        val chat = chats.firstOrNull { c -> c.id == s.optString("chat_id") }
                        Text("↗ ${s.optString("sender").ifEmpty { "訊息" }} ${fmtTime(s.optLong("sent_at"))}", fontSize = 12.sp, color = LineGreen,
                            modifier = Modifier.clip(RoundedCornerShape(10.dp)).background(Color.White).clickable(enabled = chat != null) { onJump(chat!!, s.getString("message_id")) }.padding(horizontal = 8.dp, vertical = 3.dp))
                    }
                }
            }
        }
        HorizontalDivider(Modifier.padding(top = 10.dp), color = Color(0x33000000))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("來源：" + dg.optString("source") + "・" + fmtDateTime(dg.optLong("created_at")), fontSize = 11.sp, color = Color.Gray, modifier = Modifier.weight(1f))
            TextButton(onClick = onPost) { Text("📤 貼到群組") }
            TextButton(onClick = onDelete) { Text("刪除", color = Danger) }
        }
    }
}

@Composable
fun PostDigestDialog(client: ControlClient, dg: JSONObject, targets: List<ChatItem>, onDone: (String?) -> Unit) {
    val scope = rememberCoroutineScope()
    var target by remember { mutableStateOf(targets.firstOrNull()?.id) }
    var note by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = { onDone(null) }, title = { Text("把日報貼到…") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (targets.isEmpty()) Text("要先把目標群組加進 MCP 白名單和 AI 代聊名單", fontSize = 13.sp, color = Warn)
            targets.forEach { c -> Row(Modifier.fillMaxWidth().clickable { target = c.id }, verticalAlignment = Alignment.CenterVertically) { RadioButton(target == c.id, { target = c.id }); Text(c.name) } }
            Text("依目標群組的信任狀態：審核 → 先進確認佇列；自動 → 延遲後送。網址會被換成［連結］", fontSize = 12.sp, color = Color.Gray)
            note?.let { Text(it, color = Danger, fontSize = 13.sp) }
        }
    }, confirmButton = {
        TextButton(enabled = target != null, onClick = {
            scope.launch {
                runCatching { client.postObj("/digests/post", JSONObject().put("id", dg.getInt("id")).put("target_chat", target)) }
                    .onSuccess { onDone(if (it.optString("route") == "pending") "已放進確認佇列，到總控台核准後才會送出" else "已排程送出") }
                    .onFailure { note = friendly(it) }
            }
        }) { Text("貼出") }
    }, dismissButton = { TextButton(onClick = { onDone(null) }) { Text("取消") } })
}

@Composable
fun ScheduleDialog(client: ControlClient, s: JSONObject, sources: List<ChatItem>, targets: List<ChatItem>, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val isNew = !s.has("id")
    var target by remember { mutableStateOf(s.optString("target_chat").ifEmpty { targets.firstOrNull()?.id ?: "" }) }
    var time by remember { mutableStateOf(s.optString("time_hhmm").ifEmpty { "21:00" }) }
    var picked by remember { mutableStateOf(s.optJSONArray("source_chats")?.let { a -> (0 until a.length()).map { a.getString(it) }.toSet() } ?: emptySet()) }
    var generate by remember { mutableStateOf(s.optBoolean("generate")) }
    var enabled by remember { mutableStateOf(if (isNew) true else s.optBoolean("enabled")) }
    var note by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = onDone, title = { Text(if (isNew) "新增日報排程" else "編輯日報排程") }, text = {
        Column(Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(time, { time = it.take(5) }, label = { Text("每天幾點（台北時間 HH:MM）") }, singleLine = true)
            Text("貼到", fontSize = 13.sp)
            targets.forEach { c -> Row(Modifier.fillMaxWidth().clickable { target = c.id }, verticalAlignment = Alignment.CenterVertically) { RadioButton(target == c.id, { target = c.id }); Text(c.name) } }
            Text("來源聊天（不選＝所有白名單聊天）", fontSize = 13.sp)
            sources.forEach { c -> Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) { Checkbox(c.id in picked, { v -> picked = if (v) picked + c.id else picked - c.id }); Text(c.name) } }
            ToggleRow("沒有日報時先用 App AI 產生", generate) { generate = it }
            ToggleRow("啟用", enabled) { enabled = it }
            note?.let { Text(it, color = Danger, fontSize = 13.sp) }
        }
    }, confirmButton = {
        TextButton(onClick = {
            scope.launch {
                val b = JSONObject().put("target_chat", target).put("time_hhmm", time).put("source_chats", JSONArray(picked.toList())).put("generate", generate).put("enabled", enabled)
                if (!isNew) b.put("id", s.getInt("id"))
                runCatching { client.postObj("/digests/schedules", b) }.onSuccess { onDone() }.onFailure { note = friendly(it) }
            }
        }) { Text("儲存") }
    }, dismissButton = {
        Row {
            if (!isNew) TextButton(onClick = { scope.launch { runCatching { client.post("/digests/schedules", JSONObject().put("id", s.getInt("id")).put("delete", true)) }; onDone() } }) { Text("刪除", color = Danger) }
            TextButton(onClick = onDone) { Text("取消") }
        }
    })
}

// ============================ 讀取連結 ============================
@Composable
fun LinkDialog(client: ControlClient, chatId: String, msg: Msg, onDismiss: () -> Unit) {
    var res by remember { mutableStateOf<JSONObject?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(msg.id) {
        runCatching { client.postObj("/links/read", JSONObject().put("chat_id", chatId).put("message_id", msg.id), timeoutMs = 40_000) }.onSuccess { res = it }.onFailure { err = friendly(it) }
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("🔗 讀取連結") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val r = res
            when {
                err != null -> Text(err!!, color = Danger)
                r == null -> Row(verticalAlignment = Alignment.CenterVertically) { CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = LineGreen); Text("  安全檢查中…") }
                r.optString("blocked") == "link_reading_off" -> Text("這個聊天沒開「讀取連結」。到聊天的 AI 設定裡打開。", fontSize = 13.sp)
                else -> (r.optJSONArray("results")?.objs() ?: emptyList()).forEach { x ->
                    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(if (x.optBoolean("ok")) Soft else Color(0xFFFDECEA)).padding(10.dp)) {
                        Text(x.optString("final_url").ifEmpty { x.optString("url") }, fontSize = 11.sp, color = Color.Gray, maxLines = 2)
                        if (x.optBoolean("ok")) {
                            Text(x.optString("title").ifEmpty { "（沒有標題）" }, fontWeight = FontWeight.SemiBold)
                            if (!x.isNull("description")) Text(x.optString("description"), fontSize = 13.sp)
                            Text(x.optString("text").take(300), fontSize = 12.sp, color = Color(0xFF555555), maxLines = 6)
                            val inj = x.optJSONArray("injection_flags")
                            if (inj != null && inj.length() > 0) Text("⚠️ 網頁裡有疑似對 AI 下指令的文字，已標記為不可信", fontSize = 12.sp, color = Warn)
                            Text("網頁內容不可信；只讀文字，不執行 JS、不帶 cookie", fontSize = 11.sp, color = Color.Gray)
                        } else {
                            Text("🚫 已擋下：" + blockedLabel(x.optString("blocked")), color = Danger, fontWeight = FontWeight.SemiBold)
                            Text("沒有連線到這個網站", fontSize = 12.sp, color = Color.Gray)
                        }
                    }
                }
            }
        }
    }, confirmButton = { TextButton(onClick = onDismiss) { Text("關閉") } })
}

fun blockedLabel(b: String): String = when {
    b == "known_scam_domain" -> "已知詐騙網域"
    b == "line_invite_link" -> "LINE 邀請 / 加好友連結"
    b == "private_address" -> "指向內部網路（SSRF 防護）"
    b == "scam_rules" -> "反詐規則判定可疑"
    b.startsWith("safe_browsing") -> "Google Safe Browsing 標記為威脅"
    b == "too_many_redirects" -> "轉址太多次"
    b == "scheme_not_allowed" -> "不是 http / https"
    b.startsWith("content_type") -> "不是網頁（" + b.substringAfter(":") + "）"
    b == "dns_failed" -> "找不到這個網站"
    else -> b
}
