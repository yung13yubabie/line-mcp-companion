package tw.linemcp.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

val SCAM_ACTION = linkedMapOf(
    "" to "全部", "queued" to "待確認", "scheduled" to "排程", "sent" to "已提醒", "alert_only" to "只記錄",
    "suppressed_member" to "信任成員", "cooldown" to "冷卻中", "daily_cap" to "達上限", "false_positive" to "誤判", "rejected" to "取消",
)
val AI_EVENT = linkedMapOf("" to "全部", "generated" to "產生", "edited" to "修改", "approved" to "核准", "rejected" to "退回", "sent" to "送出", "failed" to "失敗")

/** 反詐紀錄 / AI 代聊紀錄（加密保存在手機；可篩選、匯出 CSV、清除、設定保留天數） */
@Composable
fun LogsScreen(client: ControlClient, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableStateOf("scam") }
    var filter by remember { mutableStateOf("") }
    var chatFilter by remember { mutableStateOf("") }
    var rows by remember { mutableStateOf<List<JSONObject>?>(null) }
    var retention by remember { mutableIntStateOf(30) }
    var msg by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    var tick by remember { mutableIntStateOf(0) }
    fun query(csv: Boolean) = buildString {
        append(if (tab == "scam") "/logs/scam?limit=500" else "/logs/ai?limit=500")
        if (filter.isNotEmpty()) append(if (tab == "scam") "&action=" else "&event=").append(ControlClient.enc(filter))
        if (chatFilter.isNotEmpty()) append("&chat_id=").append(ControlClient.enc(chatFilter))
        if (csv) append("&format=csv")
    }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        if (uri != null) scope.launch {
            runCatching {
                val bytes = client.getBytes(query(true))
                withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } }
            }.onSuccess { msg = "匯出好了" }.onFailure { msg = friendly(it) }
        }
    }
    LaunchedEffect(tab, filter, chatFilter, tick) {
        rows = runCatching { client.getArr(query(false)).objs() }.getOrDefault(emptyList())
        retention = runCatching { client.getObj("/logs/settings").optInt("retention_days", 30) }.getOrDefault(retention)
    }
    Page("紀錄", onBack) {
        Text("人名與訊息內容用資料金鑰加密存在這支手機。", fontSize = 12.sp, color = Color.Gray)
        Chips(listOf("scam" to "🛡 反詐", "ai" to "🤖 AI 代聊"), tab) { tab = it; filter = "" }
        Chips((if (tab == "scam") SCAM_ACTION else AI_EVENT).toList(), filter) { filter = it }
        val list = rows ?: run { Loading(); return@Page }
        val chats = list.map { it.optString("chat_id") to it.optString("chat_name").ifEmpty { it.optString("chat_id").take(8) } }.distinct()
        if (chats.size > 1 || chatFilter.isNotEmpty()) Chips(listOf("" to "所有聊天") + chats.take(6), chatFilter) { chatFilter = it }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = list.isNotEmpty(), onClick = { export.launch("${if (tab == "scam") "scam" else "ai"}-log.csv") }) { Text("匯出 CSV") }
            OutlinedButton(onClick = { confirmClear = true }) { Text("清除") }
        }
        msg?.let { Text(it, color = LineGreen, fontSize = 13.sp) }
        if (list.isEmpty()) Text("沒有紀錄", color = Color.Gray, modifier = Modifier.padding(vertical = 16.dp))
        list.take(200).forEach { r ->
            if (tab == "scam") {
                Section("${r.optString("chat_name")}｜${r.optString("category")}", "${fmtDateTime(r.optLong("ts"))} · ${r.optString("sender_name").ifEmpty { r.optString("sender_mid") }}") {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Pill(SCAM_ACTION[r.optString("action")] ?: r.optString("action"), if (r.optString("action") == "sent") LineGreen else if (r.optString("action") == "suppressed_member" || r.optString("action") == "false_positive") Color.Gray else Warn)
                        Text(if (r.optString("level") == "high") "高風險" else "可疑", fontSize = 12.sp, color = Color.Gray)
                    }
                    Text(r.optString("text"), fontSize = 13.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                    Text(r.optJSONArray("rules")?.let { a -> (0 until a.length()).joinToString("、") { a.getString(it) } } ?: "", fontSize = 11.sp, color = Color.Gray)
                }
            } else {
                Section(r.optString("chat_name"), "${fmtDateTime(r.optLong("ts"))} · ${originLabel(r.optString("origin"))} · ${actorLabel(r.optString("actor"))}") {
                    Pill(AI_EVENT[r.optString("event")] ?: r.optString("event"), if (r.optString("event") == "sent") LineGreen else Color.Gray)
                    if (!r.isNull("trigger_text")) Text("↩ ${r.optString("trigger_sender")}：${r.optString("trigger_text")}", fontSize = 12.sp, color = Color.Gray, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    if (!r.isNull("text")) Text(r.optString("text"), fontSize = 13.sp, maxLines = 4, overflow = TextOverflow.Ellipsis)
                    if (!r.isNull("detail")) Text(r.optString("detail"), fontSize = 11.sp, color = Color.Gray)
                }
            }
        }
        Section("保留") {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                var d by remember(retention) { mutableIntStateOf(retention) }
                NumberField("保留天數（1–365）", d, 160.dp) { d = it }
                TextButton(onClick = { scope.launch { runCatching { client.postObj("/logs/settings", JSONObject().put("retention_days", d)) }.onSuccess { retention = it.optInt("retention_days"); msg = "保留 ${retention} 天" } } }) { Text("套用") }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
    if (confirmClear) AlertDialog(onDismissRequest = { confirmClear = false }, title = { Text("清除紀錄？") },
        text = { Text("會刪除${if (tab == "scam") "反詐" else "AI 代聊"}紀錄，無法復原。", fontWeight = FontWeight.Normal) },
        confirmButton = { TextButton(onClick = { confirmClear = false; scope.launch { runCatching { client.postObj("/logs/clear", JSONObject().put("kind", tab)) }.onSuccess { msg = "清掉 ${it.optInt("cleared")} 筆"; tick++ } } }) { Text("清除", color = Danger) } },
        dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("取消") } })
}
