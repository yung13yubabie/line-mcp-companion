package tw.linemcp.app

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class ChatItem(val id: String, val name: String, val type: String, val allowed: Boolean, val preview: String, val lastAt: Long, val members: Int, val aiAllowed: Boolean = false, val aiMode: String = "off")
data class Msg(val id: String, val sender: String?, val fromSelf: Boolean, val sentAt: Long, val type: String, val text: String?, val mediaName: String?, val replyTo: String?, val stickerId: String?)

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // secreview SR-16：畫面含 MCP token、LINE 登入 QR 與聊天內容 → release 版禁止截圖 / 錄影 / 最近使用縮圖
        if (!BuildConfig.DEBUG) window.setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE)
        if (BuildConfig.DEBUG) {
            // debug：主執行緒上的磁碟 / 網路存取都記到 logcat（tag StrictMode），用來稽核 ANR 風險
            android.os.StrictMode.setThreadPolicy(android.os.StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        // App 在前景時用 startService 啟動（沒有 5 秒 startForeground 期限），Service 內再升級為前景服務
        startService(Intent(this, NodeService::class.java))
        val ctx = applicationContext
        Keepalive.schedule(ctx)
        setContent {
            // Keystore/EncryptedSharedPreferences 很慢，不能在主執行緒做（否則 ANR）
            val boot by produceState<Triple<String, String, Boolean>?>(null) {
                value = withContext(Dispatchers.IO) { Triple(Secrets.controlToken(ctx), Secrets.mcpToken(ctx), Prefs.disclaimerAccepted(ctx)) }
            }
            var accepted by remember(boot) { mutableStateOf(boot?.third ?: false) }
            MaterialTheme(colorScheme = lightColorScheme(primary = LineGreen)) {
                val b = boot
                when {
                    b == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) { CircularProgressIndicator(color = LineGreen); Text("準備中…") }
                    }
                    !accepted -> DisclaimerScreen(onAccept = { accepted = true; Thread { Prefs.setDisclaimerAccepted(ctx) }.start() })
                    else -> AppRoot(ControlClient(b.first))
                }
            }
        }
    }
}

object Prefs {
    private fun p(ctx: Context) = ctx.getSharedPreferences("app", Context.MODE_PRIVATE)
    fun disclaimerAccepted(ctx: Context) = p(ctx).getBoolean("disclaimer_v2", false)
    fun setDisclaimerAccepted(ctx: Context) { p(ctx).edit().putBoolean("disclaimer_v2", true).commit() }
}

const val DISCLAIMER = """這個 App 用的是非官方的 LINE 通訊協定（LINEJS），不是 LINE 官方提供的功能。

• LINE 可能因此限制或停用你的帳號，風險請自己評估
• 建議先用次要帳號或測試帳號試用
• 本專案與 LY Corporation（LINE）沒有任何關係，也沒有獲得授權
• 同步資料保存在這支手機；內建 AI 預設關閉
• 開啟雲端模型或提供 MCP 連接器存取後，允許的內容會傳到對應服務；去識別化不能保證移除所有個資
• 索引、附件與部分中繼資料存於 App 私有空間，並非整個資料庫及所有檔案都加密"""

@Composable
fun DisclaimerScreen(onAccept: () -> Unit) {
    var checked by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(Color.White).verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Spacer(Modifier.height(24.dp))
        Text("開始前先看一下 🙏", fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text(DISCLAIMER.trimIndent(), lineHeight = 22.sp)
        if (BuildConfig.BUILD_TYPE == "review") Text("這是修復驗證版，尚未通過正式發布驗收。請只使用測試帳號與非敏感資料。", color = Warn, lineHeight = 22.sp)
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { checked = !checked }) {
            Checkbox(checked, { checked = it }, colors = CheckboxDefaults.colors(checkedColor = LineGreen))
            Text("我了解帳號可能被限制的風險")
        }
        Button(onClick = onAccept, enabled = checked, modifier = Modifier.fillMaxWidth()) { Text("我了解，繼續") }
    }
}

val LINK_RE = Regex("https?://|(?:[a-z0-9-]+\\.)+[a-z]{2,}/", RegexOption.IGNORE_CASE)

sealed interface Screen {
    data object Chats : Screen
    data object Console : Screen
    data object Settings : Screen
    data class Room(val chat: ChatItem, val focus: String? = null) : Screen
    data object Digest : Screen
    data object Queue : Screen
    data object AiSettings : Screen
    data class ChatAi(val chatId: String, val name: String, val type: String) : Screen
    data object Scam : Screen
    data object Social : Screen
    data object Logs : Screen
}

@Composable
fun AppRoot(client: ControlClient) {
    var state by remember { mutableStateOf<JSONObject?>(null) }
    var chats by remember { mutableStateOf(listOf<ChatItem>()) }
    var stack by remember { mutableStateOf(listOf<Screen>(Screen.Chats)) }
    var untrusted by remember { mutableStateOf(false) }
    val screen = stack.last()
    val scope = rememberCoroutineScope()
    fun go(s: Screen) { stack = stack + s }
    fun tab(s: Screen) { stack = listOf(s) }
    fun back() { if (stack.size > 1) stack = stack.dropLast(1) }

    LaunchedEffect(Unit) {
        while (true) {
            val r = runCatching { client.state() }
            untrusted = (r.exceptionOrNull() as? ControlError)?.code == "server_untrusted"
            state = r.getOrNull()
            if (state?.optString("phase") == "online") {
                chats = runCatching {
                    val a = client.chats()
                    (0 until a.length()).map { i -> a.getJSONObject(i).let {
                        ChatItem(it.getString("id"), it.optString("name", it.getString("id")), it.getString("type"), it.getBoolean("allowed"),
                            it.optString("preview", ""), it.optLong("last_message_at", 0), it.optInt("member_count", 0), it.optBoolean("ai_allowed"), it.optString("ai_mode", "off"))
                    } }
                }.getOrDefault(chats)
            }
            delay(2500)
        }
    }

    BackHandler(enabled = stack.size > 1) { back() }
    val online = state?.optString("phase") == "online"
    Scaffold(bottomBar = {
        if (screen is Screen.Chats || screen is Screen.Console || screen is Screen.Digest || screen is Screen.Settings) {
            NavigationBar(containerColor = Color.White) {
                listOf(Screen.Chats to "聊天", Screen.Console to "總控台", Screen.Digest to "日報", Screen.Settings to "設定").forEach { (s, label) ->
                    NavigationBarItem(selected = screen == s, onClick = { tab(s) }, icon = { Text(when (s) { Screen.Chats -> "💬"; Screen.Console -> "🎛"; Screen.Digest -> "📰"; else -> "⚙️" }) }, label = { Text(label) })
                }
            }
        }
    }) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            if (untrusted) {
                // H-1：未通過服務身分／回應完整性驗證；不推定原因，不顯示未驗證內容。
                Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("⚠️ 本機服務身分驗證失敗", color = Danger, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    Text("連接埠 ${BuildConfig.CONTROL_PORT} 上的服務未通過身分或回應完整性驗證，連線已停止。請先檢查本機服務狀態，再重新操作。", fontSize = 14.sp)
                    Text("請確認本 App 的本機服務已啟動，關閉再開啟本 App 後重試；若仍無法驗證，保持停止連線。", fontSize = 14.sp)
                }
                return@Box
            }
            when (val s = screen) {
                Screen.Chats -> if (online) ChatListScreen(state!!, chats,
                    onToggle = { c, v -> scope.launch { runCatching { client.setAllowed(c.id, v) } }; chats = chats.map { if (it.id == c.id) it.copy(allowed = v) else it } },
                    onOpen = { go(Screen.Room(it)) })
                else LoginScreen(state, onQr = { scope.launch { runCatching { client.startQrLogin() } } })
                Screen.Console -> ConsoleScreen(client, ::go)
                Screen.Settings -> SettingsScreen(client)
                Screen.Digest -> DigestScreen(client, chats, onJump = { c, id -> go(Screen.Room(c, id)) })
                is Screen.Room -> ChatRoomScreen(client, s.chat, s.focus, onBack = ::back, onAiSettings = { go(Screen.ChatAi(s.chat.id, s.chat.name, s.chat.type)) })
                Screen.Queue -> QueueScreen(client, onBack = ::back)
                Screen.AiSettings -> AiSettingsScreen(client, onBack = ::back)
                is Screen.ChatAi -> ChatAiScreen(client, s.chatId, s.name, s.type, onBack = ::back)
                Screen.Scam -> ScamScreen(client, onBack = ::back, onChat = { id, name -> go(Screen.ChatAi(id, name, "GROUP")) })
                Screen.Social -> SocialScreen(client, chats.filter { it.allowed && it.aiAllowed }, onBack = ::back)
                Screen.Logs -> LogsScreen(client, onBack = ::back)
            }
        }
    }
}

@Composable
fun LoginScreen(state: JSONObject?, onQr: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.White)) {
        TopBar("LINE MCP")
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (state?.optString("phase")) {
                null -> Loading("本機服務啟動中…")
                "waiting_qr_scan" -> {
                    Text("用手機 LINE 掃這個 QR（從另一台裝置顯示這個畫面）")
                    state.optString("qrUrl").takeIf { it.isNotEmpty() }?.let { QrImage(it) }
                }
                "waiting_pin" -> Text("在手機 LINE 輸入 PIN：${state.optString("pin")}", style = MaterialTheme.typography.headlineMedium)
                else -> {
                    Text("用次要裝置登入 LINE（手機那邊會繼續登入）")
                    Text("提醒：非官方協定，帳號可能被限制，建議用次要帳號。", fontSize = 12.sp, color = Warn)
                    state.optString("error").takeIf { it.isNotEmpty() }?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    Button(onClick = onQr) { Text("產生 QR Code") }
                }
            }
        }
    }
}

@Composable
fun ChatListScreen(state: JSONObject, chats: List<ChatItem>, onToggle: (ChatItem, Boolean) -> Unit, onOpen: (ChatItem) -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.White)) {
        TopBar("聊天")
        Row(Modifier.fillMaxWidth().background(Color(0xFFF3F8F3)).padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text("${state.optJSONObject("profile")?.optString("displayName")} · 勾選＝開放給 MCP · 已讀回條：封鎖", fontSize = 12.sp, color = Color(0xFF555555))
        }
        LazyColumn {
            items(chats, key = { it.id }) { c ->
                Row(Modifier.fillMaxWidth().clickable { onOpen(c) }.padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(c.name, c.type != "USER")
                    Column(Modifier.weight(1f).padding(horizontal = 12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(if (c.members > 0) "${c.name} (${c.members})" else c.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                            if (c.allowed && c.aiAllowed && c.aiMode != "off") Pill(if (c.aiMode == "auto") "代聊" else "建議", LineGreen)
                        }
                        Text(c.preview, color = Color.Gray, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(fmtTime(c.lastAt), color = Color.Gray, fontSize = 11.sp)
                        Checkbox(checked = c.allowed, onCheckedChange = { onToggle(c, it) }, colors = CheckboxDefaults.colors(checkedColor = LineGreen))
                    }
                }
            }
        }
    }
}

fun parseMsgs(a: JSONArray): List<Msg> = (0 until a.length()).map { i -> a.getJSONObject(i).let {
    Msg(it.getString("id"), it.optString("sender_name").ifEmpty { null }, it.optInt("from_self") == 1, it.getLong("sent_at"),
        it.optString("content_type"), if (it.isNull("text")) null else it.getString("text"), if (it.isNull("media_name")) null else it.getString("media_name"),
        if (it.isNull("reply_to")) null else it.optString("reply_to"), it.optJSONObject("sticker")?.optString("sticker_id"))
} }

fun msgPreview(m: Msg): String = when (m.type) {
    "IMAGE" -> "🖼 ${m.mediaName ?: "圖片"}"
    "FILE" -> "📄 ${m.mediaName ?: "檔案"}"
    "STICKER" -> "[貼圖]"
    "NONE" -> m.text ?: ""
    else -> "[${m.type}]"
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ChatRoomScreen(client: ControlClient, chat: ChatItem, focus: String? = null, onBack: () -> Unit, onAiSettings: () -> Unit) {
    var linkMsg by remember { mutableStateOf<Msg?>(null) }
    var msgs by remember { mutableStateOf(listOf<Msg>()) }
    var loaded by remember { mutableStateOf(false) }
    var replyTarget by remember { mutableStateOf<Msg?>(null) }
    var refresh by remember { mutableIntStateOf(0) }
    val list = rememberLazyListState()
    LaunchedEffect(chat.id, refresh) {
        while (true) {
            val n = runCatching { parseMsgs(client.messages(chat.id, focus)) }.getOrNull()
            if (n != null && n != msgs) {
                msgs = n
                val fi = focus?.let { f -> n.indexOfFirst { it.id == f } } ?: -1
                if (fi >= 0) list.scrollToItem(maxOf(0, fi - 2)) else if (n.isNotEmpty()) list.scrollToItem(n.size - 1)
            }
            loaded = true
            delay(3000)
        }
    }
    Column(Modifier.fillMaxSize().background(LineBg)) {
        TopBar(chat.name, onBack = onBack, action = { Text("AI 設定", color = LineGreen, modifier = Modifier.clickable { onAiSettings() }) })
        Row(Modifier.fillMaxWidth().background(Color.White).padding(horizontal = 16.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(if (chat.allowed) "MCP 可讀取" else "MCP 看不到這裡", fontSize = 12.sp, color = if (chat.allowed) LineGreen else Color.Gray, modifier = Modifier.weight(1f))
            Text("長按訊息可以回覆這則", fontSize = 12.sp, color = Color.Gray)
        }
        if (!loaded) LinearProgressIndicator(Modifier.fillMaxWidth(), color = LineGreen)
        LazyColumn(Modifier.weight(1f).padding(horizontal = 10.dp), state = list, contentPadding = PaddingValues(vertical = 8.dp)) {
            items(msgs, key = { it.id }) { m ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = if (m.fromSelf) Arrangement.End else Arrangement.Start, verticalAlignment = Alignment.Bottom) {
                    if (m.fromSelf) Text(fmtTime(m.sentAt), fontSize = 10.sp, color = Color.White, modifier = Modifier.padding(end = 4.dp))
                    Column(horizontalAlignment = if (m.fromSelf) Alignment.End else Alignment.Start,
                        modifier = Modifier.combinedClickable(onClick = {}, onLongClick = { replyTarget = m })) {
                        if (!m.fromSelf && chat.type != "USER") Text(m.sender ?: "", fontSize = 11.sp, color = Color.White)
                        if (m.type == "STICKER" && m.stickerId != null) {
                            StickerImage(client, m.stickerId)
                        } else {
                            Column(Modifier.widthIn(max = 260.dp).clip(RoundedCornerShape(16.dp)).background(if (m.id == focus) Color(0xFFFFF3B0) else if (m.fromSelf) BubbleMine else Color.White).padding(horizontal = 12.dp, vertical = 8.dp)) {
                                m.replyTo?.let { rid ->
                                    val q = msgs.firstOrNull { it.id == rid }
                                    Row(Modifier.padding(bottom = 4.dp)) {
                                        Box(Modifier.width(3.dp).height(32.dp).background(Color(0x55000000)))
                                        Column(Modifier.padding(start = 6.dp)) {
                                            Text(q?.let { if (it.fromSelf) "你" else it.sender ?: "" } ?: "", fontSize = 11.sp, color = Color(0xFF555555))
                                            Text(q?.let { msgPreview(it) } ?: "（原訊息）", fontSize = 12.sp, color = Color(0xFF555555), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        }
                                    }
                                }
                                Text(msgPreview(m))
                                if (m.text != null && LINK_RE.containsMatchIn(m.text)) Text("🔗 讀取連結", fontSize = 12.sp, color = LineGreen, modifier = Modifier.padding(top = 4.dp).clickable { linkMsg = m })
                            }
                        }
                    }
                    if (!m.fromSelf) Text(fmtTime(m.sentAt), fontSize = 10.sp, color = Color.White, modifier = Modifier.padding(start = 4.dp))
                }
            }
        }
        Row(Modifier.fillMaxWidth().background(Color.White).padding(12.dp)) { Text("不會標已讀。要回覆的話，長按那則訊息就好", color = Color.Gray, fontSize = 12.sp) }
    }
    linkMsg?.let { m -> LinkDialog(client, chat.id, m, onDismiss = { linkMsg = null }) }
    replyTarget?.let { t -> ReplyDialog(client, chat, t, onDismiss = { replyTarget = null }, onSent = { replyTarget = null; refresh++ }) }
}

@Composable
fun ReplyDialog(client: ControlClient, chat: ChatItem, target: Msg, onDismiss: () -> Unit, onSent: () -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    var stickers by remember { mutableStateOf(listOf<String>()) }
    var picked by remember { mutableStateOf<Pair<String, String>?>(null) }
    LaunchedEffect(Unit) {
        stickers = runCatching { client.getArr("/stickers").let { a -> (0 until a.length()).map { a.getJSONObject(it) }.filter { it.optBoolean("owned") }.map { it.getString("package_id") + ":" + it.getString("sticker_id") } } }.getOrDefault(emptyList())
    }
    AlertDialog(onDismissRequest = onDismiss,
        title = { Text("回覆這則", fontSize = 18.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.clip(RoundedCornerShape(8.dp)).background(Soft).padding(8.dp)) {
                    Text("${if (target.fromSelf) "你" else target.sender ?: chat.name}：${msgPreview(target)}", fontSize = 13.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
                OutlinedTextField(text, { text = it; picked = null }, placeholder = { Text("想說什麼？") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(enabled = !busy, onClick = {
                        busy = true; note = null
                        scope.launch {
                            runCatching { client.postObj("/suggest", JSONObject().put("chat_id", chat.id).put("reply_to", target.id), timeoutMs = 60_000) }
                                .onSuccess { s ->
                                    text = s.optString("text")
                                    s.optJSONObject("sticker")?.let { st -> picked = st.getString("package_id") to st.getString("sticker_id") }
                                    val flags = s.optJSONArray("flags")
                                    if (flags != null && flags.length() > 0) note = "幫你檢查過：這段有些地方要留意，送出前再看一眼"
                                }
                                .onFailure { note = friendly(it) }
                            busy = false
                        }
                    }) { Text(if (busy) "想一下…" else "✨ AI 幫我想") }
                    if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = LineGreen)
                }
                if (stickers.isNotEmpty()) {
                    Text("或回個貼圖（只列你用過的）", fontSize = 12.sp, color = Color.Gray)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        stickers.forEach { k ->
                            val (pkg, id) = k.split(":").let { it[0] to it[1] }
                            Box(Modifier.clip(RoundedCornerShape(10.dp)).background(if (picked?.second == id) LineGreen.copy(alpha = 0.25f) else Color.Transparent).clickable { picked = if (picked?.second == id) null else pkg to id }.padding(4.dp)) {
                                StickerImage(client, id, 52.dp)
                            }
                        }
                    }
                }
                note?.let { Text(it, fontSize = 12.sp, color = Warn) }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && (text.isNotBlank() || picked != null), onClick = {
                busy = true
                scope.launch {
                    val body = JSONObject().put("chat_id", chat.id).put("reply_to", target.id)
                    picked?.let { body.put("sticker", JSONObject().put("package_id", it.first).put("sticker_id", it.second)) } ?: body.put("text", text)
                    runCatching { client.postObj("/send", body) }.onSuccess { onSent() }.onFailure { note = friendly(it) }
                    busy = false
                }
            }) { Text("送出") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("算了") } })
}

@Composable
fun QrImage(url: String) {
    // QR 編碼 + 點陣轉換是 CPU 工作：放到 Dispatchers.Default
    val bmp by produceState<Bitmap?>(null, url) {
        value = withContext(Dispatchers.Default) {
            val m = QRCodeWriter().encode(url, BarcodeFormat.QR_CODE, 640, 640)
            val px = IntArray(m.width * m.height) { i -> if (m[i % m.width, i / m.width]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
            Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.RGB_565)
        }
    }
    bmp?.let { Image(it.asImageBitmap(), contentDescription = "LINE 登入 QR", modifier = Modifier.size(280.dp)) }
        ?: Box(Modifier.size(280.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
}
