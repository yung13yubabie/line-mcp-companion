package tw.linemcp.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

val LineGreen = Color(0xFF06C755)
val LineBg = Color(0xFF8CABD8)   // LINE 聊天室背景藍
val BubbleMine = Color(0xFF85E249)

data class ChatItem(val id: String, val name: String, val type: String, val allowed: Boolean, val preview: String, val lastAt: Long, val members: Int)
data class Msg(val id: String, val sender: String?, val fromSelf: Boolean, val sentAt: Long, val type: String, val text: String?, val mediaName: String?)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (BuildConfig.DEBUG) {
            // debug：主執行緒上的磁碟 / 網路存取都記到 logcat（tag StrictMode），用來稽核 ANR 風險
            android.os.StrictMode.setThreadPolicy(android.os.StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        // App 在前景時用 startService 啟動（沒有 5 秒 startForeground 期限），Service 內再升級為前景服務
        startService(Intent(this, NodeService::class.java))
        val ctx = applicationContext
        setContent {
            // Keystore/EncryptedSharedPreferences 很慢，不能在主執行緒做（否則 ANR）
            val tokens by produceState<Pair<String, String>?>(null) {
                value = withContext(Dispatchers.IO) { Secrets.controlToken(ctx) to Secrets.mcpToken(ctx) }
            }
            MaterialTheme(colorScheme = lightColorScheme(primary = LineGreen)) {
                tokens?.let { AppRoot(ControlClient(it.first), it.second) } ?: Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("準備中…") }
            }
        }
    }
}

sealed interface Screen { data object Chats : Screen; data class Room(val chat: ChatItem) : Screen; data object Settings : Screen }

@Composable
fun AppRoot(client: ControlClient, mcpToken: String) {
    var state by remember { mutableStateOf<JSONObject?>(null) }
    var chats by remember { mutableStateOf(listOf<ChatItem>()) }
    var screen by remember { mutableStateOf<Screen>(Screen.Chats) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        while (true) {
            state = runCatching { client.state() }.getOrNull()
            if (state?.optString("phase") == "online") {
                chats = runCatching {
                    val a = client.chats()
                    (0 until a.length()).map { i -> a.getJSONObject(i).let {
                        ChatItem(it.getString("id"), it.optString("name", it.getString("id")), it.getString("type"), it.getBoolean("allowed"),
                            it.optString("preview", ""), it.optLong("last_message_at", 0), it.optInt("member_count", 0))
                    } }
                }.getOrDefault(chats)
            }
            delay(2000)
        }
    }

    BackHandler(enabled = screen != Screen.Chats) { screen = Screen.Chats }
    val phase = state?.optString("phase")
    when (val s = screen) {
        is Screen.Settings -> SettingsScreen(client, mcpToken, onBack = { screen = Screen.Chats })
        is Screen.Room -> ChatRoomScreen(client, s.chat, onBack = { screen = Screen.Chats })
        Screen.Chats -> when (phase) {
            "online" -> ChatListScreen(state!!, chats,
                onToggle = { c, v -> scope.launch { client.setAllowed(c.id, v) }; chats = chats.map { if (it.id == c.id) it.copy(allowed = v) else it } },
                onOpen = { screen = Screen.Room(it) }, onSettings = { screen = Screen.Settings })
            else -> LoginScreen(state, onQr = { scope.launch { client.startQrLogin() } }, onSettings = { screen = Screen.Settings })
        }
    }
}

@Composable
fun TopBar(title: String, onBack: (() -> Unit)? = null, action: (@Composable () -> Unit)? = null) {
    Row(Modifier.fillMaxWidth().background(Color.White).padding(horizontal = 12.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
        if (onBack != null) Text("＜", fontSize = 20.sp, modifier = Modifier.clickable { onBack() }.padding(end = 12.dp))
        Text(title, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
        action?.invoke()
    }
    HorizontalDivider(color = Color(0xFFE5E5E5))
}

@Composable
fun LoginScreen(state: JSONObject?, onQr: () -> Unit, onSettings: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.White)) {
        TopBar("LINE MCP", action = { Text("設定", color = LineGreen, modifier = Modifier.clickable { onSettings() }) })
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (state?.optString("phase")) {
                null -> Text("啟動本機服務中…")
                "waiting_qr_scan" -> {
                    Text("請用手機 LINE 掃描（從另一台裝置顯示此畫面）")
                    state.optString("qrUrl").takeIf { it.isNotEmpty() }?.let { QrImage(it) }
                }
                "waiting_pin" -> Text("請在手機 LINE 輸入 PIN：${state.optString("pin")}", style = MaterialTheme.typography.headlineMedium)
                else -> {
                    Text("以次要裝置登入 LINE（手機保持登入）")
                    state.optString("error").takeIf { it.isNotEmpty() }?.let { Text("錯誤：$it", color = MaterialTheme.colorScheme.error) }
                    Button(onClick = onQr) { Text("產生 QR Code") }
                }
            }
        }
    }
}

@Composable
fun Avatar(name: String, group: Boolean) {
    Box(Modifier.size(48.dp).clip(CircleShape).background(if (group) Color(0xFF9FB3C8) else Color(0xFFB8D8A0)), contentAlignment = Alignment.Center) {
        Text(name.trim().firstOrNull()?.toString() ?: "?", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 20.sp)
    }
}

fun fmtTime(ms: Long): String = if (ms <= 0) "" else SimpleDateFormat("HH:mm", Locale.TAIWAN).format(Date(ms))

@Composable
fun ChatListScreen(state: JSONObject, chats: List<ChatItem>, onToggle: (ChatItem, Boolean) -> Unit, onOpen: (ChatItem) -> Unit, onSettings: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.White)) {
        TopBar("聊天", action = { Text("設定", color = LineGreen, modifier = Modifier.clickable { onSettings() }) })
        Row(Modifier.fillMaxWidth().background(Color(0xFFF3F8F3)).padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text("${state.optJSONObject("profile")?.optString("displayName")} · 勾選＝允許 AI / MCP 存取 · 已讀回條：封鎖", fontSize = 12.sp, color = Color(0xFF555555))
        }
        LazyColumn {
            items(chats, key = { it.id }) { c ->
                Row(Modifier.fillMaxWidth().clickable { onOpen(c) }.padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(c.name, c.type != "USER")
                    Column(Modifier.weight(1f).padding(horizontal = 12.dp)) {
                        Text(if (c.members > 0) "${c.name} (${c.members})" else c.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
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

@Composable
fun ChatRoomScreen(client: ControlClient, chat: ChatItem, onBack: () -> Unit) {
    var msgs by remember { mutableStateOf(listOf<Msg>()) }
    var aiMode by remember { mutableStateOf(false) }
    LaunchedEffect(chat.id) {
        msgs = runCatching {
            val a = client.messages(chat.id)
            (0 until a.length()).map { i -> a.getJSONObject(i).let {
                Msg(it.getString("id"), it.optString("sender_name").ifEmpty { null }, it.optInt("from_self") == 1, it.getLong("sent_at"),
                    it.optString("content_type"), if (it.isNull("text")) null else it.getString("text"), if (it.isNull("media_name")) null else it.getString("media_name"))
            } }
        }.getOrDefault(emptyList())
    }
    Column(Modifier.fillMaxSize().background(LineBg)) {
        TopBar(chat.name, onBack = onBack)
        Row(Modifier.fillMaxWidth().background(Color.White).padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(if (chat.allowed) "MCP 可存取" else "MCP 不可存取（未勾選）", fontSize = 12.sp, color = if (chat.allowed) LineGreen else Color.Gray, modifier = Modifier.weight(1f))
            Text("AI 代聊（階段 5）", fontSize = 12.sp)
            Switch(checked = aiMode, onCheckedChange = { aiMode = it }, enabled = false)
        }
        LazyColumn(Modifier.weight(1f).padding(horizontal = 10.dp), contentPadding = PaddingValues(vertical = 8.dp)) {
            items(msgs, key = { it.id }) { m ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = if (m.fromSelf) Arrangement.End else Arrangement.Start, verticalAlignment = Alignment.Bottom) {
                    if (m.fromSelf) Text(fmtTime(m.sentAt), fontSize = 10.sp, color = Color.White, modifier = Modifier.padding(end = 4.dp))
                    Column(horizontalAlignment = if (m.fromSelf) Alignment.End else Alignment.Start) {
                        if (!m.fromSelf && chat.type != "USER") Text(m.sender ?: "", fontSize = 11.sp, color = Color.White)
                        val body = when (m.type) {
                            "IMAGE" -> "🖼 ${m.mediaName ?: "圖片"}"
                            "FILE" -> "📄 ${m.mediaName ?: "檔案"}"
                            "NONE" -> m.text ?: ""
                            else -> "[${m.type}]"
                        }
                        Text(body, modifier = Modifier.widthIn(max = 260.dp).clip(RoundedCornerShape(16.dp)).background(if (m.fromSelf) BubbleMine else Color.White).padding(horizontal = 12.dp, vertical = 8.dp))
                    }
                    if (!m.fromSelf) Text(fmtTime(m.sentAt), fontSize = 10.sp, color = Color.White, modifier = Modifier.padding(start = 4.dp))
                }
            }
        }
        Row(Modifier.fillMaxWidth().background(Color.White).padding(12.dp)) { Text("（唯讀：本 App 不會標已讀，也不會從這裡發送）", color = Color.Gray, fontSize = 12.sp) }
    }
}

fun copy(ctx: Context, label: String, text: String) {
    (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(ctx, "已複製$label", Toast.LENGTH_SHORT).show()
}

@Composable
fun SettingsScreen(client: ControlClient, mcpToken: String, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var info by remember { mutableStateOf<JSONObject?>(null) }
    val scope = rememberCoroutineScope()
    var mock by remember { mutableStateOf(false) }
    // SharedPreferences 讀取也是磁碟 IO → 背景執行緒
    LaunchedEffect(Unit) { mock = withContext(Dispatchers.IO) { MockMode.enabled(ctx) } }
    LaunchedEffect(Unit) { while (true) { info = runCatching { client.info() }.getOrNull(); delay(3000) } }
    val url = info?.optString("mcp_url") ?: "http://127.0.0.1:47823/mcp"
    fun restartNode() = ctx.startService(Intent(ctx, NodeService::class.java).setAction(NodeService.ACTION_RESTART))
    Column(Modifier.fillMaxSize().background(Color(0xFFF5F5F5))) {
        TopBar("設定", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("MCP 連線資訊", fontWeight = FontWeight.Bold)
            Card { Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("URL（Streamable HTTP，只限本機 127.0.0.1）", fontSize = 12.sp, color = Color.Gray)
                Text(url, fontFamily = FontFamily.Monospace)
                OutlinedButton(onClick = { copy(ctx, " URL", url) }) { Text("複製 URL") }
                Text("Authorization: Bearer token（App 內隨機產生，Keystore 加密保存）", fontSize = 12.sp, color = Color.Gray)
                Text(mcpToken, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                OutlinedButton(onClick = { copy(ctx, " token", mcpToken) }) { Text("複製 token") }
                OutlinedButton(onClick = { copy(ctx, " 設定 JSON", """{"mcpServers":{"line":{"type":"http","url":"$url","headers":{"Authorization":"Bearer $mcpToken"}}}}""") }) { Text("複製 MCP 用戶端設定 JSON") }
            } }
            Text("狀態", fontWeight = FontWeight.Bold)
            Card { Column(Modifier.padding(12.dp)) {
                Text("已讀回條：${info?.optString("read_receipts") ?: "-"}")
                Text("會話 / 允許 / 訊息：${info?.optJSONObject("counts")?.let { "${it.optInt("chats")} / ${it.optInt("allowed")} / ${it.optInt("messages")}" } ?: "-"}")
                Text("Node 執行模式：${if (info?.optBoolean("mock") == true) "Mock（假資料）" else "正式"}")
            } }
            if (BuildConfig.DEBUG) {
                Text("開發者（僅 debug 版）", fontWeight = FontWeight.Bold)
                Card { Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Mock 模式（假聊天資料，獨立資料庫）", modifier = Modifier.weight(1f))
                        Switch(checked = mock, onCheckedChange = { v -> mock = v; scope.launch(Dispatchers.IO) { MockMode.set(ctx, v); restartNode() } })
                    }
                    OutlinedButton(onClick = { mock = false; scope.launch(Dispatchers.IO) { MockMode.purge(ctx); restartNode() } }) { Text("清除全部 Mock 資料") }
                } }
            }
            Text("版本 ${BuildConfig.VERSION_NAME}（${if (BuildConfig.DEBUG) "debug" else "release"}）", fontSize = 12.sp, color = Color.Gray)
        }
    }
}

@Composable
fun QrImage(url: String) {
    val bmp = remember(url) {
        val m = QRCodeWriter().encode(url, BarcodeFormat.QR_CODE, 640, 640)
        Bitmap.createBitmap(m.width, m.height, Bitmap.Config.RGB_565).also { b ->
            for (x in 0 until m.width) for (y in 0 until m.height) b.setPixel(x, y, if (m[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
        }
    }
    Image(bmp.asImageBitmap(), contentDescription = "LINE 登入 QR", modifier = Modifier.size(280.dp))
}
