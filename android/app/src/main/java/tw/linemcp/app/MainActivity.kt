package tw.linemcp.app

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

data class ChatItem(val id: String, val name: String, val type: String, val allowed: Boolean)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startForegroundService(Intent(this, NodeService::class.java))
        val client = ControlClient(Secrets.controlToken(this))
        setContent { MaterialTheme { AppScreen(client) } }
    }
}

@Composable
fun AppScreen(client: ControlClient) {
    var state by remember { mutableStateOf<JSONObject?>(null) }
    var chats by remember { mutableStateOf(listOf<ChatItem>()) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        while (true) {
            state = runCatching { client.state() }.getOrNull()
            if (state?.optString("phase") == "online") {
                chats = runCatching {
                    val a = client.chats()
                    (0 until a.length()).map { i -> a.getJSONObject(i).let {
                        ChatItem(it.getString("id"), it.optString("name", it.getString("id")), it.getString("type"), it.getBoolean("allowed"))
                    } }
                }.getOrDefault(chats)
            }
            delay(2000)
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        when (val phase = state?.optString("phase")) {
            null -> Text("啟動本機服務中…")
            "logged_out", "error" -> {
                Text("以次要裝置登入 LINE（手機保持登入）")
                state?.optString("error")?.takeIf { it.isNotEmpty() }?.let { Text("錯誤：$it", color = MaterialTheme.colorScheme.error) }
                Button(onClick = { scope.launch { client.startQrLogin() } }) { Text("產生 QR Code") }
            }
            "waiting_qr_scan" -> {
                Text("請用手機 LINE 掃描（另一支手機或電腦螢幕顯示此畫面）")
                state?.optString("qrUrl")?.takeIf { it.isNotEmpty() }?.let { QrImage(it) }
            }
            "waiting_pin" -> Text("請在手機 LINE 輸入 PIN：${state?.optString("pin")}", style = MaterialTheme.typography.headlineMedium)
            "online" -> {
                Text("已登入：${state?.optJSONObject("profile")?.optString("displayName")}")
                Text("勾選＝允許 AI / MCP 存取", style = MaterialTheme.typography.labelMedium)
                LazyColumn {
                    items(chats, key = { it.id }) { c ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = c.allowed, onCheckedChange = { v ->
                                scope.launch { client.setAllowed(c.id, v) }
                                chats = chats.map { if (it.id == c.id) it.copy(allowed = v) else it }
                            })
                            Text("${c.name}  ·  ${c.type}")
                        }
                    }
                }
            }
            else -> Text("狀態：$phase")
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
