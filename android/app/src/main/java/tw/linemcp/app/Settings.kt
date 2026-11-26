package tw.linemcp.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.PowerManager
import android.provider.Settings as AndroidSettings
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** 一般複製（非敏感內容） */
fun copyPlain(ctx: Context, label: String, text: String) {
    (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(ctx, "已複製$label", Toast.LENGTH_SHORT).show()
}

/** 敏感內容複製：標記 IS_SENSITIVE（不顯示在剪貼簿預覽），60 秒後若還是我們放的就清掉 */
fun copySensitive(ctx: Context, label: String, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        if (Build.VERSION.SDK_INT >= 33) putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) else putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    cm.setPrimaryClip(clip)
    Toast.makeText(ctx, "已複製$label（60 秒後自動清除）", Toast.LENGTH_SHORT).show()
    Handler(Looper.getMainLooper()).postDelayed({
        runCatching {
            val cur = cm.primaryClip
            if (cur != null && cur.itemCount > 0 && cur.getItemAt(0).text?.toString() == text) cm.clearPrimaryClip()
        }
    }, 60_000)
}

/** 用指紋 / 臉部或螢幕鎖（PIN、圖形、密碼）確認是本人 */
fun authenticate(activity: FragmentActivity, reason: String, onOk: () -> Unit, onFail: (String) -> Unit) {
    val auth = if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_WEAK or DEVICE_CREDENTIAL
    val can = BiometricManager.from(activity).canAuthenticate(auth)
    if (can != BiometricManager.BIOMETRIC_SUCCESS) { onFail("這支手機還沒設定螢幕鎖，為了安全不能顯示 token"); return }
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onOk()
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onFail(errString.toString())
    })
    prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("確認是你本人").setSubtitle(reason).setAllowedAuthenticators(auth).build())
}

@Composable
fun SettingsScreen(client: ControlClient) {
    val ctx = LocalContext.current
    val activity = ctx as FragmentActivity
    val scope = rememberCoroutineScope()
    var info by remember { mutableStateOf<JSONObject?>(null) }
    var mock by remember { mutableStateOf(false) }
    var token by remember { mutableStateOf<String?>(null) }
    var revealed by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf<String?>(null) }
    var showDisclaimer by remember { mutableStateOf(false) }
    var batteryOk by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) {
        mock = withContext(Dispatchers.IO) { MockMode.enabled(ctx) }
        token = withContext(Dispatchers.IO) { Secrets.mcpToken(ctx) }
        batteryOk = (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager).isIgnoringBatteryOptimizations(ctx.packageName)
    }
    LaunchedEffect(Unit) { var last = ""; while (true) { val i = runCatching { client.info() }.getOrNull(); val s = i?.toString() ?: ""; if (s != last) { last = s; info = i }; delay(4000) } }
    // 顯示 30 秒後自動遮起來
    LaunchedEffect(revealed) { if (revealed) { delay(30_000); revealed = false } }
    val url = info?.optString("mcp_url") ?: "http://127.0.0.1:${BuildConfig.MCP_PORT}/mcp"
    fun restartNode() = ctx.startService(Intent(ctx, NodeService::class.java).setAction(NodeService.ACTION_RESTART))
    fun withAuth(reason: String, f: () -> Unit) = authenticate(activity, reason, f) { msg = it }
    val t = token ?: ""
    Page("設定", null) {
        Section("MCP 連線", "Streamable HTTP，只在這支手機的 127.0.0.1") {
            ToggleRow("允許本機 MCP 寫入", info?.optBoolean("mcp_allow_write") == true, "預設只讀；啟用後仍受會話白名單與送出確認限制") { enabled ->
                fun savePermission() { scope.launch {
                    runCatching { client.postObj("/mcp/permissions", JSONObject().put("mcp_allow_write", enabled)); client.info() }
                        .onSuccess { info = it }
                        .onFailure { msg = friendly(it) }
                } }
                if (enabled) withAuth("允許本機 MCP 寫入", ::savePermission) else savePermission()
            }
            Text(url, fontFamily = FontFamily.Monospace)
            OutlinedButton(onClick = { copyPlain(ctx, " URL", url) }) { Text("複製 URL") }
            Text("Bearer token（Keystore 加密保存）", fontSize = 12.sp, color = Color.Gray)
            Text(if (revealed) t else "•".repeat(12) + t.takeLast(4), fontFamily = FontFamily.Monospace, fontSize = 13.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { if (revealed) revealed = false else withAuth("顯示 MCP token") { revealed = true } }) { Text(if (revealed) "遮起來" else "顯示") }
                OutlinedButton(onClick = { withAuth("複製 MCP token") { copySensitive(ctx, " token", t) } }) { Text("複製 token") }
            }
            OutlinedButton(onClick = { withAuth("複製 MCP 用戶端設定") { copySensitive(ctx, "設定 JSON", """{"mcpServers":{"line":{"type":"http","url":"$url","headers":{"Authorization":"Bearer $t"}}}}""") } }) { Text("複製 MCP 用戶端設定 JSON") }
            OutlinedButton(onClick = { withAuth("產生新的 MCP token") {
                scope.launch {
                    runCatching { client.postObj("/mcp/rotate").getString("token") }
                        .onSuccess { nt -> withContext(Dispatchers.IO) { Secrets.setMcpToken(ctx, nt) }; token = nt; revealed = false; msg = "換好了，記得更新 AI 用戶端的設定；舊 token 已失效" }
                        .onFailure { msg = friendly(it) }
                }
            } }) { Text("🔄 換一組新 token") }
            msg?.let { Text(it, color = Warn, fontSize = 13.sp) }
        }
        ConnectorSection(client) { reason, f -> withAuth(reason, f) }
        Section("狀態") {
            if (info?.optString("mcp_error") == "port_in_use") Text("⚠️ MCP 連接埠 ${BuildConfig.MCP_PORT} 被其他 App 佔用：AI 用戶端可能連到冒牌服務，請先移除可疑 App 再重新啟動", color = Warn, fontSize = 13.sp)
            Text("已讀回條：${if (info?.optString("read_receipts") == "blocked") "封鎖中" else info?.optString("read_receipts") ?: "-"}")
            Text("敏感欄位金鑰：${when (info?.optString("data_key")) { "keystore" -> "Android Keystore"; "ephemeral" -> "Mock（臨時金鑰）"; null, "" -> "-"; else -> info?.optString("data_key") }}")
            Text("部分資料庫欄位加密；聊天索引、附件與部分中繼資料另存於 App 私有空間。", fontSize = 12.sp, color = Color.Gray)
            Text("會話 / 開放 / 訊息：${info?.optJSONObject("counts")?.let { "${it.optInt("chats")} / ${it.optInt("allowed")} / ${it.optInt("messages")}" } ?: "-"}")
            Text("執行模式：${if (info?.optBoolean("mock") == true) "Mock（假資料）" else "正式"}")
        }
        Section("背景執行", "讓同步和反詐提醒在背景也能持續") {
            if (batteryOk) Text("已允許在背景執行 👍", fontSize = 13.sp)
            else {
                Text("系統的省電最佳化可能會把服務停掉", fontSize = 13.sp)
                OutlinedButton(onClick = {
                    runCatching { ctx.startActivity(Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + ctx.packageName))) }
                        .onFailure { ctx.startActivity(Intent(AndroidSettings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
                }) { Text("允許背景執行") }
            }
        }
        Section("關於") {
            TextButton(onClick = { showDisclaimer = true }) { Text("風險說明（非官方協定）") }
            Text("版本 ${BuildConfig.VERSION_NAME}（${BuildConfig.BUILD_TYPE}）· 與 LY Corporation 無關", fontSize = 12.sp, color = Color.Gray)
            if (BuildConfig.BUILD_TYPE == "review") Text("獨立審查版：使用測試簽章與分開的本機資料，供驗證修復使用。", fontSize = 12.sp, color = Warn)
        }
        if (BuildConfig.DEBUG) {
            Section("開發者（只在 debug 版）") {
                ToggleRow("Mock 模式（假聊天資料，獨立資料庫）", mock) { v -> mock = v; scope.launch(Dispatchers.IO) { MockMode.set(ctx, v); restartNode() } }
                OutlinedButton(onClick = { mock = false; scope.launch(Dispatchers.IO) { MockMode.purge(ctx); restartNode() } }) { Text("清除全部 Mock 資料") }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
    if (showDisclaimer) AlertDialog(onDismissRequest = { showDisclaimer = false }, confirmButton = { TextButton(onClick = { showDisclaimer = false }) { Text("知道了") } },
        title = { Text("風險說明") }, text = { Text(DISCLAIMER.trimIndent()) })
}
