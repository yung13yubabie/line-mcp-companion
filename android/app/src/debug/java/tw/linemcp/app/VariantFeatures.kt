package tw.linemcp.app

import android.content.Context
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Debug-only controls and environment injection, excluded by source sets from production. */
internal object VariantFeatures {
    fun additionalProviders(): List<Pair<String, String>> = listOf("mock" to "Mock")
    fun configureEnvironment(ctx: Context, environment: MutableMap<String, String>) {
        if (MockMode.enabled(ctx)) environment["LINE_MCP_MOCK"] = "1"
    }
    @Composable fun StatusBadge(info: JSONObject?) {
        if (info?.optBoolean("mock") == true) Pill("Mock 示範資料", Warn)
    }
    @Composable fun ExecutionStatus(info: JSONObject?) {
        Text("執行模式：${if (info?.optBoolean("mock") == true) "Mock（假資料）" else "正式"}")
    }
    @Composable fun Settings(ctx: Context, restart: () -> Unit) {
        var enabled by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(Unit) { enabled = withContext(Dispatchers.IO) { MockMode.enabled(ctx) } }
        Section("開發者（只在 debug 版）") {
            ToggleRow("Mock 模式（假聊天資料，獨立資料庫）", enabled) { value ->
                enabled = value; scope.launch(Dispatchers.IO) { MockMode.set(ctx, value); restart() }
            }
            OutlinedButton(onClick = { enabled = false; scope.launch(Dispatchers.IO) { MockMode.purge(ctx); restart() } }) { Text("清除全部 Mock 資料") }
        }
    }
}
