package tw.linemcp.app

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.graphics.Bitmap
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

val LineGreen = Color(0xFF06C755)
val LineBg = Color(0xFF8CABD8)   // LINE 聊天室背景藍
val BubbleMine = Color(0xFF85E249)
val Warn = Color(0xFFE8A317)
val Danger = Color(0xFFD93025)
val Soft = Color(0xFFF5F6F7)

fun fmtTime(ms: Long): String = if (ms <= 0) "" else SimpleDateFormat("HH:mm", Locale.TAIWAN).format(Date(ms))
fun fmtDateTime(ms: Long): String = if (ms <= 0) "" else SimpleDateFormat("M/d HH:mm", Locale.TAIWAN).format(Date(ms))

/** 把後端的錯誤碼翻成白話 */
fun friendly(e: Throwable): String = when ((e as? ControlError)?.code) {
    "kill_switch" -> "緊急停止中，先到總控台解除"
    "ai_disabled" -> "AI 代聊總開關還沒打開（總控台）"
    "chat_not_allowed" -> "這個聊天沒有開放給 AI / MCP"
    "ai_not_allowed" -> "這個聊天還沒加入 AI 代聊名單"
    "mode_off" -> "這個聊天的 AI 模式是關閉的"
    "image_not_allowed" -> "這個聊天沒有開放生成圖片"
    "outside_active_hours" -> "現在不在你設定的活躍時段"
    "rate_interval" -> "傳太快了，等一下再試"
    "hourly_cap", "chat_daily_cap", "daily_cap" -> "已經到上限了，今天先休息一下"
    else -> e.message ?: "出了點問題"
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
fun Section(title: String, sub: String? = null, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(title, fontWeight = FontWeight.Bold, fontSize = 15.sp)
        if (sub != null) Text(sub, fontSize = 12.sp, color = Color.Gray)
        Spacer(Modifier.height(6.dp))
        Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(14.dp)) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
        }
    }
}

@Composable
fun ToggleRow(label: String, checked: Boolean, sub: String? = null, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label)
            if (sub != null) Text(sub, fontSize = 12.sp, color = Color.Gray)
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled, colors = SwitchDefaults.colors(checkedTrackColor = LineGreen))
    }
}

@Composable
fun <T> Chips(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        options.forEach { (v, label) ->
            FilterChip(selected = v == selected, onClick = { onSelect(v) }, label = { Text(label, fontSize = 13.sp) },
                colors = FilterChipDefaults.filterChipColors(selectedContainerColor = LineGreen.copy(alpha = 0.18f)))
        }
    }
}

@Composable
fun NumberField(label: String, value: Int, width: Dp = 110.dp, onChange: (Int) -> Unit) {
    var t by remember(value) { mutableStateOf(value.toString()) }
    OutlinedTextField(t, { s -> t = s.filter { it.isDigit() }.take(5); t.toIntOrNull()?.let(onChange) }, label = { Text(label, fontSize = 12.sp) },
        singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.width(width))
}

@Composable
fun Pill(text: String, color: Color) {
    Text(text, fontSize = 11.sp, color = color, modifier = Modifier.clip(RoundedCornerShape(50)).background(color.copy(alpha = 0.12f)).padding(horizontal = 8.dp, vertical = 2.dp))
}

@Composable
fun Avatar(name: String, group: Boolean, size: Dp = 48.dp) {
    Box(Modifier.size(size).clip(CircleShape).background(if (group) Color(0xFF9FB3C8) else Color(0xFFB8D8A0)), contentAlignment = Alignment.Center) {
        Text(name.firstOrNull { it.isLetterOrDigit() }?.toString() ?: "?", color = Color.White, fontWeight = FontWeight.Bold, fontSize = (size.value * 0.42f).sp)
    }
}

private val stickerCache = mutableMapOf<String, Bitmap?>()

@Composable
fun StickerImage(client: ControlClient, stickerId: String, size: Dp = 96.dp) {
    val bmp by produceState(stickerCache[stickerId], stickerId) {
        if (!stickerCache.containsKey(stickerId)) {
            val b = client.image("/sticker_img?id=" + ControlClient.enc(stickerId))
            stickerCache[stickerId] = b
            value = b
        }
    }
    bmp?.let { Image(it.asImageBitmap(), contentDescription = "貼圖", modifier = Modifier.size(size)) }
        ?: Box(Modifier.size(size).clip(RoundedCornerShape(12.dp)).background(Color.White.copy(alpha = 0.6f)), contentAlignment = Alignment.Center) { Text("貼圖", color = Color.Gray, fontSize = 12.sp) }
}

@Composable
fun Loading(text: String = "載入中…") {
    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = LineGreen); Text(text, color = Color.Gray)
    }
}
