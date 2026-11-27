package tw.linemcp.app

import android.content.Context
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import org.json.JSONObject

/** Compiled into release/Review only; no QA preference reads or mode controls. */
internal object VariantFeatures {
    fun additionalProviders(): List<Pair<String, String>> = emptyList()
    fun configureEnvironment(ctx: Context, environment: MutableMap<String, String>) = Unit
    @Composable fun Settings(ctx: Context, restart: () -> Unit) = Unit
    @Composable fun StatusBadge(info: JSONObject?) = Unit
    @Composable fun ExecutionStatus(info: JSONObject?) { Text("執行模式：一般模式（不含 QA）") }
}
