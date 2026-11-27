package tw.linemcp.app

import java.net.URI

/** Presentation only: runtime reports readiness; this model performs no connection or key access. */
internal enum class LocalMcpServiceState { UNKNOWN, STARTING, UNAVAILABLE, READY }
internal enum class LocalMcpLegacyState { UNKNOWN, ENABLED, DISABLED }

internal data class LocalMcpPresentation(
    val state: LocalMcpServiceState,
    val legacyState: LocalMcpLegacyState,
    val secureEndpoint: String?,
    val adapterTemplate: String?,
    val portInUse: Boolean = false,
    val writeAllowed: Boolean = false,
) {
    val ready: Boolean get() = state == LocalMcpServiceState.READY
    // Existing permission can always be revoked through Control, even if MCP is unavailable.
    val canChangeWritePermission: Boolean get() = ready || writeAllowed
    val statusText: String get() = when (state) {
        LocalMcpServiceState.UNKNOWN -> "狀態未知（缺少有效服務資訊）"
        LocalMcpServiceState.STARTING -> "啟動中（尚未就緒）"
        LocalMcpServiceState.UNAVAILABLE -> "服務無法使用"
        LocalMcpServiceState.READY -> "已就緒（標準 stdio adapter）"
    }
    val detailText: String get() = when {
        portInUse -> "MCP 連接埠被佔用，服務未就緒。請排除衝突後重新啟動。"
        ready -> "受保護端點僅供本專案 stdio adapter 使用，不可貼到一般 HTTP MCP 網址欄位。"
        else -> "尚不能產生可用連線範本；請確認服務啟動成功並重新取得狀態。"
    }
    val legacyText: String get() = when (legacyState) {
        LocalMcpLegacyState.UNKNOWN -> "舊版 HTTP Bearer：實際狀態未知"
        LocalMcpLegacyState.ENABLED -> "舊版 HTTP Bearer：已啟用（相容模式）"
        LocalMcpLegacyState.DISABLED -> "舊版 HTTP Bearer：已停用"
    }
}

/** Strictly use typed actual runtime fields; configuration and legacy URLs are not evidence. */
internal fun presentLocalMcp(info: Map<String, *>?, requestFailed: Boolean = false): LocalMcpPresentation {
    val legacy = if (requestFailed) LocalMcpLegacyState.UNKNOWN else when (info?.get("mcp_legacy_http_enabled")) {
        true -> LocalMcpLegacyState.ENABLED
        false -> LocalMcpLegacyState.DISABLED
        else -> LocalMcpLegacyState.UNKNOWN
    }
    val error = info?.get("mcp_error")
    val hasError = error is String && error.isNotBlank()
    val malformedError = error != null && error !is String
    val endpoint = (info?.get("mcp_secure_url") as? String)?.takeIf(::validLocalMcpEndpoint)
    val contractValid = endpoint != null && info?.get("mcp_auth") == "mcp-psk-aead-v1" &&
        info?.get("transport") == "stdio-adapter" && legacy != LocalMcpLegacyState.UNKNOWN && !malformedError
    val state = when {
        requestFailed || hasError -> LocalMcpServiceState.UNAVAILABLE
        malformedError -> LocalMcpServiceState.UNKNOWN
        info?.get("mcp_status") == "starting" -> LocalMcpServiceState.STARTING
        info?.get("mcp_status") == "unavailable" -> LocalMcpServiceState.UNAVAILABLE
        info?.get("mcp_status") == "ready" && contractValid -> LocalMcpServiceState.READY
        else -> LocalMcpServiceState.UNKNOWN
    }
    val readyEndpoint = endpoint.takeIf { state == LocalMcpServiceState.READY }
    return LocalMcpPresentation(state = state, legacyState = legacy, secureEndpoint = readyEndpoint,
        adapterTemplate = readyEndpoint?.let(::localMcpTemplate), portInUse = error == "port_in_use",
        writeAllowed = info?.get("mcp_allow_write") == true)
}

private fun validLocalMcpEndpoint(value: String): Boolean = runCatching {
    val url = URI(value)
    url.scheme == "http" && url.host == "127.0.0.1" && url.port in 1..65535 &&
        url.rawAuthority == "127.0.0.1:${url.port}" && url.rawPath == "/mcp/secure" &&
        url.rawQuery == null && url.rawFragment == null && url.rawUserInfo == null
}.getOrDefault(false)

private fun localMcpTemplate(endpoint: String): String = """
    {
      "mcpServers": {
        "line": {
          "command": "node",
          "args": ["/absolute/path/to/line-mcp-companion/scripts/mcp-stdio.ts", "$endpoint"],
          "env": {"LMA_MCP_CHANNEL_KEY_FILE": "/absolute/path/to/private/mcp-channel.key"}
        }
      }
    }
""".trimIndent()
