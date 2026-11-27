package tw.linemcp.app

import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic local JVM unit tests; no Android, key, network or device connection is exercised. */
class LocalMcpPresentationTest {
    private fun readyInfo(port: Int = 47833): Map<String, Any?> = mapOf(
        "mcp_status" to "ready", "mcp_secure_url" to "http://127.0.0.1:$port/mcp/secure",
        "mcp_auth" to "mcp-psk-aead-v1", "transport" to "stdio-adapter",
        "mcp_legacy_http_enabled" to false, "mcp_legacy_http" to true, "mcp_error" to null,
    )
    private fun assertBlocked(info: Map<String, *>?, failed: Boolean = false) {
        val ui = presentLocalMcp(info, failed)
        assertTrue(!ui.ready && ui.secureEndpoint == null && ui.adapterTemplate == null)
    }
    @Test fun missingInfoNeverDerivesSecureUrl() {
        assertBlocked(null); assertBlocked(emptyMap<String, Any>())
        assertBlocked(mapOf("mcp_url" to "http://127.0.0.1:47823/mcp", "mcp_legacy_http" to true))
    }
    @Test fun actualPortAndSecretFreeTemplate() {
        val ui = presentLocalMcp(readyInfo(49152))
        assertTrue(ui.ready && ui.secureEndpoint == "http://127.0.0.1:49152/mcp/secure")
        val template = requireNotNull(ui.adapterTemplate)
        assertTrue(template.contains("http://127.0.0.1:49152/mcp/secure"))
        assertTrue(template.contains("\"LMA_MCP_CHANNEL_KEY_FILE\""))
        assertTrue(!template.contains("\"LMA_MCP_CHANNEL_KEY\""))
        assertTrue(template.contains("/absolute/path/to/private/mcp-channel.key"))
    }
    @Test fun runtimeLegacyOverridesConfiguration() {
        assertTrue(presentLocalMcp(readyInfo()).legacyState == LocalMcpLegacyState.DISABLED)
        val enabled = readyInfo() + mapOf("mcp_legacy_http_enabled" to true, "mcp_legacy_http" to false)
        assertTrue(presentLocalMcp(enabled).legacyState == LocalMcpLegacyState.ENABLED)
    }
    @Test fun unknownLegacyFlagBlocksTemplate() {
        for (value in listOf(null, "false", "true", 0, 1)) {
            val info = readyInfo() + ("mcp_legacy_http_enabled" to value)
            assertTrue(presentLocalMcp(info).legacyState == LocalMcpLegacyState.UNKNOWN); assertBlocked(info)
        }
    }
    @Test fun startingAndUnavailableHideEndpoint() {
        for ((status, state) in listOf("starting" to LocalMcpServiceState.STARTING, "unavailable" to LocalMcpServiceState.UNAVAILABLE)) {
            val info = readyInfo() + ("mcp_status" to status)
            assertBlocked(info); assertTrue(presentLocalMcp(info).state == state)
        }
    }
    @Test fun unrecognizedStatusNeverImpliesReady() {
        for (status in listOf(null, "running", "READY", true)) assertBlocked(readyInfo() + ("mcp_status" to status))
    }
    @Test fun errorsInvalidateStaleInfo() {
        val error = readyInfo() + ("mcp_error" to "port_in_use")
        assertBlocked(error); assertTrue(presentLocalMcp(error).portInUse)
        assertBlocked(readyInfo() + ("mcp_error" to "failed"))
        assertBlocked(readyInfo() + ("mcp_error" to true))
        assertBlocked(readyInfo(), true)
        assertTrue(presentLocalMcp(readyInfo(), true).legacyState == LocalMcpLegacyState.UNKNOWN)
    }
    @Test fun authAndTransportRequired() {
        for (field in listOf("mcp_auth", "transport")) {
            assertBlocked(readyInfo() - field)
            assertBlocked(readyInfo() + (field to "http"))
        }
    }
    @Test fun invalidEndpointNeverCopied() {
        val invalid = listOf(null, "", "null", "http://127.0.0.1:47833/mcp", "http://127.0.0.1:47833/mcp/secure/",
            "https://127.0.0.1:47833/mcp/secure", "http://localhost:47833/mcp/secure", "http://192.0.2.1:47833/mcp/secure",
            "http://127.0.0.1/mcp/secure", "http://127.0.0.1:0/mcp/secure", "http://127.0.0.1:65536/mcp/secure",
            "http://user@127.0.0.1:47833/mcp/secure", "http://127.0.0.1:47833/mcp/secure?key=synthetic",
            "http://127.0.0.1:47833/mcp/secure#fragment", "http://127.0.0.1:47833/mcp/%73ecure", " http://127.0.0.1:47833/mcp/secure")
        for (url in invalid) assertBlocked(readyInfo() + ("mcp_secure_url" to url))
    }
    @Test fun revocationRemainsAvailableWithoutReadyMcpService() {
        for (status in listOf("starting", "unavailable", "unknown")) {
            val info = readyInfo() + mapOf("mcp_status" to status, "mcp_allow_write" to true)
            val ui = presentLocalMcp(info)
            assertTrue(!ui.ready && ui.writeAllowed && ui.canChangeWritePermission)
            assertBlocked(info)
            assertTrue(presentLocalMcp(info, true).canChangeWritePermission)
        }
        for (value in listOf(null, false, "true", 1)) {
            val ui = presentLocalMcp(mapOf("mcp_allow_write" to value))
            assertTrue(!ui.writeAllowed && !ui.canChangeWritePermission)
        }
        assertTrue(presentLocalMcp(readyInfo()).canChangeWritePermission)
    }
    @Test fun secretsNeverEnterTemplate() {
        val marker = "SYNTHETIC_KEY_MUST_NOT_APPEAR"
        val ui = presentLocalMcp(readyInfo() + mapOf("token" to marker, "mcp_url" to marker, "mcp_token" to marker))
        assertTrue(ui.ready && !ui.toString().contains(marker))
    }
}
