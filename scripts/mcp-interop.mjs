/** Real SDK stdio smoke: status only; never reads messages or falls back to HTTP Bearer. */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { secureMcpUrl } from "../src/mcp/secure-channel.ts";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
let url, keyFile;
try {
 if (args.length !== 4 || args[0] !== "--url" || args[2] !== "--key-file" || !isAbsolute(args[3])) throw new Error();
 url = secureMcpUrl(args[1]).href;
 if (!new URL(url).port || Number(new URL(url).port) < 1) throw new Error();
 keyFile = args[3];
} catch {
 process.stderr.write("Usage: node scripts/mcp-interop.mjs --url http://127.0.0.1:PORT/mcp/secure --key-file /absolute/private/key-file\n");
 process.exit(64);
}
const client = new Client({ name: "local-stdio-status-smoke", version: "1.0.0" });
const transport = new StdioClientTransport({
 command: process.execPath,
 args: [fileURLToPath(new URL("mcp-stdio.ts", import.meta.url)), url],
 env: { ...getDefaultEnvironment(), LMA_MCP_CHANNEL_KEY_FILE: keyFile },
 stderr: "pipe",
});
// Do not forward adapter diagnostics or arbitrary error details into smoke output.
transport.stderr?.resume();
try {
 await client.connect(transport, { timeout: 10000 });
 const tools = await client.listTools(undefined, { timeout: 10000 });
 const reply = await client.callTool({ name: "get_sync_status", arguments: {} }, undefined, { timeout: 10000 });
 if (reply.isError) throw new Error();
 const text = reply.content.find(x => x.type === "text")?.text;
 const status = JSON.parse(text ?? "null");
 if (!status || typeof status.online !== "boolean") throw new Error();
 console.log(JSON.stringify({ transport: "stdio-adapter", sync_online: status.online,
  tool_count: tools.tools.length, trigger_sync_listed: tools.tools.some(x => x.name === "trigger_sync"),
  message_reads_performed: false }));
} catch {
 process.stderr.write("MCP stdio status smoke failed; no HTTP fallback.\n");
 process.exitCode = 1;
} finally { await client.close(); }
