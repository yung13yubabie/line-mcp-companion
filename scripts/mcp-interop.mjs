// 標準 MCP 用戶端互通測試：node scripts/mcp-interop.mjs <url> <token>
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const [url, token] = process.argv.slice(2);
const t = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
const c = new Client({ name: "interop-test", version: "1.0.0" });
await c.connect(t);
console.log("server:", JSON.stringify(c.getServerVersion()), "session:", t.sessionId ?? "(stateless)");
const tools = await c.listTools();
console.log("tools:", tools.tools.map((x) => x.name).join(", "));
const show = async (name, args = {}) => {
  const r = await c.callTool({ name, arguments: args });
  console.log(`\n== ${name} ${JSON.stringify(args)}${r.isError ? " [isError]" : ""}\n` + r.content.map((x) => x.text ?? `[${x.type}]`).join("\n").slice(0, 600));
  return r;
};
const chats = await show("list_allowed_chats");
let first; try { first = JSON.parse(chats.content[0].text); first = (first.chats ?? first)[0]; } catch {}
const mid = first?.chat_id;
await show("get_messages", { chat_id: mid, limit: 3 });
await show("search_messages", { query: "sprint" });
await show("get_unread_summary");
await show("get_sync_status");
await show("get_messages", { chat_id: "c_mock_private", limit: 1 }); // 未勾選白名單（私密理財群）
await show("get_messages", { chat_id: "c_does_not_exist", limit: 1 });
await show("get_attachment", { chat_id: mid, message_id: "9204" });
await c.close();
