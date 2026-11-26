/** Synthetic codec validation and the actual standard MCP stdio entry point; no LINE or outside services. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { sealMcp, openMcp, channelNonce, secureMcpUrl, secureMcpRequest } from "../src/mcp/secure-channel.ts";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { resolve } from "node:path";
const KEY = "synthetic-mcp-channel-key-20261126";

test("MCP-only codec authenticates direction, epoch, nonce, timestamp, status and bytes", () => {
 const epoch = channelNonce(), nonce = channelNonce(), ts = Date.now(), plain = Buffer.from("synthetic non-sensitive payload");
 const cipher = sealMcp(KEY, "response", epoch, nonce, ts, 200, plain);
 assert.deepEqual(openMcp(KEY, "response", epoch, nonce, ts, 200, cipher), plain);
 for (const action of [
  () => openMcp(KEY + "x", "response", epoch, nonce, ts, 200, cipher),
  () => openMcp(KEY, "request", epoch, nonce, ts, 200, cipher),
  () => openMcp(KEY, "response", channelNonce(), nonce, ts, 200, cipher),
  () => openMcp(KEY, "response", epoch, channelNonce(), ts, 200, cipher),
  () => openMcp(KEY, "response", epoch, nonce, ts + 1, 200, cipher),
  () => openMcp(KEY, "response", epoch, nonce, ts, 201, cipher),
  () => { const changed = Buffer.from(cipher); changed[15] = changed[15]! ^ 1; openMcp(KEY, "response", epoch, nonce, ts, 200, changed); },
 ]) assert.throws(action);
 assert.throws(() => secureMcpUrl("http://localhost:123/mcp/secure"));
 assert.throws(() => secureMcpUrl("https://example.test/mcp/secure"));
 assert.throws(() => secureMcpUrl("http://127.0.0.1:123/mcp/secure?other=1"));
});

test("standard MCP Client uses stdio adapter with authenticated local channel and current least privilege", async () => {
 const store = openDatabase(":memory:");
 let polls = 0;
 const fixture = { status: () => ({}), pollOnce: async () => { polls++; }, fullSync: async () => { polls++; } };
 const local = await startMcpHttp({ store, whitelist: new Whitelist(store), sync: fixture as never, media: null }, { port: 0, token: KEY, allowLegacyBearer: false });
 const url = local.url + "/secure";
 const transport = new StdioClientTransport({ command: process.execPath, args: [resolve("scripts/mcp-stdio.ts"), url], env: { PATH: process.env.PATH ?? "", LMA_MCP_CHANNEL_KEY: KEY }, stderr: "pipe" });
 const client = new Client({ name: "synthetic-secure-client", version: "1" });
 try {
  const disabled = await fetch(local.url, { method: "POST", headers: { authorization: `Bearer ${KEY}` }, body: "{}" });
  assert.equal(disabled.status, 403);
  await client.connect(transport);
  assert.ok((await client.listTools()).tools.some(t => t.name === "get_sync_status"));
  assert.ok(!(await client.listTools()).tools.some(t => t.name === "trigger_sync"));
  const read = await client.callTool({ name: "get_sync_status", arguments: {} });
  assert.notEqual(read.isError, true);
  store.setSetting("mcp_allow_write", "on");
  assert.ok((await client.listTools()).tools.some(t => t.name === "trigger_sync"));
  await client.callTool({ name: "trigger_sync", arguments: {} });
  assert.equal(polls, 1);
  store.setSetting("mcp_allow_write", "off");
  const denied = await client.callTool({ name: "trigger_sync", arguments: {} });
  assert.equal(denied.isError, true);
  assert.equal(polls, 1);
  await assert.rejects(secureMcpRequest(url, KEY + "incorrect", { jsonrpc: "2.0", id: 7, method: "ping" }), /mcp_server_untrusted/);
 } finally {
  await client.close();
  await new Promise<void>((yes, no) => local.server.close(e => e ? no(e) : yes()));
  store.close();
 }
});
