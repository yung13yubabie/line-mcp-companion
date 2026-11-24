import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { SyncEngine } from "../src/sync/engine.ts";
import { MediaCache } from "../src/media/cache.ts";
import { callTool, BASIC_TOOLS } from "../src/mcp/tools.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { FakeSource, ALICE, GROUP, SECRET, msg } from "./fake-source.ts";

async function setup() {
	const dir = mkdtempSync(join(tmpdir(), "lma-mcp-"));
	const store = openDatabase(join(dir, "line.db"));
	const src = new FakeSource();
	const sync = new SyncEngine(store, src);
	await sync.fullSync();
	const whitelist = new Whitelist(store);
	whitelist.set(ALICE, true);
	whitelist.set(GROUP, true);
	await sync.fullSync();
	const media = new MediaCache(dir, store, src);
	return { dir, store, src, sync, whitelist, media, ctx: { store, whitelist, sync, media } };
}

test("白名單：未勾選會話完全隔離", async () => {
	const { ctx, dir, store } = await setup();
	try {
		const chats = (await callTool(ctx, "list_allowed_chats")) as { chat_id: string }[];
		assert.deepEqual(chats.map((c) => c.chat_id).sort(), [ALICE, GROUP].sort());
		await assert.rejects(callTool(ctx, "get_messages", { chat_id: SECRET }), /not allowed/);
		await assert.rejects(callTool(ctx, "get_messages", { chat_id: "u_does_not_exist" }), /not allowed/, "不存在與未允許回同一錯誤");
		await assert.rejects(callTool(ctx, "search_messages", { query: "機密", chat_id: SECRET }), /not allowed/);
		await assert.rejects(callTool(ctx, "download_media", { chat_id: SECRET, message_id: "3001" }), /not allowed/);
		// 機密群組裡有「晚餐」但不在範圍
		const hits = (await callTool(ctx, "search_messages", { query: "晚餐" })) as { chat_id: string }[];
		assert.ok(hits.length >= 1 && hits.every((h) => h.chat_id !== SECRET));
		// 隨時取消勾選，立即生效，不需重新登入
		ctx.whitelist.set(GROUP, false);
		await assert.rejects(callTool(ctx, "get_messages", { chat_id: GROUP }), /not allowed/);
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("get_messages 分頁與時間範圍", async () => {
	const { ctx, dir, store } = await setup();
	try {
		const p1 = (await callTool(ctx, "get_messages", { chat_id: ALICE, limit: 2 })) as { messages: { message_id: string }[]; next_before: number };
		assert.deepEqual(p1.messages.map((m) => m.message_id), ["1003", "1002"]);
		const p2 = (await callTool(ctx, "get_messages", { chat_id: ALICE, limit: 2, before: p1.next_before })) as { messages: { message_id: string }[] };
		assert.deepEqual(p2.messages.map((m) => m.message_id), ["1001"]);
		const r = (await callTool(ctx, "get_messages", { chat_id: ALICE, after: "2026-11-24T10:00:30+08:00" })) as { messages: unknown[] };
		assert.equal(r.messages.length, 2);
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("未讀摘要（本機計算）、附件下載快取、同步狀態、trigger_sync", async () => {
	const { ctx, dir, store, src } = await setup();
	try {
		let u = (await callTool(ctx, "get_unread_summary")) as { chat_id: string; unread: number }[];
		assert.equal(u.find((x) => x.chat_id === ALICE)!.unread, 2, "Alice 發了 2 則");
		src.pushRead(ALICE, "1002", Date.parse("2026-11-24T10:01:00+08:00"));
		src.push(msg("1004", ALICE, ALICE, 10, "到了嗎"));
		const t = (await callTool(ctx, "trigger_sync")) as { added: number };
		assert.equal(t.added, 1);
		u = (await callTool(ctx, "get_unread_summary")) as { chat_id: string; unread: number }[];
		assert.equal(u.find((x) => x.chat_id === ALICE)!.unread, 2, "手機上讀到 1002 → 剩 1003、1004");

		const a = (await callTool(ctx, "get_attachment", { chat_id: ALICE, message_id: "1003" })) as { has_media: boolean; cached_path: string | null };
		assert.equal(a.has_media, true);
		assert.equal(a.cached_path, null);
		const d1 = (await callTool(ctx, "download_media", { chat_id: ALICE, message_id: "1003", inline: true })) as { path: string; cached: boolean; base64: string };
		assert.equal(d1.cached, false);
		assert.ok(existsSync(d1.path));
		assert.equal(d1.base64, Buffer.from([0xff, 0xd8, 0xff, 0xd9]).toString("base64"));
		const d2 = (await callTool(ctx, "download_media", { chat_id: ALICE, message_id: "1003" })) as { cached: boolean };
		assert.equal(d2.cached, true);
		assert.equal(src.downloads, 1, "第二次走快取");
		await assert.rejects(callTool(ctx, "download_media", { chat_id: ALICE, message_id: "1001" }), /no media/);

		const s = (await callTool(ctx, "get_sync_status")) as { read_receipts: string; counts: { allowed: number } };
		assert.equal(s.read_receipts, "blocked");
		assert.equal(s.counts.allowed, 2);
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("MCP over HTTP（127.0.0.1 + Bearer token）端到端", async () => {
	const { ctx, dir, store } = await setup();
	const { server, url } = await startMcpHttp(ctx, { port: 0, token: "test-token" });
	try {
		assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
		const noAuth = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
		assert.equal(noAuth.status, 401);

		const client = new Client({ name: "test", version: "0" });
		await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: "Bearer test-token" } } }));
		const { tools } = await client.listTools();
		assert.deepEqual(tools.map((t) => t.name).sort(), [...BASIC_TOOLS].sort());
		const r = (await client.callTool({ name: "search_messages", arguments: { query: "便當" } })) as { content: { text: string }[] };
		const hits = JSON.parse(r.content[0]!.text);
		assert.equal(hits[0].text, "好啊 我帶便當");
		const denied = (await client.callTool({ name: "get_messages", arguments: { chat_id: SECRET } })) as { isError: boolean; content: { text: string }[] };
		assert.equal(denied.isError, true);
		assert.equal(JSON.parse(denied.content[0]!.text).error, "chat_not_allowed");
		await client.close();
	} finally {
		server.close();
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});
