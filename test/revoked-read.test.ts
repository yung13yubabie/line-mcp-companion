import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase } from "../src/storage/db.ts";
import { SecretBox } from "../src/storage/secret-box.ts";
import { EventLog } from "../src/storage/event-log.ts";
import { Whitelist } from "../src/whitelist.ts";
import { AiPolicy } from "../src/ai/policy.ts";
import { Audit } from "../src/ai/audit.ts";
import { Outbox } from "../src/ai/outbox.ts";
import { AiService } from "../src/ai/service.ts";
import { callTool } from "../src/mcp/tools.ts";

globalThis.fetch = async () => { throw new Error("regression_network_forbidden"); };
const CHAT = "synthetic_revoked_read";
const NOW = 1_800_000_000_000;
function fixture() {
	const dir = mkdtempSync(join(tmpdir(), "revoked-read-"));
	const store = openDatabase(":memory:");
	store.upsertChat({ id: CHAT, type: "GROUP", name: "Synthetic group" });
	store.insertMessage({ chatId: CHAT, id: "source", sentAt: NOW, text: "SYNTHETIC_WITHDRAWN_TEXT" });
	store.insertMessage({ chatId: CHAT, id: "visible", sentAt: NOW - 1, text: "SYNTHETIC_VISIBLE_TEXT" });
	const whitelist = new Whitelist(store); whitelist.set(CHAT, true);
	const policy = new AiPolicy(store, { now: () => NOW, minuteOfDay: () => 600, startOfDay: (t: number) => Math.floor(t / 86400000) * 86400000 });
	policy.setAiEnabled(true);
	policy.set(CHAT, { ai_allowed: true, mode: "auto", style_lieflat: true });
	const audit = new Audit(store);
	const sender = { async sendText() { throw new Error("sender_forbidden"); }, async sendImage() { throw new Error("sender_forbidden"); }, async sendSticker() { throw new Error("sender_forbidden"); } };
	const outbox = new Outbox(store, policy, audit, sender);
	const events = new EventLog(store, new SecretBox(randomBytes(32)));
	const ctx: any = { store, whitelist, events, sync: null, media: null };
	return { dir, store, whitelist, policy, audit, outbox, events, ctx, close() { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function latch() {
	let release!: () => void, signal!: () => void;
	const hold = new Promise<void>(r => { release = r; });
	const started = new Promise<void>(r => { signal = r; });
	return { hold, started, release, signal };
}

test("historical logs: MCP excludes known hidden sources while local audit history remains available", async () => {
	const f = fixture();
	try {
		for (const id of ["source", "visible"]) {
			f.events.scam({ chat_id: CHAT, message_id: id, text: `synthetic ${id}`, action: "alert_only" });
			f.events.ai({ chat_id: CHAT, origin: "suggest", event: "generated", actor: "ui", trigger_msg_id: id, trigger_text: `synthetic ${id}`, text: "synthetic reply" });
		}
		assert.equal((await callTool(f.ctx, "get_scam_log", {}) as any[]).length, 2);
		assert.equal((await callTool(f.ctx, "get_ai_log", {}) as any[]).length, 2);
		f.store.markHidden(CHAT, "source", "unsent");
		assert.deepEqual((await callTool(f.ctx, "get_scam_log", {}) as any[]).map(r => r.message_id), ["visible"]);
		assert.deepEqual((await callTool(f.ctx, "get_ai_log", {}) as any[]).map(r => r.trigger_msg_id), ["visible"]);
		assert.equal(f.events.scamList().length, 2);
		assert.equal(f.events.aiList().length, 2);
	} finally { f.close(); }
});

for (const change of ["hidden", "whitelist", "link-toggle"] as const) {
	test(`link read: ${change} revocation stops result release and the next URL`, async () => {
		const f = fixture();
		try {
			f.store.insertMessage({ chatId: CHAT, id: "links", sentAt: NOW, text: "https://first.invalid/a https://second.invalid/b" });
			f.store.setSetting(`link_read:${CHAT}`, "on");
			const gate = latch(); const calls: string[] = [];
			f.ctx.links = { async read(url: string) { calls.push(url); gate.signal(); await gate.hold; return { ok: true, url, final_url: url, text: "synthetic page" }; } };
			const result = callTool(f.ctx, "read_link", { chat_id: CHAT, message_id: "links" });
			await gate.started;
			if (change === "hidden") f.store.markHidden(CHAT, "links", "unsent");
			else if (change === "whitelist") f.whitelist.set(CHAT, false);
			else f.store.setSetting(`link_read:${CHAT}`, "off");
			gate.release();
			await assert.rejects(result, /message_hidden|not allowed|link_reading_off/);
			assert.deepEqual(calls, ["https://first.invalid/a"]);
		} finally { f.close(); }
	});
}

for (const change of ["hidden", "whitelist", "ai-off"] as const) {
	test(`AI suggestion: ${change} revocation blocks the result and a later rewrite pass`, async () => {
		const f = fixture(); let ai: AiService | undefined;
		try {
			const gate = latch(); let calls = 0;
			const provider: any = { kind: "custom", async chat() { calls++; gate.signal(); await gate.hold; return "重點：SYNTHETIC_WITHDRAWN_TEXT"; } };
			ai = new AiService(f.store, f.policy, f.outbox, f.audit, { home: f.dir, getKey: () => "synthetic-key", providerFactory: () => provider });
			ai.setConfig({ provider: "custom", base_url: "https://model.invalid/v1", model: "fake", deidentify: true });
			f.ctx.ai = ai;
			const result = callTool(f.ctx, "get_ai_suggestion", { chat_id: CHAT, reply_to: "source" });
			await gate.started;
			if (change === "hidden") f.store.markHidden(CHAT, "source", "unsent");
			else if (change === "whitelist") f.whitelist.set(CHAT, false);
			else f.policy.setAiEnabled(false);
			gate.release();
			await assert.rejects(result, /message_hidden|not allowed|ai_disabled/);
			assert.equal(calls, 1);
		} finally { ai?.stop(); f.close(); }
	});
}

test("AI suggestion: hidden source during the rewrite cannot be swallowed as a style failure", async () => {
	const f = fixture(); let ai: AiService | undefined;
	try {
		const gate = latch(); let calls = 0;
		const provider: any = { kind: "custom", async chat() { calls++; if (calls === 1) return "重點：今天有小發現"; gate.signal(); await gate.hold; return "今天有小發現"; } };
		ai = new AiService(f.store, f.policy, f.outbox, f.audit, { home: f.dir, getKey: () => "synthetic-key", providerFactory: () => provider });
		ai.setConfig({ provider: "custom", base_url: "https://model.invalid/v1", model: "fake", deidentify: true });
		const result = ai.suggest(CHAT, "ui");
		await gate.started;
		f.store.markHidden(CHAT, "source", "unsent");
		gate.release();
		await assert.rejects(result, /message_hidden/);
		assert.equal(calls, 2);
	} finally { ai?.stop(); f.close(); }
});
