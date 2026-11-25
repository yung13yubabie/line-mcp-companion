/** Hermetic revocation tests: memory SQLite, synthetic providers and no network. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { crc32, deflateSync } from "node:zlib";
import { openDatabase } from "../src/storage/db.ts";
import { DigestStore } from "../src/storage/digests.ts";
import { SecretBox } from "../src/storage/secret-box.ts";
import { Whitelist } from "../src/whitelist.ts";
import { AiPolicy } from "../src/ai/policy.ts";
import { Audit } from "../src/ai/audit.ts";
import { Outbox } from "../src/ai/outbox.ts";
import { AiService } from "../src/ai/service.ts";
import { AiError, FallbackChain, OpenAICompatProvider, type AiProvider } from "../src/ai/provider.ts";
import type { ChatMsg } from "../src/ai/prompt.ts";
import type { LinkReader } from "../src/links/reader.ts";
import { ScamDetector } from "../src/scam/detector.ts";
import { fakeTransport } from "./helpers/http-transport.ts";

globalThis.fetch = async () => { throw new Error("regression_network_forbidden"); };
const CHAT = "context_guard_synthetic";
const NOW = 1_800_000_000_000;
const DIGEST = JSON.stringify({ title: "合成日報", items: [{ headline: "合成內容", body: "合成摘要", sources: ["#1"] }] });
const CONFIG = { provider: "custom" as const, base_url: "https://model.invalid/v1", model: "synthetic", image_model: "synthetic-image" };
function latch() {
	let release!: () => void, signal!: () => void;
	const hold = new Promise<void>((r) => { release = r; });
	const started = new Promise<void>((r) => { signal = r; });
	return { hold, started, release, signal };
}
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));
const pngChunk = (type: string, body: Buffer) => {
	const head = Buffer.alloc(8); head.writeUInt32BE(body.length); head.write(type, 4);
	const tail = Buffer.alloc(4); tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])));
	return Buffer.concat([head, body, tail]);
};
const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1); ihdr.writeUInt32BE(1, 4); ihdr[8] = 8; ihdr[9] = 6;
const PNG = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), pngChunk("IHDR", ihdr), pngChunk("IDAT", deflateSync(Buffer.from([0, 1, 2, 3, 255]))), pngChunk("IEND", Buffer.alloc(0))]);
const stubProvider = (chat: AiProvider["chat"]): AiProvider => ({
	kind: "custom", chat,
	async generateImage() { return { bytes: PNG, mime: "image/png" }; },
	async detect() { return { text: true, vision: false, image_gen: true, voice: false, models: [], checked_at: 0, heuristic: true }; },
});

function fixture() {
	const home = mkdtempSync(join(tmpdir(), "ai-context-guard-"));
	const store = openDatabase(":memory:");
	store.upsertChat({ id: CHAT, type: "GROUP", name: "Synthetic group" });
	store.insertMessage({ chatId: CHAT, id: "links", senderMid: "synthetic_sender", sentAt: NOW - 2, text: "https://first.invalid/a https://second.invalid/b" });
	store.insertMessage({ chatId: CHAT, id: "other", senderMid: "synthetic_sender", sentAt: NOW - 1, text: "SYNTHETIC_OTHER_SOURCE" });
	const whitelist = new Whitelist(store); whitelist.set(CHAT, true);
	const policy = new AiPolicy(store); policy.setAiEnabled(true); policy.set(CHAT, { ai_allowed: true, mode: "suggest", allow_image: true, style_lieflat: true });
	const audit = new Audit(store);
	const sender = { async sendText() { throw new Error("send_forbidden"); }, async sendImage() { throw new Error("send_forbidden"); }, async sendSticker() { throw new Error("send_forbidden"); } };
	const outbox = new Outbox(store, policy, audit, sender);
	const calls: ChatMsg[][] = [];
	let chat: AiProvider["chat"] = async () => "重點：今天記下一件小事。";
	const provider = stubProvider(async (messages, options) => { calls.push(messages); return chat(messages, options); });
	let active: AiProvider = provider;
	const ai = new AiService(store, policy, outbox, audit, { home, getKey: () => "synthetic-key", providerFactory: () => active });
	ai.setConfig(CONFIG);
	const digests = new DigestStore(store, new SecretBox(randomBytes(32)), whitelist); ai.digests = digests;
	return {
		home, store, whitelist, policy, outbox, provider, calls, ai, digests,
		setChat(next: AiProvider["chat"]) { chat = next; },
		setProvider(next: AiProvider) { active = next; ai.resetProvider(); },
		close() { ai.stop(); store.close(); rmSync(home, { recursive: true, force: true }); },
	};
}
type Fixture = ReturnType<typeof fixture>;
type Change = "hidden" | "deleted" | "whitelist" | "ai-off" | "consent" | "link-off";
function revoke(f: Fixture, change: Change) {
	if (change === "hidden") f.store.markHidden(CHAT, "other", "unsent");
	else if (change === "deleted") f.store.db.prepare("DELETE FROM message WHERE chat_id = ? AND id = ?").run(CHAT, "other");
	else if (change === "whitelist") f.whitelist.set(CHAT, false);
	else if (change === "ai-off") f.policy.setAiEnabled(false);
	else if (change === "consent") f.policy.set(CHAT, { ai_allowed: false });
	else f.store.setSetting(`link_read:${CHAT}`, "off");
}
const revoked = /message_hidden|chat_not_allowed|not allowed|ai_disabled|ai_not_allowed|link_reading_off/;

for (const change of ["hidden", "deleted", "whitelist", "ai-off", "consent", "link-off"] as const) {
	test(`digest: ${change} during first link blocks second URL, model, persistence`, async () => {
		const f = fixture();
		try {
			const gate = latch(); const links: string[] = [];
			f.store.setSetting(`link_read:${CHAT}`, "on");
			f.ai.links = { async read(url: string) { links.push(url); gate.signal(); await gate.hold; return { ok: true, url, title: "synthetic title" }; } } as LinkReader;
			const pending = f.ai.generateDigest(CHAT, NOW - 10, NOW, "ui");
			await gate.started; revoke(f, change); gate.release();
			await assert.rejects(pending, revoked);
			assert.equal(links.length, 1); assert.equal(f.calls.length, 0); assert.equal(f.digests.list().length, 0);
		} finally { f.close(); }
	});
}

test("digest: withdrawal while model is in flight prevents saving or returning the result", async () => {
	const f = fixture();
	try {
		const gate = latch(); f.setChat(async () => { gate.signal(); await gate.hold; return DIGEST; });
		const pending = f.ai.generateDigest(CHAT, NOW - 10, NOW, "ui");
		await gate.started; revoke(f, "hidden"); gate.release();
		await assert.rejects(pending, revoked); assert.equal(f.calls.length, 1); assert.equal(f.digests.list().length, 0);
	} finally { f.close(); }
});

for (const change of ["hidden", "deleted", "whitelist", "ai-off", "consent"] as const) {
	test(`social draft: ${change} during first model blocks later rewrite and persistence`, async () => {
		const f = fixture();
		try {
			const gate = latch(); f.setChat(async () => { gate.signal(); await gate.hold; return "重點：今天記下一件小事。"; });
			const pending = f.ai.draftSocialPost({ chatId: CHAT, platform: "threads", mode: "A" }, "ui");
			await gate.started; revoke(f, change); gate.release();
			await assert.rejects(pending, revoked); assert.equal(f.calls.length, 1); assert.equal(f.ai.socialDrafts().length, 0);
		} finally { f.close(); }
	});
}

test("social draft: Lieflat cannot swallow revocation during its second model call", async () => {
	const f = fixture();
	try {
		const gate = latch(); f.setChat(async () => { if (f.calls.length === 1) return "重點：今天記下一件小事。"; gate.signal(); await gate.hold; return "今天記下一件小事。"; });
		const pending = f.ai.draftSocialPost({ chatId: CHAT, platform: "threads", mode: "A" }, "ui");
		await gate.started; revoke(f, "consent"); gate.release();
		await assert.rejects(pending, revoked); assert.equal(f.calls.length, 2); assert.equal(f.ai.socialDrafts().length, 0);
	} finally { f.close(); }
});

test("authorized read-only drafts/digests keep their original semantics and normal model passes", async () => {
	const f = fixture();
	try {
		f.policy.setKillSwitch(true); f.policy.set(CHAT, { mode: "off" }); // send policy must not prohibit authorized read-only work
		const links: string[] = []; f.store.setSetting(`link_read:${CHAT}`, "on");
		f.ai.links = { async read(url: string) { links.push(url); return { ok: true, url, title: "synthetic title" }; } } as LinkReader;
		f.setChat(async () => DIGEST);
		assert.equal((await f.ai.generateDigest(CHAT, NOW - 10, NOW, "ui")).items.length, 1);
		assert.equal(links.length, 2); assert.equal(f.calls.length, 1);
		f.setChat(async () => f.calls.length === 2 ? "重點：今天記下一件小事。" : "今天記下一件小事。");
		assert.ok((await f.ai.draftSocialPost({ chatId: CHAT, platform: "threads", mode: "A" }, "ui")).text);
		assert.equal(f.calls.length, 3); assert.equal(f.ai.socialDrafts().length, 1);
	} finally { f.close(); }
});

test("service passes a per-call guard through a fallback chain before a new provider receives history", async () => {
	const f = fixture();
	try {
		const gate = latch(); let fallbackCalls = 0;
		f.setProvider(new FallbackChain([
			{ name: "primary", p: stubProvider(async () => { gate.signal(); await gate.hold; throw new AiError("network", "synthetic failure"); }) },
			{ name: "fallback", p: stubProvider(async () => { fallbackCalls++; return DIGEST; }) },
		]));
		const pending = f.ai.generateDigest(CHAT, NOW - 10, NOW, "ui");
		await gate.started; revoke(f, "consent"); gate.release();
		await assert.rejects(pending, revoked); assert.equal(fallbackCalls, 0); assert.equal(f.digests.list().length, 0);
	} finally { f.close(); }
});

test("authorization errors from a custom provider guard never become fallback network errors", async () => {
	let fallbackCalls = 0, checks = 0;
	const chain = new FallbackChain([
		{ name: "primary", p: stubProvider(async (_messages, options) => { options?.assertAuthorized?.(); return "unreachable"; }) },
		{ name: "fallback", p: stubProvider(async () => { fallbackCalls++; return "unreachable"; }) },
	]);
	await assert.rejects(chain.chat([], { assertAuthorized() { if (++checks === 2) throw new Error("synthetic_revocation"); } }), /synthetic_revocation/);
	assert.equal(fallbackCalls, 0);
	const healthy = new FallbackChain([{ name: "primary", p: stubProvider(async () => { throw new AiError("network", "failure"); }) }, { name: "fallback", p: stubProvider(async () => "normal fallback") }]);
	assert.equal(await healthy.chat([], { assertAuthorized() {} }), "normal fallback");
});

test("HTTP 400 token-field retry rechecks authorization; normal compatibility retry still succeeds", async () => {
	for (const withdraw of [true, false]) {
		let allowed = true, calls = 0;
		const provider = new OpenAICompatProvider(CONFIG, () => "synthetic-key", { fetch: (async () => {
			calls++;
			if (calls === 1) { if (withdraw) allowed = false; return new Response(JSON.stringify({ error: { message: "unsupported max_tokens" } }), { status: 400 }); }
			return new Response(JSON.stringify({ choices: [{ message: { content: "normal retry" } }] }));
		}) as typeof fetch });
		const pending = provider.chat([], { assertAuthorized() { if (!allowed) throw new Error("synthetic_revocation"); } });
		if (withdraw) { await assert.rejects(pending, /synthetic_revocation/); assert.equal(calls, 1); }
		else { assert.equal(await pending, "normal retry"); assert.equal(calls, 2); }
	}
});

test("concurrent calls on one provider retain their own authorization guard", async () => {
	const gate = latch(); let allowedA = true;
	const provider = new OpenAICompatProvider(CONFIG, () => "synthetic-key", { fetch: (async (_url, init) => {
		const body = JSON.parse(String(init?.body));
		const name = body.messages[0].content;
		if (name === "A") { gate.signal(); await gate.hold; }
		return new Response(JSON.stringify({ choices: [{ message: { content: `result ${name}` } }] }));
	}) as typeof fetch });
	const pendingA = provider.chat([{ role: "user", content: "A" }], { assertAuthorized() { if (!allowedA) throw new Error("A_revoked"); } });
	await gate.started; allowedA = false;
	assert.equal(await provider.chat([{ role: "user", content: "B" }], { assertAuthorized() {} }), "result B");
	gate.release(); await assert.rejects(pendingA, /A_revoked/);
});

for (const change of ["scam-ai", "scam-off", "whitelist", "hidden", "dismissed", "trusted"] as const) {
	test(`scam judge: ${change} revocation blocks fallback and verdict writeback`, async () => {
		const f = fixture();
		try {
			f.policy.setAiEnabled(false); f.policy.set(CHAT, { ai_allowed: false }); // anti-scam consent is independent
			f.store.setSetting("scam_ai", "on");
			f.store.insertMessage({ chatId: CHAT, id: "scam", senderMid: "synthetic_sender", sentAt: NOW, text: "老師帶單飆股保證獲利，加我 LINE ID: synthetic123 名額有限" });
			const detector = new ScamDetector(f.store); detector.seedBuiltin();
			const gate = latch(); let fallbackCalls = 0;
			const chain = new FallbackChain([
				{ name: "primary", p: stubProvider(async () => { gate.signal(); await gate.hold; throw new AiError("network", "synthetic failure"); }) },
				{ name: "fallback", p: stubProvider(async () => { fallbackCalls++; return '{"verdict":"scam","reason":"synthetic"}'; }) },
			]);
			detector.judge = (messages, options) => chain.chat(messages, options);
			const id = detector.scanMessage(CHAT, "scam"); assert.ok(id);
			await gate.started;
			if (change === "scam-ai") f.store.setSetting("scam_ai", "off");
			else if (change === "scam-off") f.store.setSetting("scam_enabled", "off");
			else if (change === "whitelist") f.whitelist.set(CHAT, false);
			else if (change === "hidden") f.store.markHidden(CHAT, "scam", "unsent");
			else if (change === "dismissed") detector.setStatus(id, "dismissed");
			else detector.setAdmin(CHAT, "synthetic_sender", { mention: false });
			gate.release(); await flush();
			assert.equal(fallbackCalls, 0);
			assert.equal((f.store.db.prepare("SELECT ai_verdict FROM scam_alert WHERE id = ?").get(id) as { ai_verdict: string | null }).ai_verdict, null);
		} finally { f.close(); }
	});
}

test("scam judge keeps independent consent and does not write a result after mid-call revocation", async () => {
	for (const withdraw of [false, true]) {
		const f = fixture();
		try {
			f.policy.setAiEnabled(false); f.policy.set(CHAT, { ai_allowed: false }); f.store.setSetting("scam_ai", "on");
			f.store.insertMessage({ chatId: CHAT, id: "scam", senderMid: "synthetic_sender", sentAt: NOW, text: "老師帶單飆股保證獲利，加我 LINE ID: synthetic123 名額有限" });
			const detector = new ScamDetector(f.store); detector.seedBuiltin(); const gate = latch();
			detector.judge = async () => { gate.signal(); await gate.hold; return '{"verdict":"scam","reason":"synthetic"}'; };
			const id = detector.scanMessage(CHAT, "scam"); assert.ok(id); await gate.started;
			if (withdraw) f.store.setSetting("scam_ai", "off");
			gate.release(); await flush();
			assert.equal((f.store.db.prepare("SELECT ai_verdict FROM scam_alert WHERE id = ?").get(id) as { ai_verdict: string | null }).ai_verdict, withdraw ? null : "scam");
		} finally { f.close(); }
	}
});

test("image API response revocation prevents a new download; DNS-await revocation prevents the socket", async () => {
	for (const stage of ["api", "dns"] as const) {
		let allowed = true, dns = 0;
		const transport = fakeTransport(() => { throw new Error("image request forbidden after revocation"); });
		const provider = new OpenAICompatProvider(CONFIG, () => "synthetic-key", {
			fetch: (async () => { if (stage === "api") allowed = false; return new Response(JSON.stringify({ data: [{ url: "https://images.invalid/a.png" }] })); }) as typeof fetch,
			imageDownload: { resolve: async () => { dns++; allowed = false; return ["93.184.215.14"]; }, request: transport.request },
		});
		await assert.rejects(provider.generateImage("synthetic", { assertAuthorized() { if (!allowed) throw new Error("synthetic_revocation"); } }), /synthetic_revocation/);
		assert.equal(dns, stage === "api" ? 0 : 1); assert.equal(transport.seen.length, 0);
	}
});

test("image completion revocation prevents files and outbox; authorized image still queues", async () => {
	for (const withdraw of [true, false]) {
		const f = fixture();
		try {
			const gate = latch(); f.provider.generateImage = async () => { gate.signal(); await gate.hold; return { bytes: PNG, mime: "image/png" }; };
			const pending = f.ai.imageToQueue(CHAT, "synthetic image", null, "ui", "ui");
			await gate.started; if (withdraw) f.policy.setAiEnabled(false); gate.release();
			if (withdraw) { await assert.rejects(pending, /ai_disabled/); assert.equal(existsSync(join(f.home, "ai-images")), false); assert.equal(f.outbox.list({}).length, 0); }
			else { assert.equal((await pending).route, "pending"); assert.equal(readdirSync(join(f.home, "ai-images")).length, 1); assert.equal(f.outbox.list({}).length, 1); }
		} finally { f.close(); }
	}
});
