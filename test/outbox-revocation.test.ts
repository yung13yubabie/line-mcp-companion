import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { AiPolicy } from "../src/ai/policy.ts";
import { Audit } from "../src/ai/audit.ts";
import { Outbox, type OutboxItem } from "../src/ai/outbox.ts";
import type { MessageSender } from "../src/ai/sender.ts";
import { ScamDetector } from "../src/scam/detector.ts";
import { ScamWarner } from "../src/scam/warner.ts";

// All calls are fake sender methods; fixtures contain only synthetic data.
globalThis.fetch = async () => { throw new Error("audit_network_forbidden"); };
const CHAT = "synthetic_revocation_chat";
const NOW = 1_800_000_000_000;
const STICKER = { package_id: "11537", sticker_id: "52002734", version: "1" };

function fixture() {
	const dir = mkdtempSync(join(tmpdir(), "outbox-revocation-"));
	const imagePath = join(dir, "synthetic.png");
	writeFileSync(imagePath, Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
	const store = openDatabase(":memory:");
	store.upsertChat({ id: CHAT, type: "GROUP", name: "Synthetic" });
	const whitelist = new Whitelist(store);
	whitelist.set(CHAT, true);
	const clock = { now: () => NOW, minuteOfDay: () => 600, startOfDay: (t: number) => Math.floor(t / 86400000) * 86400000 };
	const policy = new AiPolicy(store, clock);
	policy.setAiEnabled(true);
	policy.set(CHAT, { ai_allowed: true, mode: "auto", allow_image: true, delay_sec: 0, min_interval_sec: 10, max_per_hour: 60, max_per_day: 100 });
	policy.setTrust(CHAT, "ai", "auto");
	const calls: { kind: string; text?: string; mentions?: boolean }[] = [];
	const sender: MessageSender = {
		async sendText(_chat, text, opts) { calls.push({ kind: "text", text, mentions: !!opts?.mentions?.length }); },
		async sendImage() { calls.push({ kind: "image" }); },
		async sendSticker() { calls.push({ kind: "sticker" }); },
	};
	const outbox = new Outbox(store, policy, new Audit(store), sender);
	outbox.stickerSendable = () => true;
	function imageItem(byUser = true) {
		const it = outbox.enqueue({ chatId: CHAT, kind: "image", imagePath, text: "synthetic caption", origin: "ui", forcePending: byUser }, "ui").item;
		return byUser ? outbox.approve(it.id) : it;
	}
	return { store, whitelist, policy, sender, calls, outbox, imageItem, close() { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}

function latch() {
	let release!: () => void;
	let signal!: () => void;
	const hold = new Promise<void>(r => { release = r; });
	const started = new Promise<void>(r => { signal = r; });
	return { hold, started, release, signal };
}

const changes: [string, (f: ReturnType<typeof fixture>, item: OutboxItem) => void, string][] = [
	["kill switch", f => f.outbox.setKill(true), "failed"],
	["explicit rejection", (f, item) => f.outbox.reject(item.id), "rejected"],
	["chat whitelist removal", f => f.whitelist.set(CHAT, false), "failed"],
	["AI whitelist removal", f => f.policy.set(CHAT, { ai_allowed: false }), "failed"],
	["image permission removal", f => f.policy.set(CHAT, { allow_image: false }), "failed"],
	["AUTO to REVIEW demotion", f => f.policy.setTrust(CHAT, "ai", "review"), "failed"],
];

for (const [name, revoke, expectedStatus] of changes) {
	test(`dispatch parts: ${name} during image prevents caption and a duplicate retry`, async () => {
		const f = fixture();
		try {
			const item = f.imageItem(false);
			const gate = latch();
			f.sender.sendImage = async () => { f.calls.push({ kind: "image" }); gate.signal(); await gate.hold; };
			const running = f.outbox.processDue();
			await gate.started;
			revoke(f, item);
			if (name === "kill switch") {
				assert.throws(() => f.outbox.approve(item.id), /send_in_progress/);
				assert.throws(() => f.outbox.edit(item.id, { text: "replacement" }), /send_in_progress/);
			}
			gate.release();
			assert.equal(await running, 0, "partial items do not count as fully delivered");
			assert.deepEqual(f.calls, [{ kind: "image" }]);
			const current = f.outbox.get(item.id)!;
			assert.equal(current.status, expectedStatus);
			assert.match(current.error!, /^partial_send:/);
			assert.equal(current.sent_at, NOW, "confirmed delivery is retained despite cancellation");
			assert.equal(f.policy.sentSince(0, CHAT), 1);
			assert.equal(f.policy.lastSentAt(CHAT), NOW);
			assert.throws(() => f.outbox.approve(item.id), /cannot approve/);
			assert.equal(await f.outbox.processDue(), 0);
			assert.equal(f.calls.length, 1);
		} finally { f.close(); }
	});
}

test("dispatch parts: normal image/caption and text/sticker both complete", async () => {
	for (const kind of ["image", "sticker"] as const) {
		const f = fixture();
		try {
			const item = kind === "image" ? f.imageItem() : f.outbox.enqueue({ chatId: CHAT, kind, sticker: STICKER, text: "synthetic intro", origin: "ui", forcePending: true }, "ui").item;
			if (kind === "sticker") f.outbox.approve(item.id);
			// Explicit user approval continues to permit a legitimate item in REVIEW.
			f.policy.setTrust(CHAT, "ai", "review");
			assert.equal(await f.outbox.processDue(), 1);
			assert.deepEqual(f.calls.map(x => x.kind), kind === "image" ? ["image", "text"] : ["text", "sticker"]);
			assert.equal(f.outbox.get(item.id)!.status, "sent");
		} finally { f.close(); }
	}
});

test("dispatch parts: rejection during intro prevents sticker and stays rejected", async () => {
	const f = fixture();
	try {
		const item = f.outbox.enqueue({ chatId: CHAT, kind: "sticker", sticker: STICKER, text: "synthetic intro", origin: "ui", forcePending: true }, "ui").item;
		f.outbox.approve(item.id);
		const gate = latch();
		f.sender.sendText = async (_chat, text) => { f.calls.push({ kind: "text", text }); gate.signal(); await gate.hold; };
		const running = f.outbox.processDue();
		await gate.started;
		f.outbox.reject(item.id);
		gate.release();
		await running;
		assert.deepEqual(f.calls.map(x => x.kind), ["text"]);
		assert.equal(f.outbox.get(item.id)!.status, "rejected");
		assert.equal(f.policy.sentSince(0), 1);
	} finally { f.close(); }
});

test("dispatch retry: revoked mention attempt never starts fallback; valid fallback still works", async () => {
	for (const cancel of [true, false]) {
		const f = fixture();
		try {
			const item = f.outbox.enqueue({ chatId: CHAT, kind: "text", text: "@測試 合成提醒", origin: "ui", forcePending: true }, "ui").item;
			f.store.db.prepare("UPDATE outbox SET mentions_json=? WHERE id=?").run(JSON.stringify([{ start: 0, end: 3, mid: "synthetic_member" }]), item.id);
			f.outbox.approve(item.id);
			const gate = latch();
			f.sender.sendText = async (_chat, text, opts) => {
				f.calls.push({ kind: "text", text, mentions: !!opts?.mentions?.length });
				if (opts?.mentions?.length) { gate.signal(); await gate.hold; throw new Error("INVALID_REQUEST"); }
			};
			const running = f.outbox.processDue();
			await gate.started;
			if (cancel) f.outbox.reject(item.id);
			gate.release();
			await running;
			assert.equal(f.calls.length, cancel ? 1 : 2);
			assert.equal(f.outbox.get(item.id)!.status, cancel ? "rejected" : "sent");
			assert.equal(f.policy.sentSince(0), cancel ? 0 : 1);
			if (!cancel) assert.equal(f.calls[1]!.mentions, false);
		} finally { f.close(); }
	}
});

test("dispatch completion: cancellation while single send is in flight is not overwritten", async () => {
	const f = fixture();
	try {
		const item = f.outbox.enqueue({ chatId: CHAT, kind: "text", text: "synthetic text", origin: "ui", forcePending: true }, "ui").item;
		f.outbox.approve(item.id);
		const gate = latch();
		f.sender.sendText = async () => { gate.signal(); await gate.hold; };
		const running = f.outbox.processDue();
		await gate.started;
		f.outbox.reject(item.id);
		gate.release();
		assert.equal(await running, 1, "the already-started send completed; cancellation cannot recall it");
		const current = f.outbox.get(item.id)!;
		assert.equal(current.status, "rejected");
		assert.equal(current.sent_at, NOW);
		assert.match(current.error!, /^delivered_after_revocation:/);
		assert.equal(f.policy.sentSince(0), 1);
	} finally { f.close(); }
});

test("dispatch partial failure: delivered image counts toward caps and is never retried", async () => {
	const f = fixture();
	try {
		const item = f.imageItem();
		f.sender.sendText = async () => { throw new Error("synthetic caption failure"); };
		assert.equal(await f.outbox.processDue(), 0);
		assert.equal(f.outbox.get(item.id)!.status, "failed");
		assert.match(f.outbox.get(item.id)!.error!, /^partial_send:/);
		assert.equal(f.policy.sentSince(0), 1);
		f.policy.setDailyCap(1);
		assert.deepEqual(f.policy.checkSend(CHAT, "text", { approvedByUser: true }), { ok: false, reason: "daily_cap" });
		assert.equal(await f.outbox.processDue(), 0);
		assert.deepEqual(f.calls, [{ kind: "image" }]);
	} finally { f.close(); }
});

test("dispatch warning cap: delivered but cancelled warning still consumes the daily cap", async () => {
	const f = fixture();
	try {
		const warner = new ScamWarner(f.store, f.outbox, new Audit(f.store), new ScamDetector(f.store));
		warner.set(CHAT, { enabled: true, daily_cap: 1 });
		f.policy.setTrust(CHAT, "scam", "auto");
		for (const id of ["warning_source_a", "warning_source_b"]) f.store.insertMessage({ chatId: CHAT, id, sentAt: NOW - 1000, text: "synthetic warning source" });
		const item = f.outbox.enqueueWarning(CHAT, "synthetic first warning", "warning_source_a", "synthetic");
		const gate = latch();
		f.sender.sendText = async (_chat, text) => { f.calls.push({ kind: "text", text }); gate.signal(); await gate.hold; };
		const running = f.outbox.processDue();
		await gate.started;
		f.outbox.reject(item.id);
		gate.release();
		await running;
		assert.equal(f.outbox.get(item.id)!.status, "rejected");
		assert.equal(f.outbox.get(item.id)!.sent_at, NOW);
		const second = f.outbox.enqueueWarning(CHAT, "synthetic second warning", "warning_source_b", "synthetic");
		assert.equal(await f.outbox.processDue(), 0);
		assert.equal(f.outbox.get(second.id)!.status, "rejected");
		assert.equal(f.outbox.get(second.id)!.error, "scam_warn_daily_cap");
		assert.equal(f.calls.length, 1);
		assert.equal(f.policy.sentSince(0), 0, "warning and AI quotas stay separate");
	} finally { f.close(); }
});
