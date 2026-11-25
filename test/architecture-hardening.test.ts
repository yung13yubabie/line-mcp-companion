/** Defensive regression checks: synthetic data, bounded requests, loopback only; no external services. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { Audit } from "../src/ai/audit.ts";
import type { AiService } from "../src/ai/service.ts";
import { SecretBox } from "../src/storage/secret-box.ts";
import { EventLog } from "../src/storage/event-log.ts";
import { startControlHttp } from "../src/control/server.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { AuthFailureBudget, ControlReplayWindow, CONTROL_AUTH_SKEW_MS } from "../src/control/security.ts";

const TOKEN = "synthetic-local-test-token-20261125";
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const mac = (text: string) => createHmac("sha256", TOKEN).update(text).digest("hex");
const localFetch = (url: string, init?: RequestInit) => {
	assert.equal(new URL(url).hostname, "127.0.0.1", "regression test may only contact its loopback fixture");
	return fetch(url, init);
};
const closeServer = (server: Server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
const sign = (path: string) => {
	const nonce = randomBytes(16).toString("hex");
	const ts = Date.now();
	return { nonce, headers: { "x-lma-nonce": nonce, "x-lma-auth": `v1 ${ts}.${mac(`req:${nonce}:${ts}:GET:/control${path}:${hash(Buffer.alloc(0))}`)}` } };
};
const verify = async (response: Response, nonce: string, path: string) => {
	const bytes = Buffer.from(await response.arrayBuffer());
	assert.equal(response.headers.get("x-lma-proof-body"), "1");
	assert.equal(response.headers.get("x-lma-proof"), mac(`resp:${nonce}:GET:/control${path}:${response.status}:${hash(bytes)}`));
	return bytes;
};

test("F14/F15: authentication failure counters are bounded and periodic aggregation avoids per-request writes", () => {
	let now = 1_000;
	const reports: unknown[] = [];
	const budget = new AuthFailureBudget({ perMinute: 2, now: () => now, report: (summary) => reports.push(summary) });
	assert.equal(budget.reject("unauthorized"), true);
	assert.equal(budget.reject("unauthorized"), true);
	assert.equal(budget.reject("forbidden"), false);
	assert.equal(reports.length, 1, "only the first event is written immediately");
	assert.deepEqual(budget.snapshot(), { counts: { unauthorized: 2, forbidden: 1, replay: 0, expired: 0, invalid_request: 0 }, rate_limited: 1, report_failures: 0 });
	budget.flush();
	assert.equal(reports.length, 2, "the remaining two events are one aggregate");
	budget.flush();
	assert.equal(reports.length, 2, "empty periods create no event");
	now += 60_000;
	assert.equal(budget.reject("unauthorized"), true, "the bounded budget refills");
});

test("F14/F15: unavailable telemetry storage does not crash authentication handling and counters are retained", () => {
	let unavailable = true;
	const reports: { counts: { unauthorized: number }; report_failures: number }[] = [];
	const budget = new AuthFailureBudget({ perMinute: 1, report: (summary) => {
		if (unavailable) throw new Error("synthetic storage failure");
		reports.push(summary);
	} });
	assert.equal(budget.reject("unauthorized"), true);
	assert.equal(budget.reject("unauthorized"), false);
	assert.equal(budget.snapshot().report_failures, 1);
	unavailable = false;
	budget.flush();
	assert.equal(reports[0].counts.unauthorized, 2);
	assert.equal(reports[0].report_failures, 1);
});

test("F14: security-event retention cannot evict operation audit records", () => {
	const store = openDatabase(":memory:");
	try {
		const audit = new Audit(store);
		audit.log("ui", "permission_changed", { detail: { enabled: false } });
		audit.logSecurity("mcp", "mcp_auth_failures", { count: 1 });
		// Sparse fixture IDs exercise retention with three in-memory writes, not request flooding.
		store.db.prepare("INSERT INTO security_log(id, ts, actor, action, ok) VALUES (500, ?, 'mcp', 'fixture_summary', 0)").run(Date.now());
		audit.logSecurity("mcp", "mcp_auth_failures", { count: 2 });
		assert.equal(audit.securityRecent().length, 2, "old security id 1 was evicted at id 501");
		assert.equal(audit.recent().length, 1);
		assert.equal(audit.recent()[0].action, "permission_changed");
		assert.ok(audit.recent({ includeSecurity: true }).some((entry) => entry.stream === "security"));
	} finally { store.close(); }
});

test("F14: three unauthenticated requests are limited without consuming valid MCP client budget", async () => {
	const store = openDatabase(":memory:");
	const audit = new Audit(store);
	audit.log("ui", "permission_changed");
	const mcp = await startMcpHttp({ store, whitelist: new Whitelist(store), sync: null, media: null }, { port: 0, token: TOKEN, audit, authFailureRatePerMin: 1 });
	try {
		for (const expected of [401, 429, 429]) {
			const response = await localFetch(mcp.url, { method: "POST" });
			assert.equal(response.status, expected);
			await response.text();
		}
		const response = await localFetch(mcp.url, {
			method: "POST",
			headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
		});
		assert.equal(response.status, 200);
		assert.ok((await response.json() as { result: { tools: unknown[] } }).result.tools.length > 0);
		assert.equal(mcp.stats().authentication?.counts.unauthorized, 3);
		assert.equal(mcp.stats().authentication?.rate_limited, 2);
		assert.equal(audit.securityRecent().length, 1, "repeated failures do not write per request");
		assert.ok(audit.recent().some((entry) => entry.action === "permission_changed"));
	} finally { await closeServer(mcp.server); store.close(); }
});

test("F15: authenticated health works after the failure budget is exhausted and telemetry is visible", async () => {
	const store = openDatabase(":memory:");
	const control = await startControlHttp({ store, whitelist: new Whitelist(store), login: () => ({ phase: "logged_out" }), startQrLogin: () => {} }, { port: 0, token: TOKEN, hmacOnly: true, authFailureRatePerMin: 1 });
	try {
		for (const expected of [401, 429]) {
			const response = await localFetch(`${control.url}/health`);
			assert.equal(response.status, expected);
			await response.text();
		}
		const signed = sign("/health");
		const health = await localFetch(`${control.url}/health`, { headers: signed.headers });
		assert.equal(health.status, 200);
		assert.deepEqual(JSON.parse((await verify(health, signed.nonce, "/health")).toString()), { ok: true });
		const request = sign("/security");
		const events = await localFetch(`${control.url}/security`, { headers: request.headers });
		const security = JSON.parse((await verify(events, request.nonce, "/security")).toString());
		assert.equal(security.authentication.counts.unauthorized, 2);
		assert.equal(security.authentication.rate_limited, 1);
		assert.equal(security.recent[0].action, "control_auth_failures");
		const readAudit = sign("/audit");
		const response = await localFetch(`${control.url}/audit`, { headers: readAudit.headers });
		assert.ok(JSON.parse((await verify(response, readAudit.nonce, "/audit")).toString()).some((entry: { stream: string }) => entry.stream === "security"));
	} finally { await closeServer(control.server); store.close(); }
});

test("G02: CSV and image control responses bind their exact bytes, just like JSON", async () => {
	const dir = mkdtempSync(join(tmpdir(), "lma-proof-review-"));
	const bytes = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
	const file = join(dir, "synthetic.png");
	writeFileSync(file, bytes);
	const store = openDatabase(":memory:");
	const audit = new Audit(store);
	const events = new EventLog(store, new SecretBox(Buffer.alloc(32, 7)));
	const control = await startControlHttp({
		store, whitelist: new Whitelist(store), login: () => ({ phase: "logged_out" }), startQrLogin: () => {}, events,
		ai: { audit, outbox: { get: () => ({ image_path: file }) } } as unknown as AiService,
		stickerImage: async () => ({ bytes, mime: "image/png" }),
	}, { port: 0, token: TOKEN, hmacOnly: true });
	try {
		for (const path of ["/logs/scam?format=csv", "/logs/ai?format=csv", "/sticker_img?id=1", "/outbox_image?id=1"]) {
			const signed = sign(path);
			const response = await localFetch(`${control.url}${path}`, { headers: signed.headers });
			assert.equal(response.status, 200, path);
			const proof = response.headers.get("x-lma-proof");
			const actual = await verify(response, signed.nonce, path);
			const changed = Buffer.from(actual);
			changed[0] ^= 1;
			assert.notEqual(proof, mac(`resp:${signed.nonce}:GET:/control${path}:200:${hash(changed)}`), "a different body cannot share the original proof");
			assert.notEqual(proof, mac(`resp:${signed.nonce}:GET:/control${path}:200:-`), "no unsigned-body downgrade");
		}
	} finally { await closeServer(control.server); store.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("U01: a future-timestamp nonce remains consumed throughout the entire acceptance window", () => {
	let now = 1_000_000;
	const replay = new ControlReplayWindow({ now: () => now, maxEntries: 2 });
	const timestamp = now + CONTROL_AUTH_SKEW_MS - 1000;
	assert.equal(replay.consume("synthetic-nonce", timestamp), true);
	now += CONTROL_AUTH_SKEW_MS + 1000;
	assert.equal(replay.validTimestamp(timestamp), true);
	assert.equal(replay.consume("synthetic-nonce", timestamp), false, "still blocked after the old receipt-based expiry");
	now = timestamp + CONTROL_AUTH_SKEW_MS;
	assert.equal(replay.consume("synthetic-nonce", timestamp), false, "inclusive timestamp boundary is also protected");
	now++;
	assert.equal(replay.validTimestamp(timestamp), false);
	assert.equal(replay.consume("new-nonce", now), true);
});

test("U01: replay state fails closed at its cap and reclaims expired entries", () => {
	let now = 1_000_000;
	const replay = new ControlReplayWindow({ now: () => now, maxEntries: 2 });
	assert.equal(replay.consume("one", now), true);
	assert.equal(replay.consume("two", now), true);
	assert.equal(replay.consume("three", now), false);
	now += CONTROL_AUTH_SKEW_MS + 1;
	assert.equal(replay.consume("three", now), true);
});
