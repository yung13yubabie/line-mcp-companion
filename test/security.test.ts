import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { openDatabase } from "../src/storage/db.ts";
import { SecretBox, isSealed } from "../src/storage/secret-box.ts";
import { SqliteKvStorage, openSecretStore } from "../src/storage/kv-storage.ts";
import { resolveDataKey } from "../src/storage/data-key.ts";
import { Whitelist } from "../src/whitelist.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { startControlHttp } from "../src/control/server.ts";

test("SecretBox：AES-GCM 往返；竄改、換欄位（AAD）、換金鑰都解不開", () => {
	const box = new SecretBox(randomBytes(32));
	const s = box.seal("token-abc", "line_kv:authToken");
	assert.ok(isSealed(s) && !s.includes("token-abc"));
	assert.equal(box.open(s, "line_kv:authToken"), "token-abc");
	assert.throws(() => box.open(s, "line_kv:other"));
	assert.throws(() => new SecretBox(randomBytes(32)).open(s, "line_kv:authToken"));
	const b = Buffer.from(s.slice(7), "base64");
	b[b.length - 1] ^= 1;
	assert.throws(() => box.open("enc:v1:" + b.toString("base64"), "line_kv:authToken"));
	assert.throws(() => new SecretBox(randomBytes(16)));
});

test("舊版明文 line_kv 遷移成密文，並從資料庫檔案裡清掉明文", () => {
	const dir = mkdtempSync(join(tmpdir(), "lma-sec-"));
	const path = join(dir, "line.db");
	const store = openDatabase(path);
	const SECRET = "PLAINTEXT_AUTH_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaa";
	store.db.prepare("INSERT INTO line_kv(key, value) VALUES (?, ?)").run("authToken", JSON.stringify(SECRET));
	store.db.prepare("INSERT INTO line_kv(key, value) VALUES (?, ?)").run("e2eeKey:1", JSON.stringify({ priv: "PRIVKEY_bbbbbbbbbbbbbbbbbbbb" }));
	const box = new SecretBox(randomBytes(32));
	assert.equal(openSecretStore(store, box), 2);
	const rows = store.db.prepare("SELECT value FROM line_kv").all() as { value: string }[];
	assert.ok(rows.every((r) => isSealed(r.value)));
	const kv = new SqliteKvStorage(store, box);
	assert.equal(kv.getSync("authToken"), SECRET);
	store.db.close();
	for (const f of [path, `${path}-wal`]) if (existsSync(f)) assert.ok(!readFileSync(f).includes(Buffer.from(SECRET)), `${f} 不能殘留明文`);
	// 換錯金鑰 → 拒絕，不覆蓋資料
	const again = openDatabase(path);
	assert.throws(() => openSecretStore(again, new SecretBox(randomBytes(32))), /does not match/);
	assert.equal(openSecretStore(again, box), 0);
});

test("資料金鑰：沒有 LMA_DATA_KEY / LMA_PASSPHRASE 就拒絕（mock 除外）；讀完從環境變數移除", () => {
	const store = openDatabase(":memory:");
	assert.throws(() => resolveDataKey(store, {}), /refusing to start/);
	const env: NodeJS.ProcessEnv = { LMA_DATA_KEY: randomBytes(32).toString("base64") };
	assert.equal(resolveDataKey(store, env).source, "keystore");
	assert.equal(env.LMA_DATA_KEY, undefined);
	const s2 = openDatabase(":memory:");
	assert.throws(() => resolveDataKey(s2, { LMA_PASSPHRASE: "short" }), /at least 12/);
	assert.equal(resolveDataKey(openDatabase(":memory:"), {}, { mock: true }).source, "ephemeral");
});

test("MCP / 控制 API：沒有 token 或 token 太短拒絕啟動；只能綁 loopback；沒帶 token 一律 401", async () => {
	const store = openDatabase(":memory:");
	const ctx = { store, whitelist: new Whitelist(store), sync: null, media: null };
	await assert.rejects(startMcpHttp(ctx, { port: 0 }), /token is required/);
	await assert.rejects(startMcpHttp(ctx, { port: 0, token: "short" }), /token is required/);
	await assert.rejects(startMcpHttp(ctx, { port: 0, token: "x".repeat(32), host: "0.0.0.0" }), /loopback/);
	await assert.rejects(startControlHttp({ store, whitelist: ctx.whitelist, login: () => ({ phase: "logged_out" }), startQrLogin: () => {} }, { port: 0, token: "" }), /control token/);
	const { server, url } = await startMcpHttp(ctx, { port: 0, token: "x".repeat(32) });
	try {
		const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
		assert.equal(r.status, 401);
		const wrong = await fetch(url, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + "y".repeat(32) }, body: "{}" });
		assert.equal(wrong.status, 401);
	} finally {
		server.close();
	}
});

function runMain(env: Record<string, string>, waitFor: RegExp, ms = 15000): Promise<{ code: number | null; out: string }> {
	return new Promise((resolve) => {
		const p = spawn(process.execPath, ["src/main.ts"], { env: { PATH: process.env.PATH ?? "", ...env }, stdio: ["ignore", "pipe", "pipe"] });
		let out = "";
		const done = (code: number | null) => {
			clearTimeout(t);
			p.kill("SIGKILL");
			resolve({ code, out });
		};
		const on = (d: Buffer) => {
			out += d.toString();
			if (waitFor.test(out)) done(null);
		};
		p.stdout.on("data", on);
		p.stderr.on("data", on);
		p.on("exit", (code) => done(code));
		const t = setTimeout(() => done(null), ms);
	});
}

test("桌面啟動：沒有資料金鑰 → 拒絕（exit 78）；沒有 token → 自動產生、只印一次、只綁 127.0.0.1", async () => {
	const home = mkdtempSync(join(tmpdir(), "lma-main-"));
	const r1 = await runMain({ LINE_MCP_HOME: home, LINE_MCP_PORT: "0", LINE_CONTROL_PORT: "0" }, /ready/);
	assert.equal(r1.code, 78, r1.out);
	assert.match(r1.out, /refusing to start: no data key/);
	const r2 = await runMain({ LINE_MCP_HOME: home, LINE_MCP_PORT: "0", LINE_CONTROL_PORT: "0", LMA_PASSPHRASE: "correct horse battery staple" }, /"event":"ready"/);
	const gen = r2.out.match(/"generated_token"/g) ?? [];
	assert.equal(gen.length, 2, r2.out);
	assert.match(r2.out, /"mcp":"http:\/\/127\.0\.0\.1:\d+\/mcp"/);
	assert.match(r2.out, /"control":"http:\/\/127\.0\.0\.1:\d+\/control"/);
	// 錯的 passphrase → 拒絕
	const r3 = await runMain({ LINE_MCP_HOME: home, LINE_MCP_PORT: "0", LINE_CONTROL_PORT: "0", LMA_PASSPHRASE: "wrong passphrase here" }, /"event":"ready"/);
	assert.equal(r3.code, 78, r3.out);
});
