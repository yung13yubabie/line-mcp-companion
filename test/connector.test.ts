import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { SyncEngine } from "../src/sync/engine.ts";
import { OAuthServer, redirectOk } from "../src/mcp/oauth.ts";
import { startGateway, normalizePublicUrl } from "../src/mcp/gateway.ts";
import { buildMcpServer } from "../src/mcp/server.ts";
import { Audit } from "../src/ai/audit.ts";
import { FakeSource, ALICE } from "./fake-source.ts";

const STATIC = "static-token-0123456789abcdef";
const b64 = (b: Buffer) => b.toString("base64url");

async function setup() {
	const dir = mkdtempSync(join(tmpdir(), "lma-conn-"));
	const store = openDatabase(join(dir, "line.db"));
	const src = new FakeSource();
	const sync = new SyncEngine(store, src);
	const whitelist = new Whitelist(store);
	await sync.fullSync();
	whitelist.set(ALICE, true);
	await sync.fullSync();
	const audit = new Audit(store);
	const oauth = new OAuthServer(store, audit);
	const ctx = { store, whitelist, sync, media: null };
	store.setSetting("connector_enabled", "on");
	const gw = await startGateway(ctx, { port: 0, store, oauth, audit, getStaticToken: () => STATIC });
	const base = gw.url.replace("127.0.0.1", "localhost");
	const close = () => {
		gw.server.closeAllConnections();
		gw.server.close();
		store.close();
		rmSync(dir, { recursive: true, force: true });
	};
	return { store, oauth, gw, base, close, ctx, audit };
}

/** 跑完整 OAuth：DCR → authorize（配對碼）→ token */
async function oauthFlow(base: string, oauth: OAuthServer, opts: { allowSend?: boolean; method?: string } = {}) {
	const reg = await fetch(`${base}/oauth/register`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ client_name: "Test<script>", redirect_uris: ["https://client.example/cb"], token_endpoint_auth_method: opts.method ?? "none" }),
	});
	assert.equal(reg.status, 201);
	const client = (await reg.json()) as { client_id: string; client_secret?: string; client_name: string };
	assert.ok(!client.client_name.includes("<"));
	const verifier = b64(randomBytes(32));
	const challenge = b64(createHash("sha256").update(verifier).digest());
	const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: "https://client.example/cb", code_challenge: challenge, code_challenge_method: "S256", state: "xyz", scope: "line.read line.send", resource: `${base}/mcp` });
	const page = await fetch(`${base}/oauth/authorize?${q}`);
	assert.equal(page.status, 200);
	assert.match(page.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
	const htmlText = await page.text();
	const nonce = /name="nonce" value="([^"]+)"/.exec(htmlText)![1]!;
	const form = new URLSearchParams({ nonce, pairing_code: oauth.pairingCode().code.toLowerCase(), action: "allow", ...(opts.allowSend ? { allow_send: "on" } : {}) });
	const done = await fetch(`${base}/oauth/authorize`, { method: "POST", body: form, redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" } });
	assert.equal(done.status, 302);
	const loc = new URL(done.headers.get("location")!);
	assert.equal(loc.origin + loc.pathname, "https://client.example/cb");
	assert.equal(loc.searchParams.get("state"), "xyz");
	assert.equal(loc.searchParams.get("iss"), base);
	const code = loc.searchParams.get("code")!;
	const tokForm: Record<string, string> = { grant_type: "authorization_code", code, redirect_uri: "https://client.example/cb", code_verifier: verifier, client_id: client.client_id, resource: `${base}/mcp` };
	if (client.client_secret) tokForm.client_secret = client.client_secret;
	const tok = await fetch(`${base}/oauth/token`, { method: "POST", body: new URLSearchParams(tokForm) });
	assert.equal(tok.status, 200);
	const tokens = (await tok.json()) as { access_token: string; refresh_token: string; scope: string };
	// code 只能用一次
	const again = await fetch(`${base}/oauth/token`, { method: "POST", body: new URLSearchParams(tokForm) });
	assert.equal(again.status, 400);
	return { client, tokens, verifier };
}

test("連接器閘道：中繼資料、401 挑戰、Host / Origin 檢查、關閉時 404", async () => {
	const { base, store, close, gw } = await setup();
	try {
		const prm = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as { resource: string; authorization_servers: string[] };
		assert.equal(prm.resource, `${base}/mcp`);
		assert.deepEqual(prm.authorization_servers, [base]);
		const asm = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
		assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
		assert.equal(asm.registration_endpoint, `${base}/oauth/register`);
		const r401 = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
		assert.equal(r401.status, 401);
		assert.match(r401.headers.get("www-authenticate") ?? "", /resource_metadata="http:\/\/localhost:\d+\/\.well-known\/oauth-protected-resource\/mcp"/);
		// 錯的 Host（DNS rebinding / 別人的網域）
		const { request } = await import("node:http");
		const badStatus = await new Promise<number>((resolve, reject) => {
			const r = request(`${gw.url}/mcp`, { method: "POST", headers: { host: "evil.example", authorization: `Bearer ${STATIC}` } }, (res) => {
				res.resume();
				resolve(res.statusCode ?? 0);
			});
			r.on("error", reject);
			r.end("{}");
		});
		assert.equal(badStatus, 403);
		// 公開網址：只接受 https://host
		assert.throws(() => normalizePublicUrl("http://x.trycloudflare.com"));
		assert.throws(() => normalizePublicUrl("https://u:p@x.com"));
		assert.equal(normalizePublicUrl("https://abc.trycloudflare.com/"), "https://abc.trycloudflare.com");
		// 不認得的 Origin
		const o = await fetch(`${base}/mcp`, { method: "POST", headers: { origin: "https://evil.example", authorization: `Bearer ${STATIC}` }, body: "{}" });
		assert.equal(o.status, 403);
		// 靜態 token 可關
		store.setSetting("connector_allow_static", "off");
		const st = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: `Bearer ${STATIC}`, "content-type": "application/json" }, body: "{}" });
		assert.equal(st.status, 401);
		store.setSetting("connector_enabled", "off");
		assert.equal((await fetch(`${base}/.well-known/oauth-authorization-server`)).status, 404);
		// redirect_uri 規則
		assert.ok(redirectOk("https://chatgpt.com/connector_platform_oauth_redirect"));
		assert.ok(redirectOk("http://localhost:33418/callback"));
		assert.ok(!redirectOk("http://evil.example/cb"));
		assert.ok(!redirectOk("javascript:alert(1)"));
	} finally {
		close();
	}
});

test("OAuth 2.1：DCR + PKCE + 配對碼 → 只讀 token 只看得到只讀工具；送出需另外勾選", async () => {
	const { base, oauth, close } = await setup();
	try {
		const { tokens } = await oauthFlow(base, oauth);
		assert.equal(tokens.scope, "line.read");
		const c = new Client({ name: "t", version: "0" });
		await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${tokens.access_token}` } } }));
		const names = (await c.listTools()).tools.map((t) => t.name);
		assert.ok(names.includes("search") && names.includes("fetch") && names.includes("get_messages"));
		const r = (await c.callTool({ name: "search", arguments: { query: "晚餐" } })) as { content: { text: string }[] };
		assert.ok(JSON.parse(r.content[0]!.text).results.length >= 1);
		await c.close();
		// 有 send scope（客端是機密 client，用 client_secret_basic 以外的 post）
		const w = await oauthFlow(base, oauth, { allowSend: true, method: "client_secret_post" });
		assert.equal(w.tokens.scope, "line.read line.send");
		// 錯的配對碼 → 403，錯 5 次作廢並鎖一分鐘
		const verifier = b64(randomBytes(32));
		const q = new URLSearchParams({ response_type: "code", client_id: w.client.client_id, redirect_uri: "https://client.example/cb", code_challenge: b64(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256" });
		for (let i = 0; i < 5; i++) {
			const nonce = /name="nonce" value="([^"]+)"/.exec(await (await fetch(`${base}/oauth/authorize?${q}`)).text())![1]!;
			const bad = await fetch(`${base}/oauth/authorize`, { method: "POST", body: new URLSearchParams({ nonce, pairing_code: "WRONG000", action: "allow" }), redirect: "manual" });
			assert.equal(bad.status, 403);
		}
		const nonce = /name="nonce" value="([^"]+)"/.exec(await (await fetch(`${base}/oauth/authorize?${q}`)).text())![1]!;
		const locked = await fetch(`${base}/oauth/authorize`, { method: "POST", body: new URLSearchParams({ nonce, pairing_code: oauth.pairingCode().code, action: "allow" }), redirect: "manual" });
		assert.equal(locked.status, 429);
		// 沒有 PKCE → redirect 回去帶 error
		const noPkce = await fetch(`${base}/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: w.client.client_id, redirect_uri: "https://client.example/cb", state: "s" })}`, { redirect: "manual" });
		assert.equal(noPkce.status, 302);
		assert.equal(new URL(noPkce.headers.get("location")!).searchParams.get("error"), "invalid_request");
		// 沒註冊的 redirect_uri → 不 redirect（避免 open redirect）
		const evil = await fetch(`${base}/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: w.client.client_id, redirect_uri: "https://evil.example/cb" })}`, { redirect: "manual" });
		assert.equal(evil.status, 400);
		// 機密 client 沒帶 secret → 401
		const ns = await fetch(`${base}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: w.tokens.refresh_token, client_id: w.client.client_id }) });
		assert.equal(ns.status, 401);
	} finally {
		close();
	}
});

test("OAuth：refresh 輪換、重用撤銷整串、App 撤銷 client 立即失效；寫入工具只給 send scope", async () => {
	const { base, oauth, close, ctx } = await setup();
	try {
		const { client, tokens } = await oauthFlow(base, oauth);
		const r1 = (await (await fetch(`${base}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }) })).json()) as { access_token: string; refresh_token: string };
		assert.ok(r1.access_token && r1.access_token !== tokens.access_token);
		// 舊 refresh 重用 → 400，且新的也被撤銷
		const reuse = await fetch(`${base}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }) });
		assert.equal(reuse.status, 400);
		assert.equal(oauth.verify(r1.access_token), null);
		// 新流程 → App 撤銷
		const again = await oauthFlow(base, oauth);
		assert.ok(oauth.verify(again.tokens.access_token));
		assert.ok(oauth.listClients().some((c) => c.client_id === again.client.client_id && c.active));
		oauth.revokeClient(again.client.client_id);
		const after = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: `Bearer ${again.tokens.access_token}`, "content-type": "application/json" }, body: "{}" });
		assert.equal(after.status, 401);
		// scope → 工具
		const full = { ...ctx, ai: {} as never, scam: {} as never };
		const listed = async (allowWrite: boolean) => {
			const s = buildMcpServer(full, { allowWrite }) as unknown as { _registeredTools: Record<string, unknown> };
			return Object.keys(s._registeredTools);
		};
		const ro = await listed(false);
		const rw = await listed(true);
		assert.ok(!ro.includes("send_message") && !ro.includes("approve_pending") && !ro.includes("set_chat_trust") && !ro.includes("compose_scam_warning"));
		assert.ok(rw.includes("send_message") && rw.includes("approve_pending"));
	} finally {
		close();
	}
});

test("舊版 SSE 傳輸 + 靜態 token（xAI API / Claude Code 等可帶 header 的用戶端）", async () => {
	const { base, close } = await setup();
	try {
		const c = new Client({ name: "sse", version: "0" });
		const h = { authorization: `Bearer ${STATIC}` };
		await c.connect(new SSEClientTransport(new URL(`${base}/sse`), { eventSourceInit: { fetch: (u, i) => fetch(u, { ...i, headers: { ...(i?.headers as Record<string, string>), ...h } }) }, requestInit: { headers: h } }));
		const names = (await c.listTools()).tools.map((t) => t.name);
		assert.ok(names.includes("fetch"));
		const r = (await c.callTool({ name: "list_allowed_chats", arguments: {} })) as { content: { text: string }[] };
		assert.ok(r.content[0]!.text.includes(ALICE));
		await c.close();
	} finally {
		close();
	}
});
