import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { openDatabase } from "../src/storage/db.ts";
import { OAuthServer, consentPage } from "../src/mcp/oauth.ts";
import { startGateway } from "../src/mcp/gateway.ts";
import { GatewayToken } from "../src/mcp/gateway-token.ts";
import { buildMcpServer } from "../src/mcp/server.ts";
import { Whitelist } from "../src/whitelist.ts";

function grant(oauth: OAuthServer, base: string, name: string, requested = "line.read", send = false) {
	const client = oauth.register({ client_name: name, redirect_uris: ["https://client.example/cb"] });
	const verifier = randomBytes(32).toString("base64url");
	const p = oauth.validateAuthorize(new URLSearchParams({
		client_id: String(client.client_id), redirect_uri: "https://client.example/cb", response_type: "code", scope: requested,
		code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource: base + "/mcp",
	}), base);
	const nonce = oauth.beginConsent(p);
	const page = consentPage(p, nonce);
	const result = oauth.completeConsent(new URLSearchParams({ nonce, pairing_code: oauth.pairingCode().code, action: "allow", ...(send ? { allow_send: "on" } : {}) }), base);
	const tokens = oauth.token(new URLSearchParams({ client_id: String(client.client_id), grant_type: "authorization_code", code: new URL(result.redirect).searchParams.get("code")!, code_verifier: verifier, redirect_uri: "https://client.example/cb", resource: base + "/mcp" }), undefined, base);
	return { client, tokens, page };
}

test("consent binds issued scope to the original request as well as the user decision", () => {
	const store = openDatabase(":memory:");
	try {
		const oauth = new OAuthServer(store);
		const forged = grant(oauth, "https://audit.example", "readonly", "line.read", true);
		assert.match(forged.page, /name="allow_send" disabled/);
		assert.equal(forged.tokens.scope, "line.read");
		assert.equal(grant(oauth, "https://audit.example", "writer", "line.read line.send", true).tokens.scope, "line.read line.send");
		assert.equal(grant(oauth, "https://audit.example", "reader", "line.read line.send", false).tokens.scope, "line.read");
	} finally { store.close(); }
});

test("SSE sessions bind to the verified client ID rather than a colliding display name", async () => {
	const store = openDatabase(":memory:");
	store.setSetting("connector_enabled", "on");
	const oauth = new OAuthServer(store);
	const gatewayToken = new GatewayToken(store);
	const gw = await startGateway({ store, whitelist: new Whitelist(store), sync: null, media: null }, { store, oauth, gatewayToken, port: 0 });
	const abort = new AbortController();
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	try {
		const a = grant(oauth, gw.url, "same-name");
		const b = grant(oauth, gw.url, "same-name");
		assert.notEqual(a.client.client_id, b.client.client_id);
		const response = await fetch(gw.url + "/sse", { headers: { authorization: "Bearer " + a.tokens.access_token }, signal: abort.signal });
		assert.equal(response.status, 200);
		reader = response.body!.getReader();
		let raw = "";
		while (!raw.includes("sessionId=")) { const x = await reader.read(); assert.ok(!x.done); raw += new TextDecoder().decode(x.value); }
		const endpoint = /data: ([^\n]+)/.exec(raw)![1]!.trim();
		const post = (token: unknown, id: number) => fetch(new URL(endpoint, gw.url), { method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list" }) });
		const collision = await post(b.tokens.access_token, 10);
		assert.equal(collision.status, 403); await collision.text();
		const owner = await post(a.tokens.access_token, 11);
		assert.equal(owner.status, 202); await owner.text();
	} finally {
		abort.abort();
		if (reader) await reader.cancel().catch(() => {});
		gw.server.closeAllConnections();
		await new Promise<void>((resolve) => gw.server.close(() => resolve()));
		store.close();
	}
});

test("tool input complexity is bounded before schema validation and ordinary calls still work", async () => {
	const store = openDatabase(":memory:");
	const server = buildMcpServer({ store, whitelist: new Whitelist(store), sync: null, media: null });
	const client = new Client({ name: "security-regression", version: "1" });
	const [a, b] = InMemoryTransport.createLinkedPair();
	try {
		await server.connect(a); await client.connect(b);
		const large = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => ["k" + i, 0]));
		const rejected = await client.callTool({ name: "list_allowed_chats", arguments: large });
		assert.equal(rejected.isError, true);
		assert.match(JSON.stringify(rejected), /maximum of 4096 elements/);
		const normal = await client.callTool({ name: "list_allowed_chats", arguments: {} });
		assert.ok(!normal.isError);
	} finally { await client.close(); await server.close(); store.close(); }
});

test("SQLite main file and sidecars are private even in an existing traversable directory", { skip: process.platform === "win32" }, () => {
	const root = mkdtempSync(join(tmpdir(), "lma-permission-regression-"));
	const dir = join(root, "existing");
	mkdirSync(dir, { mode: 0o755 });
	const path = join(dir, "line.db");
	const oldMask = process.umask(0o022);
	let store: ReturnType<typeof openDatabase> | undefined;
	try {
		store = openDatabase(path);
		store.upsertChat({ id: "synthetic", type: "GROUP", name: "Synthetic" });
		for (const suffix of ["", "-wal", "-shm"]) assert.equal(statSync(path + suffix).mode & 0o777, 0o600, suffix || "main database");
	} finally { store?.close(); process.umask(oldMask); rmSync(root, { recursive: true, force: true }); }
});
