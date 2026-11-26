/**
 * 雲端連接器閘道（預設關）：給 ChatGPT / Claude / Grok / Gemini 等「遠端 MCP」用。
 *
 * - 一樣只綁 127.0.0.1；對外靠使用者自己開的 HTTPS 通道（Cloudflare quick tunnel / ngrok / Tailscale Funnel）
 * - Host 必須是設定的公開網址（或 loopback，給本機測試）；其他一律 403（防 DNS rebinding）
 * - 驗證：OAuth 2.1 access token（DCR + PKCE，授權要輸入 App 內配對碼）或（可關閉）MCP 靜態 Bearer token
 * - 傳輸：Streamable HTTP（/mcp，stateless JSON）＋ 舊版 SSE（GET /sse、POST /messages）
 * - scope line.read 只註冊只讀工具；line.send 才有送出類工具（仍受 App 內所有關卡限制）
 */
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { createHash } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { buildMcpServer, TokenBucket, LOOPBACK } from "./server.ts";
import { OAuthServer, OAuthError, consentPage } from "./oauth.ts";
import type { ToolContext } from "./tools.ts";
import type { Store } from "../storage/db.ts";
import type { Audit } from "../ai/audit.ts";
import type { GatewayToken } from "./gateway-token.ts";

export interface GatewayOptions {
	host?: string;
	port?: number;
	store: Store;
	oauth: OAuthServer;
	audit?: Audit | null;
	/** H-2：連接器專用靜態 token（與本機 MCP token 分開；預設關、預設只讀、30 天到期） */
	gatewayToken: GatewayToken;
	ratePerMin?: number;
	sendRatePerMin?: number;
	maxBodyBytes?: number;
}

/** 允許帶 Origin 打 /mcp 的來源（雲端用戶端的網頁 / MCP Inspector） */
const MCP_ORIGINS = new Set(["https://chatgpt.com", "https://chat.openai.com", "https://claude.ai", "https://grok.com", "https://gemini.google.com", "http://localhost:6274", "http://127.0.0.1:6274"]);
const SEND_SET = new Set<string>(["post_digest", "send_message", "generate_and_send_image", "approve_pending", "set_chat_trust", "compose_scam_warning"]);

export function connectorSettings(store: Store) {
	return {
		enabled: store.getSetting("connector_enabled") === "on",
		public_url: store.getSetting("connector_public_url") ?? null,
		allow_static: store.getSetting("connector_allow_static") === "on", // H-2：預設關
	};
}

/** 公開網址只接受 https、無路徑 / 帳密 / query */
export function normalizePublicUrl(u: string): string {
	const url = new URL(u);
	if (url.protocol !== "https:") throw new Error("public URL must be https");
	if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw new Error("public URL must be just https://host");
	return `https://${url.host}`;
}

export async function startGateway(ctx: ToolContext, opts: GatewayOptions): Promise<{ server: Server; url: string; port: number }> {
	const host = opts.host ?? "127.0.0.1";
	if (!LOOPBACK.has(host)) throw new Error("gateway must bind to a loopback address");
	const { store, oauth } = opts;
	const bucket = new TokenBucket(opts.ratePerMin ?? 120);
	const sendBucket = new TokenBucket(opts.sendRatePerMin ?? 10);
	const authBucket = new TokenBucket(30);
	const maxBody = opts.maxBodyBytes ?? 256 * 1024;
	const sse = new Map<string, { transport: SSEServerTransport; allowWrite: boolean; client: string; principal: string; last: number }>();
	let port = opts.port ?? 47825;

	const send = (res: ServerResponse, code: number, body: unknown, headers: Record<string, string> = {}) => {
		if (res.headersSent) return;
		res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store", ...headers }).end(JSON.stringify(body));
	};
	const cors = (req: IncomingMessage): Record<string, string> =>
		req.headers.origin ? { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type, mcp-protocol-version", "access-control-allow-methods": "GET, POST, OPTIONS" } : {};

	/** 這個請求對應的外部網址（公開網址或 loopback） */
	function baseFor(req: IncomingMessage): string | null {
		const h = (req.headers.host ?? "").toLowerCase();
		const pub = connectorSettings(store).public_url;
		if (pub && h === new URL(pub).host.toLowerCase()) return pub;
		if (/^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(h)) return `http://${h}`;
		return null;
	}

	async function readRaw(req: IncomingMessage): Promise<string> {
		const len = Number(req.headers["content-length"] ?? 0);
		if (len > maxBody) throw Object.assign(new Error("payload too large"), { status: 413 });
		const chunks: Buffer[] = [];
		let n = 0;
		for await (const c of req) {
			n += (c as Buffer).length;
			if (n > maxBody) throw Object.assign(new Error("payload too large"), { status: 413 });
			chunks.push(c as Buffer);
		}
		return Buffer.concat(chunks).toString("utf8");
	}
	async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
		const raw = await readRaw(req);
		if ((req.headers["content-type"] ?? "").includes("application/json")) {
			const j = JSON.parse(raw || "{}") as Record<string, unknown>;
			return new URLSearchParams(Object.entries(j).map(([k, v]) => [k, String(v)]));
		}
		return new URLSearchParams(raw);
	}

	/** Bearer → { allowWrite, client }；無效回 null */
	function authenticate(req: IncomingMessage): { allowWrite: boolean; client: string; principal: string } | null {
		const h = req.headers.authorization ?? "";
		if (!h.startsWith("Bearer ")) return null;
		const tok = h.slice(7).trim();
		const info = oauth.verify(tok);
		if (info) {
			const c = oauth.client(info.client_id);
			return { allowWrite: info.scope.includes("line.send"), client: `oauth:${c?.name ?? info.client_id}`.slice(0, 60), principal: `oauth:${info.client_id}` };
		}
		const g = opts.gatewayToken.verify(tok);
		if (g) return { allowWrite: g.allowWrite, client: g.allowWrite ? "gateway-token:send" : "gateway-token:read", principal: `gateway:${createHash("sha256").update(tok).digest("hex")}` };
		return null;
	}

	function unauthorized(res: ServerResponse, base: string, req: IncomingMessage) {
		opts.audit?.log("mcp", "connector_unauthorized", { ok: false });
		send(res, 401, { error: "unauthorized" }, {
			"www-authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp", scope="line.read line.send"`,
			...cors(req),
			"access-control-expose-headers": "www-authenticate",
		});
	}

	function mcpFor(auth: { allowWrite: boolean; client: string }) {
		return buildMcpServer(ctx, {
			client: auth.client,
			allowWrite: auth.allowWrite,
			onCall: (tool, ok, ms, code) => opts.audit?.log("mcp", `tool:${tool}`, { ok, detail: { client: auth.client, ms, code, via: "connector" } }),
		});
	}

	const http = createServer(async (req, res) => {
		try {
			if (!connectorSettings(store).enabled) return void send(res, 404, { error: "connector gateway disabled in app" });
			const base = baseFor(req);
			if (!base) return void send(res, 403, { error: "forbidden host" });
			const url = new URL(req.url ?? "/", base);
			const path = url.pathname.replace(/\/+$/, "") || "/";
			if (req.method === "OPTIONS") return void res.writeHead(204, cors(req)).end();

			// ---------- 中繼資料 ----------
			if (req.method === "GET" && (path === "/.well-known/oauth-protected-resource" || path.startsWith("/.well-known/oauth-protected-resource/")))
				return void send(res, 200, oauth.resourceMetadata(base), cors(req));
			if (req.method === "GET" && (path.startsWith("/.well-known/oauth-authorization-server") || path.startsWith("/.well-known/openid-configuration")))
				return void send(res, 200, oauth.authServerMetadata(base), cors(req));

			// ---------- OAuth ----------
			if (path === "/oauth/register" && req.method === "POST") {
				if (!authBucket.take()) return void send(res, 429, { error: "rate_limited" }, cors(req));
				const body = JSON.parse((await readRaw(req)) || "{}") as Record<string, unknown>;
				return void send(res, 201, oauth.register(body), cors(req));
			}
			if (path === "/oauth/authorize" && req.method === "GET") {
				let p;
				try {
					p = oauth.validateAuthorize(url.searchParams, base);
				} catch (e) {
					const r = (e as { redirect?: { redirect_uri: string; state: string | null } }).redirect;
					if (r && e instanceof OAuthError) {
						const back = new URL(r.redirect_uri);
						back.searchParams.set("error", e.error);
						back.searchParams.set("error_description", e.description);
						if (r.state !== null) back.searchParams.set("state", r.state);
						back.searchParams.set("iss", base);
						return void res.writeHead(302, { location: back.toString() }).end();
					}
					throw e;
				}
				return void html(res, 200, consentPage(p, oauth.beginConsent(p)));
			}
			if (path === "/oauth/authorize" && req.method === "POST") {
				if (!authBucket.take()) return void html(res, 429, "<p>Too many attempts. Wait a minute.</p>");
				const form = await readForm(req);
				try {
					const { redirect } = oauth.completeConsent(form, base);
					return void res.writeHead(302, { location: redirect, "cache-control": "no-store" }).end();
				} catch (e) {
					if (e instanceof OAuthError && e.error === "access_denied") {
						// 配對碼錯：重新出一張頁（新的 nonce）
						return void html(res, e.status, `<p style="font-family:sans-serif;color:#c00">${e.description}</p><p style="font-family:sans-serif">請回到 AI 用戶端重新按「連線」。</p>`);
					}
					throw e;
				}
			}
			if (path === "/oauth/token" && req.method === "POST") {
				if (!authBucket.take()) return void send(res, 429, { error: "rate_limited" }, cors(req));
				const form = await readForm(req);
				return void send(res, 200, oauth.token(form, req.headers.authorization, base), { ...cors(req), pragma: "no-cache" });
			}
			if (path === "/oauth/revoke" && req.method === "POST") {
				oauth.revokeToken(await readForm(req), req.headers.authorization);
				return void send(res, 200, {}, cors(req));
			}

			// ---------- MCP ----------
			if (path === "/mcp" || path === "/sse" || path === "/messages") {
				if (req.headers.origin && !MCP_ORIGINS.has(String(req.headers.origin))) return void send(res, 403, { error: "forbidden origin" });
				const auth = authenticate(req);
				if (!auth) return void unauthorized(res, base, req);
				if (!bucket.take()) return void send(res, 429, { error: "rate_limited" }, { "retry-after": "5" });

				if (path === "/sse" && req.method === "GET") {
					if (sse.size >= 10) {
						const oldest = [...sse.entries()].sort((a, b) => a[1].last - b[1].last)[0]!;
						void oldest[1].transport.close();
						sse.delete(oldest[0]);
					}
					const transport = new SSEServerTransport("/messages", res);
					const entry = { transport, allowWrite: auth.allowWrite, client: auth.client, principal: auth.principal, last: Date.now() };
					sse.set(transport.sessionId, entry);
					const ping = setInterval(() => res.write(": ping\n\n"), 25_000);
					res.on("close", () => {
						clearInterval(ping);
						sse.delete(transport.sessionId);
					});
					await mcpFor(auth).connect(transport);
					return;
				}
				if (path === "/messages" && req.method === "POST") {
					const s = sse.get(url.searchParams.get("sessionId") ?? "");
					if (!s) return void send(res, 404, { error: "unknown session" });
					// Bind to the verified client ID/token generation, never a user-chosen display name.
					if (s.principal !== auth.principal || (s.allowWrite && !auth.allowWrite)) return void send(res, 403, { error: "session belongs to another client" });
					s.last = Date.now();
					const raw = await readRaw(req);
					const body = JSON.parse(raw || "null");
					if (sendCount(body) && !sendBucket.take(sendCount(body))) return void send(res, 429, { error: "rate_limited" });
					await s.transport.handlePostMessage(req, res, body);
					return;
				}
				if (path === "/mcp" && req.method === "POST") {
					let body: unknown;
					try {
						body = JSON.parse((await readRaw(req)) || "null");
					} catch (e) {
						return void send(res, (e as { status?: number }).status ?? 400, { error: (e as Error).message });
					}
					const n = sendCount(body);
					if (n && !sendBucket.take(n)) return void send(res, 429, { error: "rate_limited", message: "too many send calls" }, { "retry-after": "30" });
					const mcp = mcpFor(auth);
					const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
					res.on("close", () => {
						void transport.close();
						void mcp.close();
					});
					await mcp.connect(transport);
					await transport.handleRequest(req, res, body);
					return;
				}
				return void res.writeHead(405, { allow: path === "/sse" ? "GET" : "POST" }).end();
			}
			if (path === "/" && req.method === "GET") return void send(res, 200, { name: "LINE MCP Companion connector", mcp: `${base}/mcp`, sse: `${base}/sse` });
			send(res, 404, { error: "not found" });
		} catch (e) {
			if (e instanceof OAuthError) return void send(res, e.status, { error: e.error, error_description: e.description }, cors(req));
			const status = (e as { status?: number }).status ?? (e instanceof SyntaxError ? 400 : 500);
			send(res, status, { error: status === 500 ? "server_error" : (e as Error).message });
		}
	});
	http.headersTimeout = 10_000;
	http.requestTimeout = 0; // SSE 是長連線；body 讀取另有大小上限
	await new Promise<void>((resolve) => http.listen(port, host, resolve));
	const addr = http.address();
	port = typeof addr === "object" && addr ? addr.port : port;
	return { server: http, url: `http://${host}:${port}`, port };
}

function html(res: ServerResponse, code: number, body: string) {
	res.writeHead(code, {
		"content-type": "text/html; charset=utf-8",
		"cache-control": "no-store",
		"x-frame-options": "DENY",
		"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
		"referrer-policy": "no-referrer",
	}).end(body);
}

function sendCount(body: unknown): number {
	const arr = Array.isArray(body) ? body : [body];
	return arr.filter((m) => m && typeof m === "object" && (m as { method?: string }).method === "tools/call" && SEND_SET.has(String((m as { params?: { name?: string } }).params?.name))).length;
}
