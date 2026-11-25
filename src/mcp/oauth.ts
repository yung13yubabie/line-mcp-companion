/**
 * 雲端連接器用的 OAuth 2.1 授權伺服器（最小實作，給 ChatGPT / Claude / Grok / Gemini 的自訂連接器）。
 *
 * - 授權碼 + PKCE（只收 S256），refresh token 輪換（重用 → 整個 family 撤銷）
 * - RFC 7591 動態註冊（DCR）：public client（none）或 client_secret_post / basic
 * - RFC 8414 授權伺服器中繼資料、RFC 9728 受保護資源中繼資料、RFC 8707 resource 參數、RFC 9207 iss
 * - 使用者同意：授權頁要輸入 App 裡顯示的「配對碼」（8 碼、10 分鐘、一次性；錯 5 次作廢）
 * - 資料庫只存 SHA-256 雜湊；access token 1 小時、refresh token 30 天
 * - scope：line.read（只讀工具）、line.send（送出 / 核准等，仍受 App 內所有關卡限制）
 */
import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import type { Store } from "../storage/db.ts";
import type { Audit } from "../ai/audit.ts";

export const SCOPES = ["line.read", "line.send"] as const;
const ACCESS_TTL = 3600_000;
const REFRESH_TTL = 30 * 86_400_000;
const CODE_TTL = 5 * 60_000;
const PAIR_TTL = 10 * 60_000;
const MAX_CLIENTS = 50;

const sha = (s: string) => createHash("sha256").update(s).digest("base64url");
const rand = (n = 32) => randomBytes(n).toString("base64url");
const PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export class OAuthError extends Error {
	readonly error: string;
	readonly description: string;
	readonly status: number;
	constructor(error: string, description: string, status = 400) {
		super(description);
		this.error = error;
		this.description = description;
		this.status = status;
	}
}

export interface ClientRow {
	client_id: string;
	secret_hash: string | null;
	name: string;
	redirect_uris: string;
	auth_method: string;
	created_at: number;
	last_used_at: number | null;
}

export interface TokenInfo {
	client_id: string;
	scope: string[];
	expires_at: number;
}

/** redirect_uri 規則：https，或 http 只限 loopback（CLI 用戶端）；不可有 fragment */
export function redirectOk(u: string): boolean {
	if (u.length > 500) return false;
	let url: URL;
	try {
		url = new URL(u);
	} catch {
		return false;
	}
	if (url.hash) return false;
	if (url.protocol === "https:") return true;
	if (url.protocol === "http:") return ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
	return false;
}

function safeEq(a: string, b: string): boolean {
	const x = Buffer.from(a);
	const y = Buffer.from(b);
	return x.length === y.length && timingSafeEqual(x, y);
}

export class OAuthServer {
	#store: Store;
	#audit: Audit | null;
	#now: () => number;
	#pair: { code: string; expires: number } | null = null;
	#lockUntil = 0;
	#fails = 0;
	/** 授權頁 nonce → 參數（防竄改、一次性） */
	#pending = new Map<string, { params: AuthorizeParams; expires: number }>();
	#regTimes: number[] = [];

	constructor(store: Store, audit: Audit | null = null, now: () => number = Date.now) {
		this.#store = store;
		this.#audit = audit;
		this.#now = now;
	}

	// ---------- 中繼資料 ----------
	authServerMetadata(base: string) {
		return {
			issuer: base,
			authorization_endpoint: `${base}/oauth/authorize`,
			token_endpoint: `${base}/oauth/token`,
			registration_endpoint: `${base}/oauth/register`,
			revocation_endpoint: `${base}/oauth/revoke`,
			response_types_supported: ["code"],
			response_modes_supported: ["query"],
			grant_types_supported: ["authorization_code", "refresh_token"],
			code_challenge_methods_supported: ["S256"],
			token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
			revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
			scopes_supported: [...SCOPES],
			authorization_response_iss_parameter_supported: true,
					};
	}

	resourceMetadata(base: string) {
		return {
			resource: `${base}/mcp`,
			authorization_servers: [base],
			scopes_supported: [...SCOPES],
			bearer_methods_supported: ["header"],
			resource_name: "LINE MCP Companion",
		};
	}

	// ---------- 配對碼（App 內顯示） ----------
	pairingCode(renew = false): { code: string; expires_at: number } {
		const t = this.#now();
		if (renew || !this.#pair || this.#pair.expires < t) {
			let c = "";
			for (let i = 0; i < 8; i++) c += PAIR_ALPHABET[randomInt(PAIR_ALPHABET.length)];
			this.#pair = { code: c, expires: t + PAIR_TTL };
		}
		return { code: this.#pair.code, expires_at: this.#pair.expires };
	}

	#checkPairing(input: string): boolean {
		const t = this.#now();
		if (t < this.#lockUntil) throw new OAuthError("access_denied", "too many attempts, wait a minute", 429);
		const p = this.#pair;
		const norm = input.toUpperCase().replace(/[^A-Z0-9]/g, "");
		if (p && p.expires >= t && norm.length === p.code.length && safeEq(norm, p.code)) {
			this.#pair = null; // 一次性
			this.#fails = 0;
			return true;
		}
		// 連續錯 5 次（不管目前有沒有配對碼）→ 作廢並鎖一分鐘
		if (++this.#fails >= 5) {
			this.#fails = 0;
			this.#pair = null;
			this.#lockUntil = t + 60_000;
			this.#audit?.log("system", "oauth_pairing_locked", { ok: false });
		}
		return false;
	}

	// ---------- DCR ----------
	register(body: Record<string, unknown>): Record<string, unknown> {
		const t = this.#now();
		this.#regTimes = this.#regTimes.filter((x) => x > t - 3600_000);
		if (this.#regTimes.length >= 20) throw new OAuthError("temporarily_unavailable", "too many registrations", 429);
		const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
		if (!uris.length || uris.length > 5 || !uris.every(redirectOk)) throw new OAuthError("invalid_redirect_uri", "redirect_uris must be https (or http loopback), max 5");
		const method = String(body.token_endpoint_auth_method ?? "none");
		if (!["none", "client_secret_post", "client_secret_basic"].includes(method)) throw new OAuthError("invalid_client_metadata", "unsupported token_endpoint_auth_method");
		const grants = Array.isArray(body.grant_types) ? body.grant_types.map(String) : ["authorization_code", "refresh_token"];
		if (grants.some((g) => g !== "authorization_code" && g !== "refresh_token")) throw new OAuthError("invalid_client_metadata", "unsupported grant_types");
		const name = String(body.client_name ?? "MCP client").replace(/[\u0000-\u001f<>]/g, "").slice(0, 60) || "MCP client";
		this.#prune();
		const n = (this.#store.db.prepare("SELECT COUNT(*) AS n FROM oauth_client").get() as { n: number }).n;
		if (n >= MAX_CLIENTS) throw new OAuthError("temporarily_unavailable", "too many clients registered; revoke some in the app", 429);
		const clientId = "lmc_" + rand(16);
		const secret = method === "none" ? null : rand(32);
		this.#store.db
			.prepare("INSERT INTO oauth_client(client_id, secret_hash, name, redirect_uris, auth_method, created_at) VALUES (?,?,?,?,?,?)")
			.run(clientId, secret ? sha(secret) : null, name, JSON.stringify(uris), method, t);
		this.#regTimes.push(t);
		this.#audit?.log("system", "oauth_client_registered", { detail: { client: name, method } });
		return {
			client_id: clientId,
			...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
			client_id_issued_at: Math.floor(t / 1000),
			client_name: name,
			redirect_uris: uris,
			token_endpoint_auth_method: method,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			scope: SCOPES.join(" "),
		};
	}

	client(id: string): ClientRow | undefined {
		return this.#store.db.prepare("SELECT * FROM oauth_client WHERE client_id = ?").get(id) as ClientRow | undefined;
	}

	// ---------- 授權 ----------
	/** 驗證 /authorize 參數；錯在 redirect_uri / client 以外的才能 redirect 回去（呼叫端處理） */
	validateAuthorize(q: URLSearchParams, base: string): AuthorizeParams {
		const clientId = q.get("client_id") ?? "";
		const c = this.client(clientId);
		if (!c) throw new OAuthError("invalid_client", "unknown client_id (register first)");
		const redirect = q.get("redirect_uri") ?? "";
		const uris = JSON.parse(c.redirect_uris) as string[];
		if (!uris.includes(redirect)) throw new OAuthError("invalid_request", "redirect_uri not registered");
		const p: AuthorizeParams = {
			client_id: clientId,
			client_name: c.name,
			redirect_uri: redirect,
			state: q.get("state")?.slice(0, 500) ?? null,
			code_challenge: q.get("code_challenge") ?? "",
			resource: q.get("resource"),
			scope: parseScope(q.get("scope")),
		};
		const redirectErr = (error: string, d: string) => Object.assign(new OAuthError(error, d), { redirect: p });
		if (q.get("response_type") !== "code") throw redirectErr("unsupported_response_type", "response_type must be code");
		if ((q.get("code_challenge_method") ?? "") !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge)) throw redirectErr("invalid_request", "PKCE S256 required");
		if (p.resource && !resourceOk(p.resource, base)) throw redirectErr("invalid_target", "resource must be this MCP server");
		return p;
	}

	/** 產生授權頁 nonce（綁定參數） */
	beginConsent(p: AuthorizeParams): string {
		const t = this.#now();
		for (const [k, v] of this.#pending) if (v.expires < t) this.#pending.delete(k);
		if (this.#pending.size > 100) this.#pending.clear();
		const nonce = rand(18);
		this.#pending.set(nonce, { params: p, expires: t + PAIR_TTL });
		return nonce;
	}

	/** 使用者在授權頁送出：檢查配對碼，回傳要 redirect 的網址 */
	completeConsent(form: URLSearchParams, base: string): { redirect: string } {
		const nonce = form.get("nonce") ?? "";
		const pend = this.#pending.get(nonce);
		if (!pend || pend.expires < this.#now()) throw new OAuthError("invalid_request", "授權頁已過期，請回到 AI 用戶端重新連線");
		const p = pend.params;
		const back = new URL(p.redirect_uri);
		if (p.state !== null) back.searchParams.set("state", p.state);
		back.searchParams.set("iss", base);
		if (form.get("action") === "deny") {
			this.#pending.delete(nonce);
			back.searchParams.set("error", "access_denied");
			this.#audit?.log("ui", "oauth_denied", { detail: { client: p.client_name } });
			return { redirect: back.toString() };
		}
		if (!this.#checkPairing(form.get("pairing_code") ?? "")) throw new OAuthError("access_denied", "配對碼錯誤或已過期（在 App 設定 → 雲端連接器 看最新配對碼）", 403);
		this.#pending.delete(nonce);
		// A modified form must not grant a scope absent from the bound authorization request.
		const scope = form.get("allow_send") === "on" && p.scope.includes("line.send") ? ["line.read", "line.send"] : ["line.read"];
		const code = rand(32);
		this.#store.db
			.prepare("INSERT INTO oauth_code(code_hash, client_id, redirect_uri, challenge, scope, resource, expires_at) VALUES (?,?,?,?,?,?,?)")
			.run(sha(code), p.client_id, p.redirect_uri, p.code_challenge, scope.join(" "), p.resource, this.#now() + CODE_TTL);
		this.#audit?.log("ui", "oauth_authorized", { detail: { client: p.client_name, scope: scope.join(" ") } });
		back.searchParams.set("code", code);
		return { redirect: back.toString() };
	}

	// ---------- token ----------
	#authClient(form: URLSearchParams, authz: string | undefined): ClientRow {
		let id = form.get("client_id") ?? "";
		let secret = form.get("client_secret");
		if (authz?.startsWith("Basic ")) {
			const dec = Buffer.from(authz.slice(6), "base64").toString("utf8");
			const i = dec.indexOf(":");
			if (i > 0) {
				id = decodeURIComponent(dec.slice(0, i));
				secret = decodeURIComponent(dec.slice(i + 1));
			}
		}
		const c = this.client(id);
		if (!c) throw new OAuthError("invalid_client", "unknown client", 401);
		if (c.secret_hash) {
			if (!secret || !safeEq(sha(secret), c.secret_hash)) throw new OAuthError("invalid_client", "bad client secret", 401);
		}
		return c;
	}

	token(form: URLSearchParams, authz: string | undefined, base: string): Record<string, unknown> {
		const c = this.#authClient(form, authz);
		const grant = form.get("grant_type");
		const t = this.#now();
		const db = this.#store.db;
		if (grant === "authorization_code") {
			const code = form.get("code") ?? "";
			const row = db.prepare("SELECT * FROM oauth_code WHERE code_hash = ?").get(sha(code)) as
				| { client_id: string; redirect_uri: string; challenge: string; scope: string; resource: string | null; expires_at: number }
				| undefined;
			db.prepare("DELETE FROM oauth_code WHERE code_hash = ? OR expires_at < ?").run(sha(code), t); // 一次性
			if (!row || row.expires_at < t || row.client_id !== c.client_id) throw new OAuthError("invalid_grant", "invalid or expired code");
			if ((form.get("redirect_uri") ?? row.redirect_uri) !== row.redirect_uri) throw new OAuthError("invalid_grant", "redirect_uri mismatch");
			const verifier = form.get("code_verifier") ?? "";
			if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || sha(verifier) !== row.challenge) throw new OAuthError("invalid_grant", "PKCE verification failed");
			const res = form.get("resource");
			if (res && !resourceOk(res, base)) throw new OAuthError("invalid_target", "resource must be this MCP server");
			return this.#issue(c.client_id, row.scope, rand(12));
		}
		if (grant === "refresh_token") {
			const rt = form.get("refresh_token") ?? "";
			const row = db.prepare("SELECT * FROM oauth_token WHERE token_hash = ? AND kind = 'refresh'").get(sha(rt)) as
				| { client_id: string; scope: string; family: string; expires_at: number; used: number }
				| undefined;
			if (!row || row.client_id !== c.client_id || row.expires_at < t) throw new OAuthError("invalid_grant", "invalid refresh token");
			if (row.used) {
				// 重用 → 可能外洩，整個 family 撤銷
				db.prepare("DELETE FROM oauth_token WHERE family = ?").run(row.family);
				this.#audit?.log("system", "oauth_refresh_reuse_revoked", { ok: false, detail: { client: c.name } });
				throw new OAuthError("invalid_grant", "refresh token reused; access revoked");
			}
			db.prepare("UPDATE oauth_token SET used = 1 WHERE token_hash = ?").run(sha(rt));
			let scope = row.scope;
			const req = form.get("scope");
			if (req) {
				const want = parseScope(req);
				scope = want.filter((s) => row.scope.split(" ").includes(s)).join(" ") || row.scope;
			}
			return this.#issue(c.client_id, scope, row.family);
		}
		throw new OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
	}

	#issue(clientId: string, scope: string, family: string) {
		const t = this.#now();
		const at = "lma_at_" + rand(32);
		const rt = "lma_rt_" + rand(32);
		const ins = this.#store.db.prepare("INSERT INTO oauth_token(token_hash, kind, client_id, scope, family, expires_at, created_at) VALUES (?,?,?,?,?,?,?)");
		ins.run(sha(at), "access", clientId, scope, family, t + ACCESS_TTL, t);
		ins.run(sha(rt), "refresh", clientId, scope, family, t + REFRESH_TTL, t);
		this.#store.db.prepare("UPDATE oauth_client SET last_used_at = ? WHERE client_id = ?").run(t, clientId);
		return { access_token: at, token_type: "Bearer", expires_in: ACCESS_TTL / 1000, refresh_token: rt, scope };
	}

	/** Bearer access token → 資訊；無效回 null */
	verify(token: string): TokenInfo | null {
		if (!token.startsWith("lma_at_")) return null;
		const row = this.#store.db.prepare("SELECT client_id, scope, expires_at FROM oauth_token WHERE token_hash = ? AND kind = 'access'").get(sha(token)) as
			| { client_id: string; scope: string; expires_at: number }
			| undefined;
		if (!row || row.expires_at < this.#now()) return null;
		return { client_id: row.client_id, scope: row.scope.split(" "), expires_at: row.expires_at };
	}

	revokeToken(form: URLSearchParams, authz: string | undefined): void {
		let c: ClientRow;
		try {
			c = this.#authClient(form, authz);
		} catch {
			return; // RFC 7009：未知一律 200
		}
		const tok = form.get("token") ?? "";
		const row = this.#store.db.prepare("SELECT family FROM oauth_token WHERE token_hash = ? AND client_id = ?").get(sha(tok), c.client_id) as { family: string } | undefined;
		if (row) this.#store.db.prepare("DELETE FROM oauth_token WHERE family = ?").run(row.family);
	}

	// ---------- App 管理 ----------
	listClients() {
		const rows = this.#store.db
			.prepare(
				`SELECT c.client_id, c.name, c.created_at, c.last_used_at, c.redirect_uris,
				        (SELECT GROUP_CONCAT(DISTINCT scope) FROM oauth_token t WHERE t.client_id = c.client_id AND t.kind='refresh' AND t.used=0 AND t.expires_at > ?) AS scope
				 FROM oauth_client c ORDER BY COALESCE(c.last_used_at, c.created_at) DESC`,
			)
			.all(this.#now()) as { client_id: string; name: string; created_at: number; last_used_at: number | null; redirect_uris: string; scope: string | null }[];
		return rows.map((r) => ({
			client_id: r.client_id,
			name: r.name,
			created_at: r.created_at,
			last_used_at: r.last_used_at,
			redirect_host: (() => {
				try {
					return new URL((JSON.parse(r.redirect_uris) as string[])[0]!).host;
				} catch {
					return null;
				}
			})(),
			active: !!r.scope,
			scope: r.scope,
		}));
	}

	revokeClient(clientId: string | "all"): number {
		const db = this.#store.db;
		if (clientId === "all") {
			db.exec("DELETE FROM oauth_token; DELETE FROM oauth_code; DELETE FROM oauth_client;");
			this.#audit?.log("ui", "oauth_revoked_all");
			return 1;
		}
		db.prepare("DELETE FROM oauth_token WHERE client_id = ?").run(clientId);
		db.prepare("DELETE FROM oauth_code WHERE client_id = ?").run(clientId);
		const r = db.prepare("DELETE FROM oauth_client WHERE client_id = ?").run(clientId);
		this.#audit?.log("ui", "oauth_client_revoked", { detail: { client_id: clientId } });
		return Number(r.changes);
	}

	#prune() {
		const t = this.#now();
		const db = this.#store.db;
		db.prepare("DELETE FROM oauth_token WHERE expires_at < ?").run(t);
		db.prepare("DELETE FROM oauth_code WHERE expires_at < ?").run(t);
		// 註冊後 1 天都沒拿到 token 的 client 清掉（DCR 會產生很多）
		db.prepare("DELETE FROM oauth_client WHERE last_used_at IS NULL AND created_at < ? AND client_id NOT IN (SELECT client_id FROM oauth_token)").run(t - 86_400_000);
	}
}

export interface AuthorizeParams {
	client_id: string;
	client_name: string;
	redirect_uri: string;
	state: string | null;
	code_challenge: string;
	resource: string | null;
	scope: string[];
}

function parseScope(s: string | null | undefined): string[] {
	const want = (s ?? "").split(/\s+/).filter(Boolean);
	const ok = want.filter((x) => (SCOPES as readonly string[]).includes(x));
	return ok.length ? ok : ["line.read", "line.send"];
}

function norm(u: string): string {
	return u.replace(/\/+$/, "");
}

export function resourceOk(resource: string, base: string): boolean {
	const r = norm(resource);
	return r === norm(base) || r === `${norm(base)}/mcp` || r === `${norm(base)}/sse`;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** 授權（同意）頁：純 HTML，無 JS */
export function consentPage(p: AuthorizeParams, nonce: string, error?: string): string {
	const host = (() => {
		try {
			return new URL(p.redirect_uri).host;
		} catch {
			return "?";
		}
	})();
	const wantsSend = p.scope.includes("line.send");
	return `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LINE MCP Companion — 授權連接器</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:32px auto;padding:0 16px;color:#222}h1{font-size:20px}.box{border:1px solid #ddd;border-radius:12px;padding:16px;margin:16px 0}
input[type=text]{font-size:22px;letter-spacing:4px;width:100%;padding:8px;box-sizing:border-box;text-transform:uppercase}button{font-size:16px;padding:10px 18px;border-radius:20px;border:1px solid #06c755;margin-right:8px}
.ok{background:#06c755;color:#fff}.err{color:#c00}.muted{color:#666;font-size:14px}</style></head><body>
<h1>授權「${esc(p.client_name)}」連接你的 LINE MCP Companion</h1>
<p class="muted">授權後會回到：<b>${esc(host)}</b>。只有你在 App 裡勾選的聊天看得到；送出訊息仍受 App 的白名單、確認佇列、上限與緊急停止限制。</p>
${error ? `<p class="err">${esc(error)}</p>` : ""}
<form method="post" action="/oauth/authorize" class="box">
<input type="hidden" name="nonce" value="${esc(nonce)}">
<label>配對碼（App → 設定 → 雲端連接器）<br><input type="text" name="pairing_code" autocomplete="one-time-code" maxlength="12" autofocus></label>
<p><label><input type="checkbox" name="allow_send"${wantsSend ? "" : " disabled"}> 也允許送出 / 核准（預設只讀）</label></p>
<button class="ok" type="submit" name="action" value="allow">授權</button><button type="submit" name="action" value="deny">拒絕</button>
</form>
<p class="muted">不認得這個要求？按「拒絕」，並到 App 撤銷所有連接器。</p>
</body></html>`;
}
