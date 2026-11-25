/**
 * App 內部控制 API（給 Kotlin UI 用，不是給 AI）：登入、會話與白名單、AI 設定、確認佇列、總控台、反詐、社群貼文草稿。
 * 只綁 127.0.0.1。Android 使用 HMAC 簽章；桌面可使用 Bearer 相容模式（timing-safe 比對）。
 * 請求本體上限 256KB；拒絕帶 Origin 的請求（瀏覽器網頁不能呼叫）。
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { OAuthServer } from "../mcp/oauth.ts";
import type { DigestStore } from "../storage/digests.ts";
import type { DigestPoster } from "../ai/digest-post.ts";
import { type LinkReader, extractUrls } from "../links/reader.ts";
import type { QuickTunnel } from "../mcp/tunnel.ts";
import type { GatewayToken } from "../mcp/gateway-token.ts";
import { connectorSettings, normalizePublicUrl } from "../mcp/gateway.ts";
import { timingSafeEqual, createHmac, createHash, createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Store } from "../storage/db.ts";
import type { Whitelist } from "../whitelist.ts";
import type { AiService } from "../ai/service.ts";
import type { ScamDetector } from "../scam/detector.ts";
import type { ScamWarner } from "../scam/warner.ts";
import { PRESETS } from "../ai/provider.ts";
import { PermissionDeniedError, type ChatAiConfig } from "../ai/policy.ts";
import { ChatNotAllowedError } from "../whitelist.ts";
import { moduleInfo } from "../style/registry.ts";
import { CATEGORY_TIPS } from "../scam/rules.ts";
import type { McpStats } from "../mcp/server.ts";
import { toCsv, SCAM_CSV_COLS, AI_CSV_COLS, type EventLog } from "../storage/event-log.ts";
import type { TrustFeature, TrustState } from "../ai/policy.ts";
import { Audit } from "../ai/audit.ts";
import { AuthFailureBudget, ControlReplayWindow, type AuthFailureReason } from "./security.ts";

export interface LoginState {
	phase: "logged_out" | "waiting_qr_scan" | "waiting_pin" | "online" | "error";
	qrUrl?: string;
	pin?: string;
	error?: string;
	profile?: { displayName: string; mid: string };
}

export interface ControlDeps {
	store: Store;
	whitelist: Whitelist;
	login: () => LoginState;
	startQrLogin: () => void;
	logout?: () => Promise<void>;
	info?: () => Record<string, unknown>;
	ai?: AiService | null;
	scam?: ScamDetector | null;
	warner?: ScamWarner | null;
	events?: EventLog | null;
	/** 設定 / 清除記憶體中的 API key（Kotlin 端負責加密保存） */
	setAiKey?: (key: string | null) => void;
	mcpStats?: () => McpStats | null;
	/** 產生新的 MCP token 並立即生效；回傳新 token（只回傳給 UI） */
	rotateMcpToken?: () => string;
	stickerImage?: (stickerId: string) => Promise<{ bytes: Uint8Array; mime: string }>;
	syncStatus?: () => Record<string, unknown> | null;
	digests?: DigestStore | null;
	poster?: DigestPoster | null;
	links?: LinkReader | null;
	/** 雲端連接器（OAuth 閘道 + 通道） */
	connector?: {
		oauth: OAuthServer;
		gatewayPort: number;
		tunnel: QuickTunnel | null;
		gatewayToken?: GatewayToken;
	} | null;
}

const SETTING_KEYS = new Set(["read_receipts", "sync_scope", "allow_key_registration", "scam_enabled", "scam_ai", "scam_scan_dm"]);
const MAX_BODY = 256 * 1024;

class HttpError extends Error {
	status: number;
	constructor(status: number, msg: string) {
		super(msg);
		this.status = status;
	}
}

/** 已預先讀取（並視需要解密）的請求本體：HMAC 驗證要先看到本體 */
const preread = new WeakMap<IncomingMessage, Buffer>();

async function readRaw(req: IncomingMessage): Promise<Buffer> {
	if (Number(req.headers["content-length"] ?? 0) > MAX_BODY) throw new HttpError(413, "payload too large");
	const chunks: Buffer[] = [];
	let n = 0;
	for await (const c of req) {
		n += (c as Buffer).length;
		if (n > MAX_BODY) throw new HttpError(413, "payload too large");
		chunks.push(c as Buffer);
	}
	return Buffer.concat(chunks);
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
	const buf = preread.get(req) ?? (await readRaw(req));
	if (!buf.length) return {};
	try {
		const v = JSON.parse(buf.toString("utf8"));
		if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
		return v as Record<string, unknown>;
	} catch {
		throw new HttpError(400, "invalid JSON");
	}
}

/** DNS rebinding 縱深防禦：Host 必須是 loopback（與 MCP 一致） */
function hostOk(req: IncomingMessage): boolean {
	const h = (req.headers.host ?? "").toLowerCase();
	return /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(h);
}

/**
 * 伺服器身分證明（防 loopback 埠被其他 App 搶佔）：UI 先用隨機 nonce 呼叫 GET /control/hello（不帶 token），
 * 伺服器回 x-lma-proof = HMAC-SHA256(controlToken, "hello:"+nonce)。只有持有 token 的正牌 Node 算得出來；
 * UI 驗證通過才送出 HMAC 簽章請求。之後所有回應綁 method、path、status 和完整 body。
 */
const NONCE_RE = /^[0-9a-f]{32,128}$/;
export function controlProof(token: string, msg: string): string {
	return createHmac("sha256", token).update(msg).digest("hex");
}

/** listen 失敗（例如 EADDRINUSE：埠被其他程式佔用）時 reject，讓呼叫端能處理 / 告警，而不是 uncaught crash */
export function listenLoopback(server: Server, port: number, host: string): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		const onErr = (e: Error) => {
			server.removeListener("listening", onOk);
			reject(e);
		};
		const onOk = () => {
			server.removeListener("error", onErr);
			resolve();
		};
		server.once("error", onErr);
		server.once("listening", onOk);
		server.listen(port, host);
	});
}

const sha256hex = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

/**
 * H-1 / N-05：Android UI 不再送出 Bearer token。每個請求帶
 *   x-lma-nonce: <128-bit hex>
 *   x-lma-auth:  v1 <unix-ms>.<HMAC(token, "req:"+nonce+":"+ts+":"+METHOD+":"+path?query+":"+sha256(rawBody))>
 * 本體若含秘密（例如 AI 金鑰）以 AES-256-GCM 加密（x-lma-enc: 1；金鑰 = HMAC(token, "body:"+nonce)，AAD = METHOD:path）。
 * 冒牌伺服器即使搶到埠，也只拿到一次性簽章與密文，拿不到 token 或金鑰。nonce 2 分鐘內不可重用，時間差 ±2 分鐘。
 */
function hmacAuth(req: IncomingMessage, token: string, raw: Buffer, nonce: string | null, replay: ControlReplayWindow): { ok: true } | { ok: false; reason: AuthFailureReason } {
	const h = req.headers["x-lma-auth"];
	if (typeof h !== "string" || !nonce || !NONCE_RE.test(nonce)) return { ok: false, reason: "unauthorized" };
	const m = /^v1 (\d{10,16})\.([0-9a-f]{64})$/.exec(h.trim());
	if (!m) return { ok: false, reason: "unauthorized" };
	const ts = Number(m[1]);
	if (!replay.validTimestamp(ts)) return { ok: false, reason: "expired" };
	const want = Buffer.from(controlProof(token, `req:${nonce}:${ts}:${req.method}:${req.url ?? ""}:${sha256hex(raw)}`));
	const got = Buffer.from(m[2]!);
	if (got.length !== want.length || !timingSafeEqual(got, want)) return { ok: false, reason: "unauthorized" };
	if (!replay.consume(nonce, ts)) return { ok: false, reason: "replay" };
	return { ok: true };
}

export function decryptControlBody(token: string, nonce: string, method: string, path: string, raw: Buffer): Buffer {
	const b = Buffer.from(raw.toString("utf8"), "base64");
	if (b.length < 12 + 16) throw new HttpError(400, "bad encrypted body");
	const key = createHmac("sha256", token).update(`body:${nonce}`).digest();
	const d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12), { authTagLength: 16 });
	d.setAAD(Buffer.from(`${method}:${path}`));
	d.setAuthTag(b.subarray(b.length - 16));
	try {
		return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
	} catch {
		throw new HttpError(400, "bad encrypted body");
	}
}

function tokenOk(req: IncomingMessage, token: string): boolean {
	const want = Buffer.from(`Bearer ${token}`);
	const got = Buffer.from(req.headers.authorization ?? "");
	return got.length === want.length && timingSafeEqual(got, want);
}

function need<T>(v: T | null | undefined, what: string): T {
	if (!v) throw new HttpError(503, `${what} not available`);
	return v;
}

function preview(m: { text: string | null; content_type: string; media_name?: string | null }): string {
	if (m.text) return m.text;
	if (m.content_type === "IMAGE") return "[圖片]";
	if (m.content_type === "STICKER") return "[貼圖]";
	if (m.content_type === "FILE") return `[檔案] ${m.media_name ?? ""}`;
	return `[${m.content_type}]`;
}

/** 取消針對某則訊息、尚未送出的反詐提醒（誤判時） */
export function cancelWarnings(ai: AiService, chatId: string, messageId: string, actor: "ui" | "mcp"): number {
	const rows = ai.outbox.store.db
		.prepare("SELECT id FROM outbox WHERE origin='scam_warn' AND chat_id=? AND reply_to=? AND status IN ('pending','approved')")
		.all(chatId, messageId) as { id: number }[];
	for (const r of rows) ai.outbox.reject(r.id, actor);
	return rows.length;
}

export async function startControlHttp(deps: ControlDeps, opts: { port?: number; token: string; /** Android：只接受 HMAC 簽章（UI 從不送 Bearer） */ hmacOnly?: boolean; authFailureRatePerMin?: number }): Promise<{ server: Server; url: string }> {
	if (!opts.token || opts.token.length < 16) throw new Error("control token is required (>= 16 chars)");
	const { store } = deps;
	const controlAudit = deps.ai?.audit ?? new Audit(store);
	const replay = new ControlReplayWindow();
	const authFailures = new AuthFailureBudget({
		perMinute: opts.authFailureRatePerMin,
		report: (summary) => controlAudit.logSecurity("system", "control_auth_failures", { ...summary }),
	});
	const responseProof = new WeakMap<ServerResponse, (code: number, bytes: Buffer) => void>();
	const sendBytes = (res: ServerResponse, code: number, body: string | Uint8Array, headers: Record<string, string> = {}) => {
		const bytes = Buffer.from(body);
		responseProof.get(res)?.(code, bytes);
		res.writeHead(code, headers).end(bytes);
	};
	const startOfDay = () => {
		const d = new Date();
		d.setHours(0, 0, 0, 0);
		return d.getTime();
	};

	const chatAiView = (cfg: ChatAiConfig) => ({
		...cfg,
		warn: deps.warner?.get(cfg.chat_id) ?? null,
		admins: deps.scam?.admins(cfg.chat_id) ?? [],
		trust: { ai: cfg.ai_trust, scam: deps.ai?.policy.trust(cfg.chat_id, "scam") ?? "review" },
		trust_log: deps.ai?.policy.trustLog(10, cfg.chat_id) ?? [],
		link_read: store.getSetting(`link_read:${cfg.chat_id}`) === "on",
		digest_share: store.getSetting(`digest_share:${cfg.chat_id}`) === "on",
		digest_target: store.getSetting(`digest_target:${cfg.chat_id}`) === "on",
	});
	const logFilter = (url: URL) => {
		const q = url.searchParams;
		const n = (k: string) => (q.get(k) ? Number(q.get(k)) : undefined);
		return { chatId: q.get("chat_id") || undefined, since: n("since"), until: n("until"), limit: n("limit") ?? 300 };
	};

	function dashboard() {
		const ai = deps.ai;
		const sod = startOfDay();
		return {
			login: deps.login(),
			sync: deps.syncStatus?.() ?? null,
			info: deps.info?.() ?? {},
			ai: ai
				? {
						driver: ai.driver,
						enabled: ai.policy.aiEnabled,
						kill_switch: ai.policy.killSwitch,
						has_key: ai.hasKey(),
						key_hint: ai.keyHint(),
						provider: ai.config().provider,
						model: ai.config().model,
						capabilities: ai.capabilities(),
						counters: ai.policy.counters(),
						pending: ai.outbox.list({ status: "pending", limit: 50 }).length,
						scheduled: ai.outbox.list({ status: "approved", limit: 50 }).length,
					}
				: null,
			chats: ai
				? ai.policy
						.overview()
						.filter((c) => c.allowed)
						.map((c) => ({ ...c, warn_enabled: deps.warner?.get(c.chat_id).enabled ?? false, scam_trust: ai.policy.trust(c.chat_id, "scam") }))
				: [],
			trust_log: ai?.policy.trustLog(20) ?? [],
			mcp_allow_promote: store.getSetting("mcp_allow_promote") === "on",
			mcp_allow_approve: store.getSetting("mcp_allow_approve") === "on",
			mcp: deps.mcpStats?.() ?? null,
			scam: deps.scam ? { enabled: deps.scam.enabled, ai: deps.scam.aiEnabled, today: deps.scam.counts(sod), recent: deps.scam.alerts({ limit: 5 }), warnings: deps.warner?.log(10) ?? [] } : null,
			audit: controlAudit.recent({ limit: 30, includeSecurity: true }),
		};
	}

	type Handler = (url: URL, req: IncomingMessage, res: ServerResponse) => Promise<unknown> | unknown;
	const routes: Record<string, Handler> = {
		// ---- 登入 / 會話 ----
		"GET /control/state": () => deps.login(),
		"GET /control/health": () => ({ ok: true }),
		"GET /control/security": () => ({ authentication: authFailures.snapshot(), recent: controlAudit.securityRecent(50) }),
		"POST /control/login/qr": () => {
			deps.startQrLogin();
			return deps.login();
		},
		"GET /control/info": () => deps.info?.() ?? {},
		"GET /control/chats": () =>
			store.listChats().map((c) => {
				const last = store.getMessages(c.id, { limit: 1 })[0];
				const ai = deps.ai?.policy.get(c.id);
				return { id: c.id, type: c.type, name: c.name, allowed: c.allowed === 1, last_message_at: c.last_message_at, preview: last ? preview(last) : "", member_count: c.member_count, ai_allowed: ai?.ai_allowed ?? false, ai_mode: ai?.mode ?? "off" };
			}),
		"GET /control/messages": (url) => {
			// UI 自己的檢視（使用者本人），不受 MCP 白名單限制；同樣不呼叫任何已讀 API
			const chatId = url.searchParams.get("chat_id") ?? "";
			// around=<message_id>：從日報跳回原訊息，回傳前後各 40 則
			const around = url.searchParams.get("around");
			const target = around ? store.getMessage(chatId, around) : undefined;
			const rows = target
				? [
						...store.getMessages(chatId, { after: target.sent_at - 1, limit: 500 }).filter((m) => m.sent_at >= target.sent_at).slice(-41),
						...store.getMessages(chatId, { before: target.sent_at, limit: 40 }),
					]
				: store.getMessages(chatId, { limit: Math.min(500, Number(url.searchParams.get("limit") ?? 100)) });
			return rows.reverse().map((r) => {
				const full = store.getMessage(chatId, r.id);
				let meta: Record<string, unknown> | null = null;
				try {
					meta = full?.meta_json ? (JSON.parse(full.meta_json) as Record<string, unknown>) : null;
				} catch {}
				return { ...r, reply_to: meta?.relatedMessageId ?? null, sticker: meta?.STKID ? { package_id: String(meta.STKPKGID), sticker_id: String(meta.STKID) } : null };
			});
		},
		"POST /control/chats/allow": async (_u, req) => {
			const b = await body(req);
			const ok = deps.whitelist.set(String(b.chat_id), b.allowed === true);
			if (ok && b.allowed === true) deps.scam?.rescanChat(String(b.chat_id));
			if (!ok) throw new HttpError(404, "chat not found");
			return { ok };
		},
		"POST /control/settings": async (_u, req) => {
			const b = await body(req);
			for (const [k, v] of Object.entries(b)) {
				if (!SETTING_KEYS.has(k)) throw new HttpError(400, `unknown setting ${k}`);
				store.setSetting(k, String(v));
			}
			return { ok: true };
		},
		"GET /control/dashboard": () => dashboard(),

		// ---- AI 設定 ----
		"GET /control/ai": () => {
			const ai = need(deps.ai, "AI");
			return { config: ai.config(), presets: PRESETS, driver: ai.driver, enabled: ai.policy.aiEnabled, kill_switch: ai.policy.killSwitch, daily_cap: ai.policy.dailyCap, persona: ai.persona, has_key: ai.hasKey(), key_hint: ai.keyHint(), capabilities: ai.capabilities(), styles: moduleInfo() };
		},
		"POST /control/ai": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const patch: Record<string, unknown> = {};
			for (const k of ["provider", "base_url", "model", "image_model", "max_tokens_field", "fallback", "deidentify"]) if (b[k] !== undefined) patch[k] = b[k];
			if (Object.keys(patch).length) ai.setConfig(patch as never);
			if (b.driver !== undefined) ai.setDriver(b.driver === "builtin" ? "builtin" : "connector");
			if (b.enabled !== undefined) {
				ai.policy.setAiEnabled(b.enabled === true);
				ai.audit.log("ui", b.enabled === true ? "ai_enabled" : "ai_disabled");
			}
			if (b.daily_cap !== undefined) ai.policy.setDailyCap(Number(b.daily_cap));
			if (b.persona !== undefined) ai.setPersona(String(b.persona));
			return routes["GET /control/ai"]!(_u, req, undefined as never);
		},
		"POST /control/ai/key": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const k = b.key == null || b.key === "" ? null : String(b.key).trim();
			if (k && (k.length < 8 || k.length > 512 || /\s/.test(k))) throw new HttpError(400, "invalid key format");
			need(deps.setAiKey, "key store")(k);
			ai.resetProvider();
			ai.audit.log("ui", k ? "ai_key_set" : "ai_key_cleared");
			return { has_key: ai.hasKey(), key_hint: ai.keyHint() };
		},
		"POST /control/ai/detect": async () => need(deps.ai, "AI").detect(),
		"POST /control/kill": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const moved = ai.outbox.setKill(b.on === true, "ui");
			return { kill_switch: ai.policy.killSwitch, moved_to_pending: moved };
		},

		// ---- 每會話 AI ----
		"GET /control/chat_ai": (url) => chatAiView(need(deps.ai, "AI").policy.get(url.searchParams.get("chat_id") ?? "")),
		"POST /control/chat_ai": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			const { chat_id: _c, ...patch } = b;
			const cfg = ai.policy.set(chatId, patch as never);
			ai.audit.log("ui", "chat_ai_updated", { chatId, detail: { mode: cfg.mode, ai_allowed: cfg.ai_allowed, confirm_send: cfg.confirm_send } });
			return chatAiView(cfg);
		},

		// ---- 確認佇列 / 送出 ----
		"GET /control/queue": (url) => {
			const ai = need(deps.ai, "AI");
			const status = (url.searchParams.get("status") ?? "pending") as never;
			const names = new Map(store.listChats().map((c) => [c.id, c.name]));
			return ai.outbox.list({ status, limit: 100 }).map((it) => {
				const target = it.reply_to ? store.getMessage(it.chat_id, it.reply_to) : undefined;
				return { ...it, image_path: undefined, has_image: !!it.image_path, chat_name: names.get(it.chat_id) ?? null, reply_preview: target ? preview(target).slice(0, 60) : null };
			});
		},
		"POST /control/queue/approve": async (_u, req) => {
			const b = await body(req);
			return need(deps.ai, "AI").outbox.approve(Number(b.id), b.text == null ? null : String(b.text));
		},
		"POST /control/queue/edit": async (_u, req) => {
			const b = await body(req);
			const st = b.sticker as { package_id?: unknown; sticker_id?: unknown } | null | undefined;
			return need(deps.ai, "AI").outbox.edit(
				Number(b.id),
				{
					text: b.text === undefined ? undefined : b.text == null ? null : String(b.text),
					sticker: st === undefined ? undefined : st === null ? null : { package_id: String(st.package_id ?? ""), sticker_id: String(st.sticker_id ?? "") },
				},
				"ui",
			);
		},

		// ---- 信任狀態（review ⇄ auto）----
		"POST /control/trust": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const st = ai.policy.setTrust(String(b.chat_id ?? ""), String(b.feature) as TrustFeature, String(b.state) as TrustState, "ui", b.reason == null ? "manual" : String(b.reason));
			return { chat_id: b.chat_id, feature: b.feature, state: st };
		},
		"POST /control/trust/demote_all": async () => ({ demoted: need(deps.ai, "AI").policy.demoteAll("ui", "manual_all") }),
		"GET /control/trust/log": (url) => need(deps.ai, "AI").policy.trustLog(Number(url.searchParams.get("limit") ?? 100), url.searchParams.get("chat_id") || undefined),
		"POST /control/mcp/permissions": async (_u, req) => {
			const b = await body(req);
			for (const k of ["mcp_allow_promote", "mcp_allow_approve"] as const) {
				if (b[k] !== undefined) {
					store.setSetting(k, b[k] === true ? "on" : "off");
					deps.ai?.audit.log("ui", `${k}_${b[k] === true ? "on" : "off"}`);
				}
			}
			return { mcp_allow_promote: store.getSetting("mcp_allow_promote") === "on", mcp_allow_approve: store.getSetting("mcp_allow_approve") === "on" };
		},

		// ---- 紀錄（加密保存；可篩選 / 匯出 CSV / 清除）----
		"GET /control/logs/scam": (url, _r, res) => {
			const ev = need(deps.events, "logs");
			const rows = ev.scamList({ ...logFilter(url), action: url.searchParams.get("action") || undefined, category: url.searchParams.get("category") || undefined });
			if (url.searchParams.get("format") === "csv") {
				deps.ai?.audit.log("ui", "scam_log_exported", { detail: { rows: rows.length } });
				sendBytes(res, 200, toCsv(rows as never, SCAM_CSV_COLS), { "content-type": "text/csv; charset=utf-8", "cache-control": "no-store" });
				return undefined;
			}
			return rows;
		},
		"GET /control/logs/ai": (url, _r, res) => {
			const ev = need(deps.events, "logs");
			const rows = ev.aiList({ ...logFilter(url), event: url.searchParams.get("event") || undefined });
			if (url.searchParams.get("format") === "csv") {
				deps.ai?.audit.log("ui", "ai_log_exported", { detail: { rows: rows.length } });
				sendBytes(res, 200, toCsv(rows as never, AI_CSV_COLS), { "content-type": "text/csv; charset=utf-8", "cache-control": "no-store" });
				return undefined;
			}
			return rows;
		},
		"GET /control/logs/settings": () => ({ retention_days: need(deps.events, "logs").retentionDays }),
		"POST /control/logs/settings": async (_u, req) => {
			const b = await body(req);
			return { retention_days: need(deps.events, "logs").setRetentionDays(Number(b.retention_days)) };
		},
		"POST /control/logs/clear": async (_u, req) => {
			const b = await body(req);
			const kind = b.kind === "scam" || b.kind === "ai" ? b.kind : "all";
			const n = need(deps.events, "logs").clear(kind);
			deps.ai?.audit.log("ui", "logs_cleared", { detail: { kind, rows: n } });
			return { cleared: n };
		},

		"POST /control/queue/reject": async (_u, req) => {
			const b = await body(req);
			return need(deps.ai, "AI").outbox.reject(Number(b.id), "ui");
		},
		"GET /control/outbox_image": (url, _r, res) => {
			const it = need(deps.ai, "AI").outbox.get(Number(url.searchParams.get("id")));
			if (!it?.image_path) throw new HttpError(404, "no image");
			sendBytes(res, 200, readFileSync(it.image_path), { "content-type": "image/png", "cache-control": "no-store" });
			return undefined;
		},
		"POST /control/suggest": async (_u, req) => {
			const b = await body(req);
			return need(deps.ai, "AI").suggest(String(b.chat_id ?? ""), "ui", b.instruction == null ? null : String(b.instruction).slice(0, 500), b.reply_to == null ? null : String(b.reply_to));
		},
		/** 使用者在 App 裡按「送出」（例如長按訊息→回覆這則）：放進佇列並直接核准，仍受白名單 / kill switch / 每日上限限制 */
		"POST /control/send": async (_u, req) => {
			const ai = need(deps.ai, "AI");
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			const st = b.sticker as { package_id?: unknown; sticker_id?: unknown } | undefined;
			const replyTo = b.reply_to == null ? null : String(b.reply_to);
			const r = st
				? ai.outbox.enqueue({ chatId, kind: "sticker", sticker: { package_id: String(st.package_id), sticker_id: String(st.sticker_id) }, text: null, origin: "ui", replyTo, forcePending: true }, "ui")
				: ai.outbox.enqueue({ chatId, kind: "text", text: String(b.text ?? ""), origin: "ui", replyTo, forcePending: true }, "ui");
			return ai.outbox.approve(r.item.id, null);
		},
		"POST /control/image": async (_u, req) => {
			const b = await body(req);
			return need(deps.ai, "AI").imageToQueue(String(b.chat_id ?? ""), String(b.prompt ?? "").slice(0, 1000), b.caption == null ? null : String(b.caption).slice(0, 500), "ui", "ui");
		},
		"GET /control/audit": (url) => controlAudit.recent({ limit: Math.min(500, Number(url.searchParams.get("limit") ?? 100)), includeSecurity: true }),

		// ---- 貼圖 ----
		"GET /control/stickers": () => need(deps.ai, "AI").stickers.list({ limit: 200 }),
		"POST /control/stickers/label": async (_u, req) => {
			const b = await body(req);
			need(deps.ai, "AI").stickers.setLabel(String(b.sticker_id ?? ""), b.label == null ? null : String(b.label));
			return { ok: true };
		},
		"GET /control/sticker_img": async (url, _r, res) => {
			const id = url.searchParams.get("id") ?? "";
			if (!/^\d{1,12}$/.test(id)) throw new HttpError(400, "bad id");
			const img = await need(deps.stickerImage, "sticker images")(id);
			sendBytes(res, 200, img.bytes, { "content-type": img.mime, "cache-control": "no-store" });
			return undefined;
		},

		// ---- MCP ----
		"GET /control/mcp": () => deps.mcpStats?.() ?? null,
		"POST /control/mcp/rotate": () => {
			const t = need(deps.rotateMcpToken, "token rotation")();
			deps.ai?.audit.log("ui", "mcp_token_rotated");
			return { token: t };
		},

		// ---- 日報 ----
		"GET /control/digests": (url) => {
			const ds = need(deps.digests, "digests");
			const date = url.searchParams.get("date");
			let since: number | undefined;
			let until: number | undefined;
			if (date) {
				if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new HttpError(400, "date must be YYYY-MM-DD");
				since = Date.parse(`${date}T00:00:00+08:00`);
				until = since + 86_400_000;
			}
			const chatIds = (url.searchParams.get("chat_ids") ?? "").split(",").filter(Boolean);
			const list = ds.list({ chatIds, since, until, limit: 50 });
			const names: Record<string, string> = {};
			for (const d of list) for (const c of d.chats) names[c] ??= store.getChat(c)?.name ?? c;
			return { digests: list, chat_names: names, can_generate: !!deps.ai && deps.ai.driver === "builtin" && deps.ai.hasKey() };
		},
		"POST /control/digests/delete": async (_u, req) => {
			const b = await body(req);
			const ok = need(deps.digests, "digests").delete(Number(b.id));
			deps.ai?.audit.log("ui", "digest_deleted", { detail: { id: Number(b.id) } });
			return { ok };
		},
		"POST /control/digests/generate": async (_u, req) => {
			const b = await body(req);
			const ai = need(deps.ai, "AI");
			const date = String(b.date ?? "");
			if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new HttpError(400, "date must be YYYY-MM-DD");
			const start = Date.parse(`${date}T00:00:00+08:00`);
			try {
				return await ai.generateDigest(String(b.chat_id ?? ""), start, start + 86_400_000, "ui");
			} catch (e) {
				throw new HttpError(e instanceof PermissionDeniedError ? 403 : 400, (e as Error).message);
			}
		},

		"POST /control/digests/post": async (_u, req) => {
			const b = await body(req);
			const p = need(deps.poster, "digest posting");
			const ids = (Array.isArray(b.ids) ? b.ids : [b.id]).map(Number).filter((n) => Number.isFinite(n));
			try {
				const r = p.post(ids, String(b.target_chat ?? ""), "ui");
				return { outbox_id: r.item.id, status: r.item.status, route: r.route, text: r.text };
			} catch (e) {
				throw new HttpError(e instanceof PermissionDeniedError ? 403 : 400, (e as Error).message);
			}
		},
		"GET /control/digests/schedules": () => {
			const p = need(deps.poster, "digest posting");
			return { schedules: p.schedules().map((s) => ({ ...s, target_name: store.getChat(s.target_chat)?.name ?? s.target_chat })) };
		},
		"POST /control/digests/schedules": async (_u, req) => {
			const b = await body(req);
			const p = need(deps.poster, "digest posting");
			if (b.delete) return { ok: p.deleteSchedule(Number(b.id), "ui") };
			try {
				return p.saveSchedule(
					{ id: b.id ? Number(b.id) : undefined, target_chat: String(b.target_chat ?? ""), source_chats: Array.isArray(b.source_chats) ? b.source_chats.map(String) : [], time_hhmm: String(b.time_hhmm ?? ""), enabled: b.enabled !== false, generate: !!b.generate },
					"ui",
				);
			} catch (e) {
				throw new HttpError(400, (e as Error).message);
			}
		},

		// ---- M-3：日報跨聊天分享（來源允許分享 / 目標允許接收），預設都關 ----
		"POST /control/digests/share": async (_u, req) => {
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			if (!store.getChat(chatId)) throw new HttpError(404, "chat not found");
			if (b.share !== undefined) store.setSetting(`digest_share:${chatId}`, b.share ? "on" : "off");
			if (b.target !== undefined) store.setSetting(`digest_target:${chatId}`, b.target ? "on" : "off");
			deps.ai?.audit.log("ui", "digest_share_changed", { chatId, detail: { share: b.share, target: b.target } });
			return { ok: true, share: store.getSetting(`digest_share:${chatId}`) === "on", target: store.getSetting(`digest_target:${chatId}`) === "on" };
		},

		// ---- 讀取連結 ----
		"POST /control/links/toggle": async (_u, req) => {
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			if (!store.getChat(chatId)) throw new HttpError(404, "chat not found");
			store.setSetting(`link_read:${chatId}`, b.on ? "on" : "off");
			deps.ai?.audit.log("ui", "link_read_toggled", { chatId, detail: { on: !!b.on } });
			return { ok: true, on: !!b.on };
		},
		"POST /control/links/read": async (_u, req) => {
			const b = await body(req);
			const reader = need(deps.links, "link reading");
			const chatId = String(b.chat_id ?? "");
			const m = store.getMessage(chatId, String(b.message_id ?? ""));
			if (!m) throw new HttpError(404, "message not found");
			if (m.hidden) throw new HttpError(400, "message_hidden");
			if (store.getSetting(`link_read:${chatId}`) !== "on") return { results: [], blocked: "link_reading_off" };
			const results = [];
			for (const u of extractUrls(m.text).slice(0, 3)) results.push(await reader.read(u));
			deps.ai?.audit.log("ui", "read_link", { chatId, detail: { n: results.length, blocked: results.filter((r) => !r.ok).map((r) => r.blocked) } });
			return { results };
		},

		// ---- 雲端連接器 ----
		"GET /control/connector": () => {
			const c = need(deps.connector, "connector");
			const st = connectorSettings(deps.store);
			return {
				...st,
				gateway: `http://127.0.0.1:${c.gatewayPort}`,
				mcp_url: st.public_url ? `${st.public_url}/mcp` : null,
				sse_url: st.public_url ? `${st.public_url}/sse` : null,
				pairing: st.enabled ? c.oauth.pairingCode() : null,
				clients: c.oauth.listClients(),
				static_token: c.gatewayToken?.status() ?? null,
				tunnel: c.tunnel?.status() ?? null,
			};
		},
		"POST /control/connector": async (_u, req) => {
			const b = await body(req);
			need(deps.connector, "connector");
			if (b.enabled !== undefined) {
				deps.store.setSetting("connector_enabled", b.enabled ? "on" : "off");
				deps.ai?.audit.log("ui", b.enabled ? "connector_enabled" : "connector_disabled");
				if (!b.enabled) deps.connector?.tunnel?.stop();
			}
			if (b.public_url !== undefined) {
				if (b.public_url === null || b.public_url === "") deps.store.setSetting("connector_public_url", "");
				else {
					try {
						deps.store.setSetting("connector_public_url", normalizePublicUrl(String(b.public_url)));
					} catch (e) {
						throw new HttpError(400, (e as Error).message);
					}
				}
			}
			if (b.allow_static !== undefined) {
				deps.store.setSetting("connector_allow_static", b.allow_static ? "on" : "off");
				deps.ai?.audit.log("ui", b.allow_static ? "connector_static_enabled" : "connector_static_disabled");
			}
			return connectorSettings(deps.store);
		},
		// H-2：連接器專用 token（建立 / 輪替會回明文一次；送出權限 UI 端要生物辨識）
		"POST /control/connector/static": async (_u, req) => {
			const b = await body(req);
			const g = need(need(deps.connector, "connector").gatewayToken, "gateway token");
			if (b.action === "rotate") return g.rotate("ui");
			if (b.action === "revoke") {
				g.revoke("ui");
				return g.status();
			}
			if (b.action === "send") {
				try {
					g.setSend(!!b.on, "ui");
				} catch (e) {
					throw new HttpError(409, (e as Error).message);
				}
				return g.status();
			}
			throw new HttpError(400, "action must be rotate | revoke | send");
		},
		"POST /control/connector/pairing": () => need(deps.connector, "connector").oauth.pairingCode(true),
		"POST /control/connector/revoke": async (_u, req) => {
			const b = await body(req);
			const id = b.client_id === "all" ? "all" : String(b.client_id ?? "");
			if (!id) throw new HttpError(400, "client_id required");
			return { revoked: need(deps.connector, "connector").oauth.revokeClient(id) };
		},
		"POST /control/connector/tunnel": async (_u, req) => {
			const b = await body(req);
			const c = need(deps.connector, "connector");
			const t = need(c.tunnel, "tunnel");
			if (b.action === "stop") {
				t.stop();
				return t.status();
			}
			if (!connectorSettings(deps.store).enabled) throw new HttpError(409, "enable the connector gateway first");
			const st = await t.start(c.gatewayPort);
			deps.ai?.audit.log("ui", "connector_tunnel", { ok: st.state === "up", detail: { state: st.state, error: st.error } });
			return st;
		},

		// ---- 反詐 ----
		"GET /control/scam/alerts": (url) =>
			need(deps.scam, "anti-scam").alerts({ chatId: url.searchParams.get("chat_id") ?? undefined, status: url.searchParams.get("status") ?? undefined, limit: Number(url.searchParams.get("limit") ?? 100) }),
		"POST /control/scam/alert_status": async (_u, req) => {
			const b = await body(req);
			const s = b.status === "dismissed" ? "dismissed" : b.status === "new" ? "new" : "seen";
			return { ok: need(deps.scam, "anti-scam").setStatus(Number(b.id), s) };
		},
		"POST /control/scam/false_positive": async (_u, req) => {
			const b = await body(req);
			const r = need(deps.scam, "anti-scam").markFalsePositive(Number(b.id), b.trust_member !== false);
			const cancelled = deps.ai ? cancelWarnings(deps.ai, r.chat_id, r.message_id, "ui") : 0;
			deps.events?.setScamAction({ alertId: Number(b.id) }, "false_positive", r.trusted ? "member trusted" : null);
			deps.ai?.audit.log("ui", "scam_false_positive", { chatId: r.chat_id, detail: { alert: Number(b.id), trusted: r.trusted, cancelled } });
			return { ...r, cancelled };
		},
		"POST /control/scam/compose": async (_u, req) => {
			const b = await body(req);
			return need(deps.warner, "anti-scam").compose(String(b.chat_id ?? ""), String(b.message_id ?? ""), b.text == null ? null : String(b.text), "ui");
		},
		"GET /control/scam/samples": (url) => need(deps.scam, "anti-scam").samples({ label: (url.searchParams.get("label") as "SCAM" | "OK" | null) ?? undefined, limit: 500 }),
		"POST /control/scam/samples": async (_u, req) => {
			const sc = need(deps.scam, "anti-scam");
			const b = await body(req);
			if (b.remove != null) return { ok: sc.removeSample(Number(b.remove)) };
			const text = String(b.text ?? "").trim().slice(0, 500);
			if (text.length < 4) throw new HttpError(400, "text too short");
			return sc.addSample({ label: b.label === "OK" ? "OK" : "SCAM", category: String(b.category ?? "其他").slice(0, 20), text }, "user");
		},
		"GET /control/scam/warn": (url) => {
			const w = need(deps.warner, "anti-scam");
			const chatId = url.searchParams.get("chat_id") ?? "";
			return { config: w.get(chatId), admins: deps.scam!.admins(chatId), preview: w.preview(chatId), global_template: w.template(), categories: CATEGORY_TIPS };
		},
		"POST /control/scam/warn": async (url, req) => {
			const w = need(deps.warner, "anti-scam");
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			const { chat_id: _c, ...patch } = b;
			w.set(chatId, patch as never);
			return routes["GET /control/scam/warn"]!(new URL(`http://x/?chat_id=${encodeURIComponent(chatId)}`), req, undefined as never);
		},
		"POST /control/scam/admin": async (_u, req) => {
			const sc = need(deps.scam, "anti-scam");
			const b = await body(req);
			const chatId = String(b.chat_id ?? "");
			if (store.getChat(chatId)?.allowed !== 1) throw new ChatNotAllowedError();
			sc.setAdmin(chatId, String(b.mid ?? ""), { name: b.name == null ? null : String(b.name), mention: b.mention !== false, remove: b.remove === true });
			return sc.admins(chatId);
		},
		"GET /control/scam/members": (url) => {
			// 群組成員（從已同步訊息推得），給「選管理員」用
			const chatId = url.searchParams.get("chat_id") ?? "";
			return store.db
				.prepare("SELECT m.sender_mid AS mid, COALESCE(p.display_name, m.sender_mid) AS name, COUNT(*) AS n FROM message m LEFT JOIN participant p ON p.mid=m.sender_mid WHERE m.chat_id=? AND m.from_self=0 AND m.sender_mid IS NOT NULL GROUP BY m.sender_mid ORDER BY n DESC LIMIT 100")
				.all(chatId);
		},
		"POST /control/scam/template": async (_u, req) => {
			const b = await body(req);
			return { template: need(deps.warner, "anti-scam").setTemplate(b.template == null ? null : String(b.template)) };
		},

		// ---- 社群貼文草稿 ----
		"GET /control/social/drafts": () => need(deps.ai, "AI").socialDrafts(30),
		"POST /control/social/draft": async (_u, req) => {
			const b = await body(req);
			const mode = b.mode === "B" ? "B" : b.mode === "C" ? "C" : "A";
			return need(deps.ai, "AI").draftSocialPost({ chatId: String(b.chat_id ?? ""), platform: String(b.platform ?? "facebook") as never, mode, note: b.note == null ? null : String(b.note).slice(0, 500), limit: b.limit == null ? undefined : Number(b.limit) }, "ui");
		},
		"GET /control/social/voice": () => need(deps.ai, "AI").voice(),
		"POST /control/social/voice": async (_u, req) => need(deps.ai, "AI").setVoice((await body(req)) as never),
		"GET /control/styles": () => moduleInfo(),
	};

	const server = createServer(async (req, res) => {
		const send = (code: number, v: unknown) => {
			if (res.headersSent) return;
			const json = JSON.stringify(v ?? null);
			sendBytes(res, code, json, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
		};
		const reject = (reason: AuthFailureReason, status: number, error: string) => {
			const allowed = authFailures.reject(reason);
			if (!allowed) res.setHeader("retry-after", "60");
			return send(allowed ? status : 429, { error: allowed ? error : "auth_rate_limited" });
		};
		if (req.headers.origin || !hostOk(req)) return reject("forbidden", 403, "forbidden");
		const nonce = typeof req.headers["x-lma-nonce"] === "string" ? req.headers["x-lma-nonce"].toLowerCase() : null;
		if (req.method === "GET" && (req.url ?? "").split("?")[0] === "/control/hello") {
			if (!nonce || !NONCE_RE.test(nonce)) return reject("invalid_request", 400, "bad nonce");
			res.setHeader("x-lma-proof", controlProof(opts.token, `hello:${nonce}`));
			return send(200, { ok: true });
		}
		// Missing credentials are rejected without collecting a request body. Valid Bearer remains desktop-only compatibility.
		const hasHmac = typeof req.headers["x-lma-auth"] === "string" && !!nonce && NONCE_RE.test(nonce);
		const viaBearer = !opts.hmacOnly && tokenOk(req, opts.token);
		if (!hasHmac && !viaBearer) return reject("unauthorized", 401, "unauthorized");
		let raw: Buffer;
		try {
			raw = await readRaw(req);
		} catch (e) {
			return reject("invalid_request", e instanceof HttpError ? e.status : 400, "invalid request body");
		}
		const auth = hmacAuth(req, opts.token, raw, nonce, replay);
		const viaHmac = auth.ok;
		if (!viaHmac && !viaBearer) return reject(auth.reason, 401, "unauthorized");
		// Every response body is bound, including CSV and images. There is no unsigned-body fallback.
		if (nonce && NONCE_RE.test(nonce)) {
			const n = nonce;
			const base = `resp:${n}:${req.method}:${req.url ?? ""}`;
			responseProof.set(res, (code, bytes) => {
				res.setHeader("x-lma-proof", controlProof(opts.token, `${base}:${code}:${sha256hex(bytes)}`));
				res.setHeader("x-lma-proof-body", "1");
			});
		}
		try {
			if (req.headers["x-lma-enc"] === "1") {
				if (!viaHmac || !nonce) throw new HttpError(400, "encrypted body needs HMAC auth");
				raw = decryptControlBody(opts.token, nonce, req.method ?? "", (req.url ?? "").split("?")[0]!, raw);
			}
			preread.set(req, raw);
			const url = new URL(req.url ?? "/", "http://x");
			const h = routes[`${req.method} ${url.pathname}`];
			if (!h) return send(404, { error: "not found" });
			const out = await h(url, req, res);
			if (!res.headersSent) send(200, out);
		} catch (e) {
			if (e instanceof HttpError) return send(e.status, { error: e.message });
			if (e instanceof ChatNotAllowedError) return send(403, { error: "chat_not_allowed", message: e.message });
			if (e instanceof PermissionDeniedError) return send(409, { error: e.reason, message: e.message });
			return send(500, { error: (e as Error).message });
		}
	});
	server.maxConnections = 64;
	server.headersTimeout = 10_000;
	server.requestTimeout = 120_000;
	await listenLoopback(server, opts.port ?? 47824, "127.0.0.1");
	const authFlush = setInterval(() => authFailures.flush(), 60_000);
	authFlush.unref();
	server.once("close", () => clearInterval(authFlush));
	const a = server.address();
	return { server, url: `http://127.0.0.1:${typeof a === "object" && a ? a.port : opts.port}/control` };
}
