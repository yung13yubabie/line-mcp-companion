/**
 * 本機 MCP Server（Streamable HTTP，stateless，JSON 回應）。
 * - 預設只綁 127.0.0.1；不設 CORS（瀏覽器網頁無法呼叫）。
 * - 可選 Bearer token（Android 上建議一律開，因為同機其他 App 也能連 loopback）。
 */
import { createServer, type Server, type IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { callTool, BASIC_TOOLS, SEND_TOOLS, SCAM_TOOLS, type ToolContext } from "./tools.ts";
import { PermissionDeniedError } from "../ai/policy.ts";
import type { Audit } from "../ai/audit.ts";
import { ChatNotAllowedError } from "../whitelist.ts";

const timeArg = z.union([z.number(), z.string()]).optional().describe("epoch ms 或 ISO 8601");

const TOOL_DEFS: Record<string, { description: string; schema: Record<string, z.ZodType> }> = {
	list_allowed_chats: { description: "列出使用者勾選「允許 AI / MCP 存取」的會話。", schema: {} },
	get_messages: {
		description: "讀取指定會話訊息（新到舊分頁）。用回傳的 next_before 取下一頁。不會標已讀。",
		schema: { chat_id: z.string(), limit: z.number().int().min(1).max(500).optional(), before: timeArg, after: timeArg },
	},
	search_messages: {
		description: "全文搜尋允許會話中的訊息（中文可用；3 字以上走 FTS5 trigram）。",
		schema: { query: z.string().min(1), chat_id: z.string().optional(), limit: z.number().int().min(1).max(200).optional() },
	},
	get_attachment: { description: "取得一則訊息的附件資訊與本機快取路徑。", schema: { chat_id: z.string(), message_id: z.string() } },
	download_media: {
		description: "下載訊息中的圖片/影片/檔案到 App 私有快取；inline=true 時同時回傳 base64（有大小上限）。",
		schema: { chat_id: z.string(), message_id: z.string(), inline: z.boolean().optional() },
	},
	get_unread_summary: { description: "允許會話的未讀摘要（本機計算，不呼叫 LINE 已讀 API）。", schema: { per_chat: z.number().int().min(0).max(50).optional() } },
	get_sync_status: { description: "同步狀態、筆數、已讀回條是否封鎖。", schema: {} },
	trigger_sync: { description: "手動觸發一次增量同步；full=true 先做完整同步。", schema: { full: z.boolean().optional() } },
	send_message: {
		description:
			"以使用者身分在允許的會話送出文字或貼圖（可引用回覆 reply_to）。需要使用者在 App 開啟「AI 代聊」且該會話同時在 MCP 與代聊白名單。預設會先放進確認佇列等使用者核准；回傳 status=pending 代表尚未送出。受每日 / 每小時上限、間隔、活躍時段與總開關限制。",
		schema: {
			chat_id: z.string(),
			text: z.string().max(2000).optional(),
			reply_to: z.string().max(64).optional().describe("要引用回覆的 message_id"),
			sticker: z.object({ package_id: z.string(), sticker_id: z.string() }).optional().describe("只能用 list_stickers 列出的貼圖"),
		},
	},
	generate_and_send_image: {
		description: "用 App 內設定的圖片模型生成圖片並送到允許的會話（需該會話開啟「允許生成圖片」）。預設進確認佇列。",
		schema: { chat_id: z.string(), prompt: z.string().min(1).max(1000), caption: z.string().max(500).optional() },
	},
	get_ai_suggestion: {
		description: "用 App 內建 AI 產生一則建議回覆（不送出）。可指定 reply_to 針對某則訊息。需要 App 內已設定 API key。",
		schema: { chat_id: z.string(), reply_to: z.string().max(64).optional(), instruction: z.string().max(500).optional() },
	},
	get_outbox_item: { description: "查詢 send_message / generate_and_send_image 排入項目的狀態（pending / approved / sent / rejected…）。", schema: { id: z.number().int() } },
	list_stickers: { description: "列出使用者自己用過、可以送出的貼圖。", schema: {} },
	scan_scam_alerts: {
		description: "取得允許會話中本機偵測到的疑似詐騙 / 換群警示（適合排程輪詢：用回傳的 next_since 當下次的 since）。不會標已讀。",
		schema: { since: timeArg, chat_id: z.string().optional(), min_level: z.enum(["suspicious", "high"]).optional(), limit: z.number().int().min(1).max(200).optional() },
	},
	list_scam_samples: { description: "列出詐騙判斷範例（SCAM / OK）。", schema: { label: z.enum(["SCAM", "OK"]).optional(), category: z.string().max(20).optional(), limit: z.number().int().min(1).max(500).optional() } },
	add_scam_sample: { description: "新增一則詐騙範例（只能新增 SCAM 類，最多 500 字）。", schema: { text: z.string().min(6).max(500), category: z.string().max(20).optional() } },
};

export function buildMcpServer(ctx: ToolContext, hooks: { client?: string; onCall?: (name: string, ok: boolean, ms: number, code?: string) => void } = {}): McpServer {
	const server = new McpServer({ name: "line-mcp-app", version: "0.2.0" });
	const names: string[] = [...BASIC_TOOLS, ...(ctx.ai ? SEND_TOOLS : []), ...(ctx.scam ? SCAM_TOOLS : [])];
	for (const name of names) {
		const def = TOOL_DEFS[name]!;
		server.registerTool(name, { description: def.description, inputSchema: def.schema }, async (args: Record<string, unknown>) => {
			const t0 = Date.now();
			try {
				const result = await callTool(ctx, name, args, hooks.client);
				hooks.onCall?.(name, true, Date.now() - t0);
				return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
			} catch (e) {
				const code = e instanceof ChatNotAllowedError ? e.code : e instanceof PermissionDeniedError ? e.reason : "error";
				hooks.onCall?.(name, false, Date.now() - t0, code);
				return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code, message: (e as Error).message }) }] };
			}
		});
	}
	return server;
}

export interface HttpOptions {
	host?: string;
	port?: number;
	/** 固定 token（測試用）；Android 上用 getToken 以便執行中輪換 */
	token?: string;
	getToken?: () => string | undefined;
	audit?: Audit | null;
	/** 每分鐘請求上限（全域 token bucket） */
	ratePerMin?: number;
	/** 送訊息類工具每分鐘上限 */
	sendRatePerMin?: number;
	maxBodyBytes?: number;
}

export interface McpStats {
	started_at: number;
	requests: number;
	rejected: { unauthorized: number; rate_limited: number; too_large: number; forbidden: number };
	clients: { name: string; last_seen: number; calls: number }[];
	recent: { ts: number; client: string; tool: string; ok: boolean; ms: number; code?: string }[];
}

export class TokenBucket {
	#cap: number;
	#tokens: number;
	#perMs: number;
	#last: number;
	#now: () => number;
	constructor(perMin: number, now: () => number = Date.now) {
		this.#cap = Math.max(1, perMin);
		this.#tokens = this.#cap;
		this.#perMs = this.#cap / 60_000;
		this.#now = now;
		this.#last = now();
	}
	take(n = 1): boolean {
		const t = this.#now();
		this.#tokens = Math.min(this.#cap, this.#tokens + (t - this.#last) * this.#perMs);
		this.#last = t;
		if (this.#tokens < n) return false;
		this.#tokens -= n;
		return true;
	}
}

function authorized(req: IncomingMessage, token?: string): boolean {
	if (!token) return false;
	const h = req.headers.authorization ?? "";
	const want = Buffer.from(`Bearer ${token}`);
	const got = Buffer.from(h);
	return got.length === want.length && timingSafeEqual(got, want);
}

/** DNS rebinding 防護：Host 必須是 loopback */
function hostOk(req: IncomingMessage): boolean {
	const h = (req.headers.host ?? "").toLowerCase();
	return /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(h);
}

async function readBody(req: IncomingMessage, max: number): Promise<unknown> {
	const len = Number(req.headers["content-length"] ?? 0);
	if (len > max) throw Object.assign(new Error("payload too large"), { status: 413 });
	const chunks: Buffer[] = [];
	let n = 0;
	for await (const c of req) {
		n += (c as Buffer).length;
		if (n > max) throw Object.assign(new Error("payload too large"), { status: 413 });
		chunks.push(c as Buffer);
	}
	try {
		return JSON.parse(Buffer.concat(chunks).toString("utf8"));
	} catch {
		throw Object.assign(new Error("invalid JSON"), { status: 400 });
	}
}

const SEND_SET = new Set<string>(["send_message", "generate_and_send_image"]);

function sendCalls(body: unknown): number {
	const arr = Array.isArray(body) ? body : [body];
	return arr.filter((m) => m && typeof m === "object" && (m as { method?: string }).method === "tools/call" && SEND_SET.has(String((m as { params?: { name?: string } }).params?.name))).length;
}

export const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export async function startMcpHttp(ctx: ToolContext, opts: HttpOptions = {}): Promise<{ server: Server; url: string; stats: () => McpStats }> {
	const host = opts.host ?? "127.0.0.1";
	// 只綁 loopback；必須有 token（絕不提供未驗證的服務）
	if (!LOOPBACK.has(host)) throw new Error("MCP server must bind to a loopback address");
	const getToken = opts.getToken ?? (() => opts.token);
	if (!getToken() || String(getToken()).length < 16) throw new Error("MCP token is required (>= 16 chars)");
	const bucket = new TokenBucket(opts.ratePerMin ?? 120);
	const sendBucket = new TokenBucket(opts.sendRatePerMin ?? 10);
	const maxBody = opts.maxBodyBytes ?? 256 * 1024;
	const stats: McpStats = { started_at: Date.now(), requests: 0, rejected: { unauthorized: 0, rate_limited: 0, too_large: 0, forbidden: 0 }, clients: [], recent: [] };
	const clients = new Map<string, { name: string; last_seen: number; calls: number }>();
	const json = (res: import("node:http").ServerResponse, code: number, v: unknown, extra: Record<string, string> = {}) =>
		res.writeHead(code, { "content-type": "application/json", ...extra }).end(JSON.stringify(v));

	const http = createServer(async (req, res) => {
		stats.requests++;
		if (!req.url?.startsWith("/mcp")) return void res.writeHead(404).end();
		// 瀏覽器網頁一律拒絕（有 Origin 就拒），並檢查 Host 防 DNS rebinding
		if (req.headers.origin || !hostOk(req)) {
			stats.rejected.forbidden++;
			return void json(res, 403, { error: "forbidden" });
		}
		if (!authorized(req, getToken())) {
			stats.rejected.unauthorized++;
			opts.audit?.log("mcp", "mcp_unauthorized", { ok: false });
			return void json(res, 401, { error: "unauthorized" });
		}
		if (req.method !== "POST") return void res.writeHead(405, { allow: "POST" }).end();
		if (!bucket.take()) {
			stats.rejected.rate_limited++;
			return void json(res, 429, { error: "rate_limited" }, { "retry-after": "5" });
		}
		let parsed: unknown;
		try {
			parsed = await readBody(req, maxBody);
		} catch (e) {
			const status = (e as { status?: number }).status ?? 400;
			if (status === 413) stats.rejected.too_large++;
			return void json(res, status, { error: (e as Error).message });
		}
		const nSend = sendCalls(parsed);
		if (nSend && !sendBucket.take(nSend)) {
			stats.rejected.rate_limited++;
			opts.audit?.log("mcp", "mcp_send_rate_limited", { ok: false });
			return void json(res, 429, { error: "rate_limited", message: "too many send calls" }, { "retry-after": "30" });
		}
		const client = String(req.headers["user-agent"] ?? "unknown").replace(/[^\x20-\x7e]/g, "").slice(0, 40) || "unknown";
		const c = clients.get(client) ?? { name: client, last_seen: 0, calls: 0 };
		c.last_seen = Date.now();
		clients.set(client, c);
		const mcp = buildMcpServer(ctx, {
			client,
			onCall: (tool, ok, ms, code) => {
				c.calls++;
				stats.recent.unshift({ ts: Date.now(), client, tool, ok, ms, code });
				stats.recent.length = Math.min(stats.recent.length, 50);
				opts.audit?.log("mcp", `tool:${tool}`, { ok, detail: { client, ms, code } });
			},
		});
		const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
		res.on("close", () => {
			void transport.close();
			void mcp.close();
		});
		try {
			await mcp.connect(transport);
			await transport.handleRequest(req, res, parsed);
		} catch (e) {
			if (!res.headersSent) json(res, 500, { error: (e as Error).message });
		}
	});
	http.headersTimeout = 10_000;
	http.requestTimeout = 60_000;
	await new Promise<void>((resolve) => http.listen(opts.port ?? 47823, host, resolve));
	const addr = http.address();
	const port = typeof addr === "object" && addr ? addr.port : opts.port;
	return {
		server: http,
		url: `http://${host}:${port}/mcp`,
		stats: () => ({ ...stats, clients: [...clients.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, 10) }),
	};
}
