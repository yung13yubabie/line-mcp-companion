/**
 * App 內部控制 API（給 Kotlin UI 用，不是給 AI）：登入狀態、QR/PIN、會話清單與勾選、設定。
 * 只綁 127.0.0.1，必須帶 Bearer token（由 Android Service 產生、經環境變數傳入）。
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { Store } from "../storage/db.ts";
import type { Whitelist } from "../whitelist.ts";

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
}

const SETTING_KEYS = new Set(["read_receipts", "sync_scope", "allow_key_registration"]);

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
	const chunks: Buffer[] = [];
	for await (const c of req) chunks.push(c as Buffer);
	if (!chunks.length) return {};
	return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export async function startControlHttp(deps: ControlDeps, opts: { port?: number; token: string }): Promise<{ server: Server; url: string }> {
	const server = createServer(async (req, res) => {
		const send = (code: number, v: unknown) => res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(v));
		if (req.headers.authorization !== `Bearer ${opts.token}`) return send(401, { error: "unauthorized" });
		try {
			const url = new URL(req.url ?? "/", "http://x");
			if (req.method === "GET" && url.pathname === "/control/state") return send(200, deps.login());
			if (req.method === "POST" && url.pathname === "/control/login/qr") {
				deps.startQrLogin();
				return send(202, deps.login());
			}
			if (req.method === "GET" && url.pathname === "/control/chats") {
				return send(
					200,
					deps.store.listChats().map((c) => {
						const last = deps.store.getMessages(c.id, { limit: 1 })[0];
						const preview = last ? (last.text ?? (last.content_type === "IMAGE" ? "[圖片]" : last.content_type === "FILE" ? `[檔案] ${last.media_name ?? ""}` : `[${last.content_type}]`)) : "";
						return { id: c.id, type: c.type, name: c.name, allowed: c.allowed === 1, last_message_at: c.last_message_at, preview, member_count: c.member_count };
					}),
				);
			}
			if (req.method === "GET" && url.pathname === "/control/info") return send(200, deps.info?.() ?? {});
			if (req.method === "GET" && url.pathname === "/control/messages") {
				// UI 自己的檢視（使用者本人），不受 MCP 白名單限制；同樣不呼叫任何已讀 API
				const chatId = url.searchParams.get("chat_id") ?? "";
				const rows = deps.store.getMessages(chatId, { limit: Number(url.searchParams.get("limit") ?? 100) });
				return send(200, rows.reverse());
			}
			if (req.method === "POST" && url.pathname === "/control/chats/allow") {
				const b = await body(req);
				const ok = deps.whitelist.set(String(b.chat_id), b.allowed === true);
				return send(ok ? 200 : 404, { ok });
			}
			if (req.method === "POST" && url.pathname === "/control/settings") {
				const b = await body(req);
				for (const [k, v] of Object.entries(b)) {
					if (!SETTING_KEYS.has(k)) return send(400, { error: `unknown setting ${k}` });
					deps.store.setSetting(k, String(v));
				}
				return send(200, { ok: true });
			}
			return send(404, { error: "not found" });
		} catch (e) {
			return send(500, { error: (e as Error).message });
		}
	});
	await new Promise<void>((r) => server.listen(opts.port ?? 47824, "127.0.0.1", r));
	const a = server.address();
	return { server, url: `http://127.0.0.1:${typeof a === "object" && a ? a.port : opts.port}/control` };
}
