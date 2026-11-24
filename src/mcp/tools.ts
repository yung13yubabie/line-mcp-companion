/**
 * MCP 基本工具（不需外部 AI API）。全部是純函式，方便單元測試。
 * 規則：每個工具都先過白名單；未允許的會話一律回 chat_not_allowed（不洩漏是否存在）。
 * 沒有任何工具會呼叫已讀 API。
 */
import { readFileSync } from "node:fs";
import type { Store, MessageRow } from "../storage/db.ts";
import { Whitelist } from "../whitelist.ts";
import type { SyncEngine } from "../sync/engine.ts";
import type { MediaCache } from "../media/cache.ts";
import type { AiService } from "../ai/service.ts";
import type { OutboxItem } from "../ai/outbox.ts";
import type { ScamDetector, ScamLevel } from "../scam/detector.ts";

export interface ToolContext {
	store: Store;
	whitelist: Whitelist;
	sync: SyncEngine | null;
	media: MediaCache | null;
	/** download_media 回傳 base64 的上限（bytes） */
	maxInlineBytes?: number;
	/** 進階工具（送訊息 / AI）；未設定時這些工具不註冊 */
	ai?: AiService | null;
	scam?: ScamDetector | null;
}

/** 進階工具：會送出訊息或呼叫 AI。全部受「MCP 白名單 + AI 代聊白名單 + 模式 + kill switch + 上限」控制。 */
export const SEND_TOOLS = ["send_message", "generate_and_send_image", "get_ai_suggestion", "get_outbox_item", "list_stickers"] as const;
/** 反詐工具：只讀警示與範例（add_scam_sample 只能加 SCAM 範例） */
export const SCAM_TOOLS = ["scan_scam_alerts", "list_scam_samples", "add_scam_sample"] as const;

export const BASIC_TOOLS = [
	"list_allowed_chats",
	"get_messages",
	"search_messages",
	"get_attachment",
	"download_media",
	"get_unread_summary",
	"get_sync_status",
	"trigger_sync",
] as const;
export type ToolName = (typeof BASIC_TOOLS)[number] | (typeof SEND_TOOLS)[number] | (typeof SCAM_TOOLS)[number];

/** 接受 epoch ms 或 ISO 字串 */
export function toMs(v: unknown): number | undefined {
	if (v === undefined || v === null || v === "") return undefined;
	if (typeof v === "number") return v;
	const n = Number(v);
	if (Number.isFinite(n)) return n;
	const t = Date.parse(String(v));
	if (Number.isNaN(t)) throw new Error(`invalid time: ${String(v)}`);
	return t;
}

function view(m: MessageRow) {
	return {
		chat_id: m.chat_id,
		message_id: m.id,
		sender: m.sender_name ?? m.sender_mid,
		from_self: m.from_self === 1,
		sent_at: new Date(m.sent_at).toISOString(),
		type: m.content_type,
		text: m.text,
		media: m.content_type !== "NONE" ? { name: m.media_name, size: m.media_size } : undefined,
		decrypt_state: m.decrypt_state === "plain" || m.decrypt_state === "decrypted" ? undefined : m.decrypt_state,
	};
}

function outboxView(it: OutboxItem) {
	return {
		id: it.id,
		chat_id: it.chat_id,
		kind: it.kind,
		status: it.status,
		needs_user_confirmation: it.status === "pending",
		text: it.text,
		reply_to: it.reply_to,
		scheduled_at: it.scheduled_at ? new Date(it.scheduled_at).toISOString() : null,
		sent_at: it.sent_at ? new Date(it.sent_at).toISOString() : null,
		error: it.error,
	};
}

function need<T>(v: T | null | undefined, what: string): T {
	if (!v) throw new Error(`${what} not available`);
	return v;
}

function str(v: unknown, max: number, field: string): string {
	const s = v == null ? "" : String(v);
	if ([...s].length > max) throw new Error(`${field} too long (max ${max})`);
	return s;
}

export async function callTool(ctx: ToolContext, name: string, args: Record<string, unknown> = {}, client?: string): Promise<unknown> {
	const { store, whitelist } = ctx;
	switch (name as ToolName) {
		case "list_allowed_chats":
			return store.listChats({ allowedOnly: true }).map((c) => {
				const ai = ctx.ai?.policy.get(c.id);
				return {
					chat_id: c.id,
					type: c.type,
					name: c.name,
					member_count: c.member_count,
					last_message_at: c.last_message_at ? new Date(c.last_message_at).toISOString() : null,
					// 這個會話能不能經 MCP 代聊（send_message）
					can_send: !!ai && ai.ai_allowed && ai.mode !== "off" && !!ctx.ai?.policy.aiEnabled && !ctx.ai?.policy.killSwitch,
					send_mode: ai ? (ai.mode === "auto" && !ai.confirm_send ? "direct" : ai.mode === "off" ? "off" : "needs_confirmation") : "off",
				};
			});

		case "send_message": {
			const ai = need(ctx.ai, "send tools");
			const chatId = String(args.chat_id ?? "");
			const st = args.sticker as { package_id?: unknown; sticker_id?: unknown } | undefined;
			const text = args.text == null ? null : str(args.text, 2000, "text").trim();
			if (!st && !text) throw new Error("text or sticker is required");
			const replyTo = args.reply_to == null || args.reply_to === "" ? null : str(args.reply_to, 64, "reply_to");
			const base = { chatId, origin: "mcp" as const, originDetail: client ?? null, replyTo };
			const r = st
				? ai.outbox.enqueue({ ...base, kind: "sticker", sticker: { package_id: String(st.package_id ?? ""), sticker_id: String(st.sticker_id ?? "") }, text: null }, "mcp")
				: ai.outbox.enqueue({ ...base, kind: "text", text }, "mcp");
			return { ...outboxView(r.item), route: r.route, note: r.route === "pending" ? "已放進確認佇列，使用者核准後才會送出" : "已排程，延遲後送出（使用者可在總控台取消）" };
		}

		case "generate_and_send_image": {
			const ai = need(ctx.ai, "send tools");
			const r = await ai.imageToQueue(String(args.chat_id ?? ""), str(args.prompt, 1000, "prompt"), args.caption == null ? null : str(args.caption, 500, "caption"), "mcp", "mcp", client ?? null);
			return { ...outboxView(r.item), route: r.route };
		}

		case "get_ai_suggestion": {
			const ai = need(ctx.ai, "AI");
			const chatId = String(args.chat_id ?? "");
			const s = await ai.suggest(chatId, "mcp", args.instruction == null ? null : str(args.instruction, 500, "instruction"), args.reply_to == null ? null : str(args.reply_to, 64, "reply_to"));
			return { chat_id: chatId, text: s.text, sticker: s.sticker, flags: s.flags, note: "只是建議，尚未送出；要送請呼叫 send_message" };
		}

		case "get_outbox_item": {
			const ai = need(ctx.ai, "send tools");
			const it = ai.outbox.get(Number(args.id));
			if (!it || it.origin !== "mcp") throw new Error("outbox item not found");
			whitelist.assert(it.chat_id);
			return outboxView(it);
		}

		case "list_stickers": {
			const ai = need(ctx.ai, "send tools");
			return ai.stickers.list({ ownedOnly: true, limit: 100 }).map((e) => ({ package_id: e.package_id, sticker_id: e.sticker_id, label: e.label ?? e.text, uses: e.uses }));
		}

		case "scan_scam_alerts": {
			const sc = need(ctx.scam, "anti-scam");
			if (args.chat_id !== undefined) whitelist.assert(String(args.chat_id));
			const lvl = args.min_level === "high" ? "high" : ("suspicious" as ScamLevel);
			const since = toMs(args.since);
			const rows = sc.alerts({ since, chatId: args.chat_id === undefined ? undefined : String(args.chat_id), minLevel: lvl, limit: args.limit === undefined ? 50 : Math.min(200, Number(args.limit)) });
			return { alerts: rows, next_since: rows.length ? Math.max(...rows.map((r) => r.created_at)) + 1 : (since ?? null) };
		}

		case "list_scam_samples": {
			const sc = need(ctx.scam, "anti-scam");
			return sc.samples({ label: args.label === "OK" ? "OK" : args.label === "SCAM" ? "SCAM" : undefined, category: args.category == null ? undefined : String(args.category), limit: args.limit === undefined ? 100 : Math.min(500, Number(args.limit)) });
		}

		case "add_scam_sample": {
			const sc = need(ctx.scam, "anti-scam");
			// MCP 只能新增 SCAM 範例（不能加 OK 範例來「洗白」某種訊息）
			const text = str(args.text, 500, "text").trim();
			if (text.length < 6) throw new Error("text too short");
			return sc.addSample({ label: "SCAM", category: str(args.category ?? "其他", 20, "category") || "其他", text }, "mcp");
		}

		case "get_messages": {
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			const rows = store.getMessages(chatId, {
				limit: args.limit === undefined ? 50 : Number(args.limit),
				before: toMs(args.before),
				after: toMs(args.after),
			});
			const next = rows.length ? rows[rows.length - 1]!.sent_at : null;
			return { chat_id: chatId, messages: rows.map(view), next_before: next };
		}

		case "search_messages": {
			const q = String(args.query ?? "");
			let scope = whitelist.allowedIds();
			if (args.chat_id !== undefined) {
				whitelist.assert(String(args.chat_id));
				scope = [String(args.chat_id)];
			}
			return store.searchMessages(q, scope, args.limit === undefined ? 50 : Number(args.limit)).map(view);
		}

		case "get_attachment": {
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			const m = store.getMessage(chatId, String(args.message_id ?? ""));
			if (!m) throw new Error("message not found");
			const cached = ctx.media?.cached(chatId, m.id);
			return {
				...view(m),
				has_media: m.content_type !== "NONE",
				cached_path: cached?.path ?? null,
				mime: cached?.mime ?? null,
			};
		}

		case "download_media": {
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			if (!ctx.media) throw new Error("media cache not configured");
			const r = await ctx.media.ensure(chatId, String(args.message_id ?? ""));
			const out: Record<string, unknown> = { path: r.path, mime: r.mime, size: r.size, cached: r.cached };
			if (args.inline === true) {
				const max = ctx.maxInlineBytes ?? 5 * 1024 * 1024;
				if ((r.size ?? 0) > max) throw new Error(`file too large to inline (${r.size} > ${max} bytes)`);
				out.base64 = readFileSync(r.path).toString("base64");
			}
			return out;
		}

		case "get_unread_summary": {
			const perChat = args.per_chat === undefined ? 5 : Number(args.per_chat);
			const names = new Map(store.listChats({ allowedOnly: true }).map((c) => [c.id, c.name]));
			return store.unreadSummary(whitelist.allowedIds(), perChat).map((u) => ({
				chat_id: u.chat_id,
				name: names.get(u.chat_id) ?? null,
				unread: u.unread,
				latest: u.latest.map(view),
			}));
		}

		case "get_sync_status": {
			const s = ctx.sync?.status();
			return {
				online: !!ctx.sync,
				read_receipts: store.getSetting("read_receipts") === "on" ? "enabled" : "blocked",
				...(s ?? { state: "offline", counts: store.counts() }),
			};
		}

		case "trigger_sync": {
			if (!ctx.sync) throw new Error("not online: no LINE session");
			if (args.full === true) await ctx.sync.fullSync();
			const added = await ctx.sync.pollOnce();
			return { ok: true, added, status: ctx.sync.status() };
		}

		default:
			throw new Error(`unknown tool: ${name}`);
	}
}
