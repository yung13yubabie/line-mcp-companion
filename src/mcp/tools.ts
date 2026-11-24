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

export interface ToolContext {
	store: Store;
	whitelist: Whitelist;
	sync: SyncEngine | null;
	media: MediaCache | null;
	/** download_media 回傳 base64 的上限（bytes） */
	maxInlineBytes?: number;
}

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
export type ToolName = (typeof BASIC_TOOLS)[number];

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

export async function callTool(ctx: ToolContext, name: string, args: Record<string, unknown> = {}): Promise<unknown> {
	const { store, whitelist } = ctx;
	switch (name as ToolName) {
		case "list_allowed_chats":
			return store.listChats({ allowedOnly: true }).map((c) => ({
				chat_id: c.id,
				type: c.type,
				name: c.name,
				member_count: c.member_count,
				last_message_at: c.last_message_at ? new Date(c.last_message_at).toISOString() : null,
			}));

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
