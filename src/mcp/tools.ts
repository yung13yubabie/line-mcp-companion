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
import type { ScamWarner } from "../scam/warner.ts";
import type { EventLog } from "../storage/event-log.ts";

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
	warner?: ScamWarner | null;
	events?: EventLog | null;
}

/** 進階工具：會送出訊息或呼叫 AI。全部受「MCP 白名單 + AI 代聊白名單 + 模式 + kill switch + 上限」控制。 */
export const SEND_TOOLS = ["send_message", "generate_and_send_image", "get_ai_suggestion", "get_outbox_item", "list_stickers"] as const;
/** 確認佇列 / 信任狀態 / AI 紀錄。核准需 App 內開「允許 MCP 核准」；升級到 AUTO 需開「允許 MCP 升級」且 confirm_auto=true。降級永遠允許。 */
export const REVIEW_TOOLS = ["list_pending", "edit_pending", "approve_pending", "reject_pending", "get_chat_trust", "set_chat_trust", "get_ai_log"] as const;
/** 反詐工具（add_scam_sample 只能加 SCAM 範例） */
export const SCAM_TOOLS = ["scan_scam_alerts", "list_scam_samples", "add_scam_sample", "compose_scam_warning", "mark_scam_false_positive", "trust_scam_member", "get_scam_log"] as const;

/** ChatGPT 相容的 search / fetch（只讀） */
export const FETCH_TOOLS = ["search", "fetch"] as const;

/** 只讀工具：連接器（OAuth）只拿到 read scope 時只註冊這些 */
export const READ_ONLY_TOOLS = new Set<string>([
	"list_allowed_chats", "get_messages", "search_messages", "get_attachment", "download_media", "get_unread_summary", "get_sync_status", "trigger_sync",
	"get_outbox_item", "list_stickers", "scan_scam_alerts", "list_scam_samples", "list_pending", "get_chat_trust", "get_ai_log", "get_scam_log", "search", "fetch",
]);

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
export type ToolName = (typeof BASIC_TOOLS)[number] | (typeof SEND_TOOLS)[number] | (typeof REVIEW_TOOLS)[number] | (typeof SCAM_TOOLS)[number] | (typeof FETCH_TOOLS)[number];

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
		// 被隱藏 / 收回的訊息不回傳內容，也不能回覆
		text: m.hidden ? null : m.text,
		hidden: m.hidden ? m.hidden : undefined,
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

/** 只能操作白名單會話裡的 pending 項目 */
function pendingItem(ctx: ToolContext, id: unknown): OutboxItem {
	const it = ctx.ai?.outbox.get(Number(id));
	if (!it) throw new Error("outbox item not found");
	ctx.whitelist.assert(it.chat_id);
	if (it.status !== "pending") throw new Error(`item is ${it.status}, not pending`);
	return it;
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

		// ---- 確認佇列 ----
		case "list_pending": {
			const ai = need(ctx.ai, "review tools");
			if (args.chat_id !== undefined) whitelist.assert(String(args.chat_id));
			const allowed = new Map(store.listChats({ allowedOnly: true }).map((c) => [c.id, c.name]));
			return ai.outbox
				.list({ status: "pending", limit: 100 })
				.filter((it) => allowed.has(it.chat_id) && (args.chat_id === undefined || it.chat_id === String(args.chat_id)))
				.map((it) => ({ ...outboxView(it), chat_name: allowed.get(it.chat_id) ?? null, origin: it.origin, flags: it.flags ? it.flags.split(",") : [], sticker: it.sticker_json ? JSON.parse(it.sticker_json) : null }));
		}
		case "edit_pending": {
			const ai = need(ctx.ai, "review tools");
			const it = pendingItem(ctx, args.id);
			const st = args.sticker as { package_id?: unknown; sticker_id?: unknown } | undefined;
			const out = ai.outbox.edit(it.id, { text: args.text === undefined ? undefined : str(args.text, 2000, "text"), sticker: st ? { package_id: String(st.package_id ?? ""), sticker_id: String(st.sticker_id ?? "") } : undefined }, "mcp");
			return { ...outboxView(out), note: "已修改，仍在確認佇列" };
		}
		case "approve_pending": {
			const ai = need(ctx.ai, "review tools");
			if (store.getSetting("mcp_allow_approve") !== "on") throw new Error("mcp_approve_disabled: 使用者沒有開啟「允許 MCP 核准佇列」，請請使用者在 App 總控台核准");
			const it = pendingItem(ctx, args.id);
			return outboxView(ai.outbox.approve(it.id, args.text == null ? null : str(args.text, 2000, "text"), "mcp"));
		}
		case "reject_pending": {
			const ai = need(ctx.ai, "review tools");
			const it = pendingItem(ctx, args.id);
			return outboxView(ai.outbox.reject(it.id, "mcp"));
		}

		// ---- 信任狀態 ----
		case "get_chat_trust": {
			const ai = need(ctx.ai, "review tools");
			if (args.chat_id !== undefined) whitelist.assert(String(args.chat_id));
			const chats = store.listChats({ allowedOnly: true }).filter((c) => args.chat_id === undefined || c.id === String(args.chat_id));
			return {
				mcp_can_promote: store.getSetting("mcp_allow_promote") === "on",
				mcp_can_approve: store.getSetting("mcp_allow_approve") === "on",
				kill_switch: ai.policy.killSwitch,
				chats: chats.map((c) => ({ chat_id: c.id, name: c.name, ai: ai.policy.trust(c.id, "ai").toUpperCase(), scam: ai.policy.trust(c.id, "scam").toUpperCase(), ai_allowed: ai.policy.get(c.id).ai_allowed, scam_warn_enabled: ctx.warner?.get(c.id).enabled ?? false })),
				recent_changes: ai.policy.trustLog(20).filter((r) => store.getChat(r.chat_id)?.allowed === 1),
			};
		}
		case "set_chat_trust": {
			const ai = need(ctx.ai, "review tools");
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			const feature = args.feature === "scam" ? "scam" : args.feature === "ai" ? "ai" : null;
			if (!feature) throw new Error("feature must be ai or scam");
			const state = String(args.state ?? "").toLowerCase();
			if (state !== "review" && state !== "auto") throw new Error("state must be REVIEW or AUTO");
			if (state === "auto") {
				if (store.getSetting("mcp_allow_promote") !== "on") throw new Error("mcp_promote_disabled: 使用者沒有開啟「允許 MCP 升級到 AUTO」；降級永遠可以");
				if (args.confirm_auto !== true) throw new Error("confirm_auto_required: 升級到 AUTO 需要 confirm_auto=true");
			}
			const st = ai.policy.setTrust(chatId, feature, state, "mcp", `${client ?? "mcp"}${args.reason ? ": " + str(args.reason, 60, "reason") : ""}`);
			return { chat_id: chatId, feature, state: st.toUpperCase() };
		}
		case "get_ai_log": {
			const ev = need(ctx.events, "logs");
			if (args.chat_id !== undefined) whitelist.assert(String(args.chat_id));
			return ev.aiList({ allowedOnly: true, chatId: args.chat_id === undefined ? undefined : String(args.chat_id), since: toMs(args.since), until: toMs(args.until), event: args.event == null ? undefined : String(args.event), limit: args.limit === undefined ? 100 : Math.min(500, Number(args.limit)) });
		}

		// ---- 反詐：自訂提醒 / 誤判 / 信任成員 / 紀錄 ----
		case "compose_scam_warning": {
			const w = need(ctx.warner, "anti-scam");
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			const it = w.compose(chatId, str(args.message_id, 64, "message_id"), args.text == null ? null : str(args.text, 300, "text"), "mcp");
			return { ...outboxView(it), note: it.status === "pending" ? "已放進確認佇列（此群反詐提醒為 REVIEW）" : "已排程（此群反詐提醒為 AUTO）" };
		}
		case "mark_scam_false_positive": {
			const sc = need(ctx.scam, "anti-scam");
			const a = store.db.prepare("SELECT chat_id FROM scam_alert WHERE id = ?").get(Number(args.alert_id)) as { chat_id: string } | undefined;
			if (!a) throw new Error("alert not found");
			whitelist.assert(a.chat_id);
			const r = sc.markFalsePositive(Number(args.alert_id), args.trust_member !== false);
			let cancelled = 0;
			if (ctx.ai) {
				const rows = store.db.prepare("SELECT id FROM outbox WHERE origin='scam_warn' AND chat_id=? AND reply_to=? AND status IN ('pending','approved')").all(r.chat_id, r.message_id) as { id: number }[];
				for (const x of rows) ctx.ai.outbox.reject(x.id, "mcp");
				cancelled = rows.length;
			}
			ctx.events?.setScamAction({ alertId: Number(args.alert_id) }, "false_positive", r.trusted ? "member trusted" : null);
			return { ...r, cancelled };
		}
		case "trust_scam_member": {
			const sc = need(ctx.scam, "anti-scam");
			const chatId = String(args.chat_id ?? "");
			whitelist.assert(chatId);
			const mid = str(args.member_id, 64, "member_id");
			if (!mid) throw new Error("member_id is required");
			sc.setAdmin(chatId, mid, args.remove === true ? { remove: true } : { mention: args.mention === true });
			return { chat_id: chatId, trusted_members: sc.admins(chatId) };
		}
		case "get_scam_log": {
			const ev = need(ctx.events, "logs");
			if (args.chat_id !== undefined) whitelist.assert(String(args.chat_id));
			return ev.scamList({
				allowedOnly: true,
				chatId: args.chat_id === undefined ? undefined : String(args.chat_id),
				since: toMs(args.since),
				until: toMs(args.until),
				action: args.action == null ? undefined : String(args.action),
				category: args.category == null ? undefined : String(args.category),
				limit: args.limit === undefined ? 100 : Math.min(500, Number(args.limit)),
			});
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

		// ChatGPT（deep research / 公司知識）相容的 search / fetch：只讀、只在白名單內
		case "search": {
			const q = String(args.query ?? "").trim();
			if (!q) return { results: [] };
			const rows = store.searchMessages(q, whitelist.allowedIds(), 20).filter((m) => !m.hidden);
			return {
				results: rows.map((m) => ({
					id: `${m.chat_id}:${m.id}`,
					title: `${store.getChat(m.chat_id)?.name ?? m.chat_id}｜${m.sender_name ?? m.sender_mid}｜${new Date(m.sent_at).toISOString().slice(0, 16)}`,
					url: `line-mcp://chat/${encodeURIComponent(m.chat_id)}/${encodeURIComponent(m.id)}`,
				})),
			};
		}

		case "fetch": {
			const id = String(args.id ?? "");
			const i = id.lastIndexOf(":");
			if (i <= 0) throw new Error("id must be <chat_id>:<message_id> from search");
			const chatId = id.slice(0, i);
			const msgId = id.slice(i + 1);
			whitelist.assert(chatId);
			const m = store.getMessage(chatId, msgId);
			if (!m || m.hidden) throw new Error("not_found");
			// 前後文：前 5 則 + 本則 + 後 5 則（被隱藏的不含內容）
			const before = store.getMessages(chatId, { before: m.sent_at, limit: 5 }).reverse();
			const after = store.getMessages(chatId, { after: m.sent_at, limit: 500 }).reverse().slice(0, 5);
			const line = (r: MessageRow) => `[${new Date(r.sent_at).toISOString().slice(0, 16)}] ${r.sender_name ?? r.sender_mid}: ${r.hidden ? "（已隱藏）" : (r.text ?? `[${r.content_type}]`)}`;
			const text = [...before.map(line), "▶ " + line(m), ...after.filter((r) => r.id !== m.id).map(line)].join("\n");
			return {
				id,
				title: `${store.getChat(chatId)?.name ?? chatId}｜${m.sender_name ?? m.sender_mid}`,
				text,
				url: `line-mcp://chat/${encodeURIComponent(chatId)}/${encodeURIComponent(msgId)}`,
				metadata: { chat_id: chatId, message_id: msgId, sent_at: new Date(m.sent_at).toISOString() },
			};
		}

		default:
			throw new Error(`unknown tool: ${name}`);
	}
}
