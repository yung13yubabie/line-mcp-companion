/**
 * 日報（digest）：AI 把一段期間的聊天整理成幾則「新聞」，每則附上來源訊息。
 *
 * - 寫入來源：MCP `save_digest`（外部 AI）、App 內建 AI、mock 示範
 * - 內容視為不可信文字：去掉 HTML 標籤 / 控制字元，限制長度與數量
 * - 來源訊息必須屬於該聊天（跨聊天日報用 "<chat_id>:<message_id>"），而且聊天要在 MCP 白名單
 * - 來源時間一律以資料庫為準（不採信呼叫端給的 first/last_sent_at）；被隱藏的訊息直接拿掉
 * - 標題 / 內容用資料金鑰 AES-256-GCM 加密，AAD = digest:<created_at>:<chat|*>
 */
import type { Store } from "./db.ts";
import type { SecretBox } from "./secret-box.ts";
import type { Whitelist } from "../whitelist.ts";

export const DIGEST_LIMITS = { title: 120, headline: 120, body: 1200, items: 30, sources: 50, source: 60, bytes: 64 * 1024, spanDays: 31 };

export interface DigestItemInput {
	headline: string;
	body?: string;
	source_message_ids?: string[];
	first_sent_at?: unknown;
	last_sent_at?: unknown;
}

export interface DigestInput {
	chat_id: string | null;
	period_start: number;
	period_end: number;
	title: string;
	items: DigestItemInput[];
	source?: string | null;
}

export interface DigestSource {
	chat_id: string;
	message_id: string;
	sent_at: number;
	sender: string | null;
}

export interface DigestItem {
	headline: string;
	body: string;
	sources: DigestSource[];
	first_sent_at: number | null;
	last_sent_at: number | null;
}

export interface Digest {
	id: number;
	chat_id: string | null;
	chats: string[];
	period_start: number;
	period_end: number;
	created_at: number;
	source: string;
	actor: string;
	title: string;
	items: DigestItem[];
}

/** 不可信文字 → 純文字：去 HTML 標籤、控制字元、bidi 控制字元，壓空白，截斷 */
export function plainText(v: unknown, max: number, multiline = false): string {
	let s = String(v ?? "");
	s = s.replace(/<\/?[a-zA-Z][^>]*>/g, "").replace(/<!--[\s\S]*?-->/g, "");
	s = s.replace(/[<>]/g, (c) => (c === "<" ? "‹" : "›"));
	s = s.replace(/[\u202a-\u202e\u2066-\u2069\u200e\u200f]/g, "");
	s = multiline ? s.replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, "").replace(/\n{3,}/g, "\n\n") : s.replace(/[\u0000-\u001f\u007f]/g, " ");
	s = s.replace(/[ \t]+/g, " ").trim();
	const cps = [...s];
	return cps.length > max ? cps.slice(0, max - 1).join("") + "…" : s;
}

export class DigestStore {
	#store: Store;
	#box: SecretBox;
	#wl: Whitelist;
	constructor(store: Store, box: SecretBox, whitelist: Whitelist) {
		this.#store = store;
		this.#box = box;
		this.#wl = whitelist;
	}

	#aad(createdAt: number, chatId: string | null) {
		return `digest:${createdAt}:${chatId ?? "*"}`;
	}

	/** 驗證 + 正規化；錯誤丟 Error（訊息給呼叫端看） */
	normalize(input: DigestInput): { chats: string[]; title: string; items: DigestItem[] } {
		const chatId = input.chat_id ?? null;
		if (chatId !== null) this.#wl.assert(chatId);
		const ps = Number(input.period_start);
		const pe = Number(input.period_end);
		if (!Number.isFinite(ps) || !Number.isFinite(pe) || pe <= ps) throw new Error("period_end must be after period_start");
		if (pe - ps > DIGEST_LIMITS.spanDays * 86_400_000) throw new Error(`period too long (max ${DIGEST_LIMITS.spanDays} days)`);
		if (JSON.stringify(input).length > DIGEST_LIMITS.bytes) throw new Error("digest too large (max 64 KB)");
		const title = plainText(input.title, DIGEST_LIMITS.title);
		if (!title) throw new Error("title required");
		if (!Array.isArray(input.items) || input.items.length === 0) throw new Error("items required");
		if (input.items.length > DIGEST_LIMITS.items) throw new Error(`too many items (max ${DIGEST_LIMITS.items})`);
		const chats = new Set<string>();
		if (chatId) chats.add(chatId);
		const items: DigestItem[] = input.items.map((it, i) => {
			const headline = plainText(it?.headline, DIGEST_LIMITS.headline);
			if (!headline) throw new Error(`items[${i}].headline required`);
			const ids = Array.isArray(it.source_message_ids) ? it.source_message_ids.map(String) : [];
			if (ids.length > DIGEST_LIMITS.sources) throw new Error(`items[${i}]: too many source_message_ids (max ${DIGEST_LIMITS.sources})`);
			const sources: DigestSource[] = [];
			for (const raw of ids) {
				if (raw.length > DIGEST_LIMITS.source) throw new Error(`items[${i}]: bad message id`);
				let c = chatId;
				let mid = raw;
				if (chatId === null) {
					const k = raw.lastIndexOf(":");
					if (k <= 0) throw new Error(`items[${i}]: cross-chat digests need "<chat_id>:<message_id>"`);
					c = raw.slice(0, k);
					mid = raw.slice(k + 1);
					this.#wl.assert(c);
				} else if (raw.includes(":") && raw.startsWith(chatId + ":")) mid = raw.slice(chatId.length + 1);
				const m = this.#store.getMessage(c!, mid);
				if (!m) throw new Error(`items[${i}]: message ${raw} is not in ${c}`);
				if (m.hidden) continue; // 被隱藏 / 收回的訊息不當來源（安靜拿掉）
				if (!sources.some((s) => s.chat_id === c && s.message_id === mid)) sources.push({ chat_id: c!, message_id: mid, sent_at: m.sent_at, sender: m.sender_name ?? m.sender_mid ?? null });
				chats.add(c!);
			}
			sources.sort((a, b) => a.sent_at - b.sent_at);
			return {
				headline,
				body: plainText(it.body ?? "", DIGEST_LIMITS.body, true),
				sources,
				first_sent_at: sources[0]?.sent_at ?? null,
				last_sent_at: sources.at(-1)?.sent_at ?? null,
			};
		});
		return { chats: [...chats], title, items };
	}

	save(input: DigestInput, actor: string): Digest {
		const n = this.normalize(input);
		const createdAt = Date.now();
		const source = plainText(input.source ?? actor, 60) || actor;
		const body = this.#box.seal(JSON.stringify({ title: n.title, items: n.items }), this.#aad(createdAt, input.chat_id ?? null));
		const r = this.#store.db
			.prepare("INSERT INTO digest(chat_id, chats, period_start, period_end, created_at, source, actor, n_items, body_enc) VALUES (?,?,?,?,?,?,?,?,?)")
			.run(input.chat_id ?? null, JSON.stringify(n.chats), Number(input.period_start), Number(input.period_end), createdAt, source, actor, n.items.length, body);
		return this.get(Number(r.lastInsertRowid))!;
	}

	#row(r: Record<string, unknown>): Digest {
		let body: { title: string; items: DigestItem[] } = { title: "（無法解密）", items: [] };
		try {
			body = JSON.parse(this.#box.open(String(r.body_enc), this.#aad(Number(r.created_at), (r.chat_id as string | null) ?? null)));
		} catch {}
		return {
			id: Number(r.id),
			chat_id: (r.chat_id as string | null) ?? null,
			chats: JSON.parse(String(r.chats)) as string[],
			period_start: Number(r.period_start),
			period_end: Number(r.period_end),
			created_at: Number(r.created_at),
			source: String(r.source),
			actor: String(r.actor),
			title: body.title,
			items: body.items,
		};
	}

	/** 白名單：所有引用的聊天都還在白名單才看得到（UI 用 respectWhitelist=false 看全部自己的資料） */
	#visible(d: { chats: string[] }, respectWhitelist: boolean) {
		return !respectWhitelist || d.chats.every((c) => this.#wl.isAllowed(c));
	}

	get(id: number, respectWhitelist = false): Digest | null {
		const r = this.#store.db.prepare("SELECT * FROM digest WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		if (!r) return null;
		const d = this.#row(r);
		return this.#visible(d, respectWhitelist) ? d : null;
	}

	/** 期間有重疊的日報（新到舊） */
	list(f: { chatIds?: string[] | null; since?: number; until?: number; limit?: number; respectWhitelist?: boolean } = {}): Digest[] {
		const rows = this.#store.db
			.prepare("SELECT * FROM digest WHERE period_end > ? AND period_start < ? ORDER BY period_end DESC, id DESC LIMIT ?")
			.all(f.since ?? 0, f.until ?? Number.MAX_SAFE_INTEGER, Math.min(500, Math.max(1, (f.limit ?? 50) * 4))) as Record<string, unknown>[];
		const want = f.chatIds?.length ? new Set(f.chatIds) : null;
		const out: Digest[] = [];
		for (const r of rows) {
			const chats = JSON.parse(String(r.chats)) as string[];
			if (!this.#visible({ chats }, f.respectWhitelist ?? false)) continue;
			if (want && !chats.some((c) => want.has(c))) continue;
			out.push(this.#row(r));
			if (out.length >= (f.limit ?? 50)) break;
		}
		return out;
	}

	delete(id: number, respectWhitelist = false): boolean {
		if (!this.get(id, respectWhitelist)) return false;
		this.#store.db.prepare("DELETE FROM digest WHERE id = ?").run(id);
		return true;
	}
}
