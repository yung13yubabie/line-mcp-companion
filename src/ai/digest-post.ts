/**
 * 日報貼到群組：手動（App 按鈕 / MCP post_digest）或每天定時。
 * 一律走 Outbox：目標聊天要在 MCP 白名單 + AI 代聊名單（代聊模式不可為「關」），
 * 依目標聊天的 AI 信任狀態：審核 → 進確認佇列；自動 → 延遲後送。上限 / 緊急停止 / 活躍時段照常。
 * 貼出的文字：去掉網址（避免把詐騙連結轉貼出去）、LINE 禁字替換、≤ 1500 字。
 */
import type { Store } from "../storage/db.ts";
import type { DigestStore, Digest } from "../storage/digests.ts";
import type { Outbox, OutboxItem } from "./outbox.ts";
import type { AiService } from "./service.ts";
import type { Actor } from "./audit.ts";
import { scrubNotice } from "../scam/warner.ts";

export interface DigestSchedule {
	id: number;
	target_chat: string;
	source_chats: string[];
	time_hhmm: string;
	enabled: boolean;
	generate: boolean;
	last_run_day: string | null;
	created_at: number;
}

const MAX_POST = 1500;
const taipeiDay = (t: number) => new Date(t + 8 * 3600_000).toISOString().slice(0, 10);
const taipeiHHMM = (t: number) => new Date(t + 8 * 3600_000).toISOString().slice(11, 16);

export function stripLinks(s: string): string {
	return s
		.replace(/\bhttps?:\/\/\S+/gi, "［連結］")
		.replace(/(?<![\w@.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\/\S*/gi, "［連結］")
		.replace(/\bline\s*id\s*[:：]?\s*\S+/gi, "［LINE ID］");
}

/** 日報 → 一則 LINE 訊息 */
export function renderDigest(ds: Digest[], label?: string): string {
	const parts: string[] = [];
	for (const d of ds) {
		const date = taipeiDay(d.period_end - 1);
		parts.push(`📰 ${d.title}（${date}）`);
		d.items.slice(0, 10).forEach((it, i) => {
			const body = it.body ? `：${[...it.body].slice(0, 120).join("")}${[...it.body].length > 120 ? "…" : ""}` : "";
			parts.push(`${i + 1}. ${it.headline}${body}`);
		});
		parts.push("");
	}
	if (label) parts.push(label);
	let text = scrubNotice(stripLinks(parts.join("\n").trim()));
	if ([...text].length > MAX_POST) text = [...text].slice(0, MAX_POST - 1).join("") + "…";
	return text;
}

export class DigestPoster {
	#store: Store;
	#digests: DigestStore;
	#outbox: Outbox;
	#ai: AiService | null;
	#now: () => number;
	constructor(store: Store, digests: DigestStore, outbox: Outbox, ai: AiService | null, now: () => number = Date.now) {
		this.#store = store;
		this.#digests = digests;
		this.#outbox = outbox;
		this.#ai = ai;
		this.#now = now;
	}

	/** 手動貼一份（或多份）日報到目標聊天 */
	post(digestIds: number[], targetChat: string, actor: Actor, opts: { respectWhitelist?: boolean; detail?: string } = {}): { item: OutboxItem; route: "pending" | "scheduled"; text: string } {
		const ds = digestIds.map((id) => this.#digests.get(id, opts.respectWhitelist ?? false)).filter((d): d is Digest => !!d);
		if (!ds.length) throw new Error("digest not_found");
		const text = renderDigest(ds, "（由 LINE MCP Companion 日報整理）");
		const r = this.#outbox.enqueue({ chatId: targetChat, kind: "text", text, origin: "digest", originDetail: opts.detail ?? `digest:${digestIds.join(",")}`, trustOnly: true }, actor);
		this.#outbox.audit.log(actor, "digest_post_queued", { chatId: targetChat, detail: { digests: digestIds, route: r.route } });
		return { ...r, text };
	}

	// ---- 排程 ----
	schedules(): DigestSchedule[] {
		return (this.#store.db.prepare("SELECT * FROM digest_schedule ORDER BY id").all() as Record<string, unknown>[]).map((r) => ({
			id: Number(r.id),
			target_chat: String(r.target_chat),
			source_chats: JSON.parse(String(r.source_chats)) as string[],
			time_hhmm: String(r.time_hhmm),
			enabled: r.enabled === 1,
			generate: r.generate === 1,
			last_run_day: (r.last_run_day as string | null) ?? null,
			created_at: Number(r.created_at),
		}));
	}

	saveSchedule(s: { id?: number; target_chat: string; source_chats?: string[]; time_hhmm: string; enabled?: boolean; generate?: boolean }, actor: Actor): DigestSchedule {
		if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time_hhmm)) throw new Error("time must be HH:MM");
		const chat = this.#store.getChat(s.target_chat);
		if (!chat || chat.allowed !== 1) throw new Error("target chat must be in the MCP whitelist");
		const src = (s.source_chats ?? []).map(String).slice(0, 20);
		for (const c of src) if (this.#store.getChat(c)?.allowed !== 1) throw new Error(`source chat ${c} is not whitelisted`);
		if (s.id) {
			this.#store.db
				.prepare("UPDATE digest_schedule SET target_chat=?, source_chats=?, time_hhmm=?, enabled=?, generate=? WHERE id=?")
				.run(s.target_chat, JSON.stringify(src), s.time_hhmm, s.enabled === false ? 0 : 1, s.generate ? 1 : 0, s.id);
		} else {
			if (this.schedules().length >= 10) throw new Error("max 10 schedules");
			const r = this.#store.db
				.prepare("INSERT INTO digest_schedule(target_chat, source_chats, time_hhmm, enabled, generate, created_at) VALUES (?,?,?,?,?,?)")
				.run(s.target_chat, JSON.stringify(src), s.time_hhmm, s.enabled === false ? 0 : 1, s.generate ? 1 : 0, this.#now());
			s.id = Number(r.lastInsertRowid);
		}
		this.#outbox.audit.log(actor, "digest_schedule_saved", { chatId: s.target_chat, detail: { id: s.id, time: s.time_hhmm, sources: src.length } });
		return this.schedules().find((x) => x.id === s.id)!;
	}

	deleteSchedule(id: number, actor: Actor): boolean {
		const r = this.#store.db.prepare("DELETE FROM digest_schedule WHERE id = ?").run(id);
		this.#outbox.audit.log(actor, "digest_schedule_deleted", { detail: { id } });
		return Number(r.changes) > 0;
	}

	/** 每分鐘呼叫：到點的排程貼出今天的日報（最多一天一次） */
	async tick(): Promise<number> {
		const now = this.#now();
		const day = taipeiDay(now);
		const hhmm = taipeiHHMM(now);
		let n = 0;
		for (const s of this.schedules()) {
			if (!s.enabled || s.last_run_day === day || hhmm < s.time_hhmm) continue;
			this.#store.db.prepare("UPDATE digest_schedule SET last_run_day=? WHERE id=?").run(day, s.id);
			const start = Date.parse(`${day}T00:00:00+08:00`);
			const sources = s.source_chats.length ? s.source_chats : null;
			let list = this.#digests.list({ chatIds: sources, since: start, until: now, limit: 5 }).filter((d) => d.chats.every((c) => this.#store.getChat(c)?.allowed === 1));
			if (!list.length && s.generate && this.#ai && this.#ai.driver === "builtin" && this.#ai.hasKey()) {
				for (const c of (sources ?? []).slice(0, 5)) {
					try {
						list.push(await this.#ai.generateDigest(c, start, now, "auto"));
					} catch {
						/* 該聊天今天沒訊息等：略過 */
					}
				}
			}
			if (!list.length) {
				this.#outbox.audit.log("auto", "digest_schedule_skipped", { chatId: s.target_chat, ok: false, detail: { id: s.id, reason: "no_digest" } });
				continue;
			}
			try {
				this.post(
					list.map((d) => d.id),
					s.target_chat,
					"auto",
					{ detail: `schedule:${s.id}` },
				);
				n++;
			} catch (e) {
				this.#outbox.audit.log("auto", "digest_schedule_failed", { chatId: s.target_chat, ok: false, detail: { id: s.id, error: (e as Error).message.slice(0, 80) } });
			}
		}
		return n;
	}
}
