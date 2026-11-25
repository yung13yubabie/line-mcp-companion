/**
 * 反詐紀錄 + AI 代聊紀錄。人名與訊息內容用 SecretBox（AES-256-GCM，與 line_kv 同一把資料金鑰）加密後才寫入 SQLite。
 * 保留天數可設定（預設 30 天，1–365），可一鍵清除。
 */
import type { Store } from "./db.ts";
import type { SecretBox } from "./secret-box.ts";

export type ScamAction =
	| "alert_only" // 偵測到但該群沒開即時提醒
	| "queued" // 進確認佇列（review）
	| "scheduled" // 直接排程（auto）
	| "sent"
	| "rejected"
	| "suppressed_member" // 信任成員，不提醒
	| "cooldown"
	| "daily_cap"
	| "below_min_level"
	| "already_warned"
	| "blocked"
	| "false_positive"
	| "custom" // 使用者 / 連接器自訂的提醒
	| "error";

export interface ScamLogRow {
	id: number;
	ts: number;
	chat_id: string;
	chat_name: string | null;
	message_id: string;
	sender_mid: string | null;
	sender_name: string | null;
	text: string | null;
	level: string | null;
	score: number | null;
	category: string | null;
	rules: string[];
	action: ScamAction;
	detail: string | null;
	alert_id: number | null;
	outbox_id: number | null;
}

export type AiEvent = "generated" | "edited" | "approved" | "rejected" | "sent" | "failed" | "expired" | "blocked";

export interface AiLogRow {
	id: number;
	ts: number;
	chat_id: string;
	chat_name: string | null;
	outbox_id: number | null;
	origin: string;
	event: AiEvent;
	actor: string;
	trigger_msg_id: string | null;
	trigger_sender: string | null;
	trigger_text: string | null;
	text: string | null;
	detail: string | null;
}

export interface LogFilter {
	chatId?: string;
	since?: number;
	until?: number;
	limit?: number;
	/** 只回白名單會話（MCP 用） */
	allowedOnly?: boolean;
}

const MAX_SNAPSHOT = 1000;

export class EventLog {
	#store: Store;
	#box: SecretBox;
	constructor(store: Store, box: SecretBox) {
		this.#store = store;
		this.#box = box;
	}

	#seal(v: string | null | undefined, aad: string): string | null {
		if (v == null || v === "") return null;
		return this.#box.seal(String(v).slice(0, MAX_SNAPSHOT), aad);
	}
	#open(v: unknown, aad: string): string | null {
		if (v == null) return null;
		try {
			return this.#box.open(String(v), aad);
		} catch {
			return "（無法解密）";
		}
	}

	// ---- 反詐 ----------------------------------------------------------------
	scam(e: {
		chat_id: string;
		message_id: string;
		sender_mid?: string | null;
		sender_name?: string | null;
		text?: string | null;
		level?: string | null;
		score?: number | null;
		category?: string | null;
		rules?: string[];
		action: ScamAction;
		detail?: string | null;
		alert_id?: number | null;
	}): number {
		const aad = `scam_log:${e.chat_id}:${e.message_id}`;
		const r = this.#store.db
			.prepare(
				`INSERT INTO scam_log(ts, chat_id, message_id, sender_mid, sender_name, text, level, score, category, rules, action, detail, alert_id)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				Date.now(),
				e.chat_id,
				e.message_id,
				e.sender_mid ?? null,
				this.#seal(e.sender_name, aad + ":name"),
				this.#seal(e.text, aad + ":text"),
				e.level ?? null,
				e.score ?? null,
				e.category ?? null,
				JSON.stringify(e.rules ?? []),
				e.action,
				e.detail ? String(e.detail).slice(0, 120) : null,
				e.alert_id ?? null,
			);
		return Number(r.lastInsertRowid);
	}

	/** 依警示或佇列項目更新最新動作 */
	setScamAction(by: { alertId?: number; outboxId?: number }, action: ScamAction, detail?: string | null, outboxId?: number): void {
		const set = "action = ?, detail = COALESCE(?, detail)" + (outboxId != null ? ", outbox_id = " + Number(outboxId) : "");
		if (by.alertId != null) this.#store.db.prepare(`UPDATE scam_log SET ${set} WHERE alert_id = ?`).run(action, detail ?? null, by.alertId);
		else if (by.outboxId != null) this.#store.db.prepare(`UPDATE scam_log SET ${set} WHERE outbox_id = ?`).run(action, detail ?? null, by.outboxId);
	}

	scamList(f: LogFilter & { action?: string; category?: string } = {}): ScamLogRow[] {
		const w: string[] = [];
		const a: (string | number)[] = [];
		this.#where(f, w, a, "l");
		if (f.action) {
			w.push("l.action = ?");
			a.push(f.action);
		}
		if (f.category) {
			w.push("l.category = ?");
			a.push(f.category);
		}
		const rows = this.#store.db
			.prepare(`SELECT l.*, c.name AS chat_name FROM scam_log l LEFT JOIN chat c ON c.id = l.chat_id ${w.length ? "WHERE " + w.join(" AND ") : ""} ORDER BY l.id DESC LIMIT ?`)
			.all(...a, Math.max(1, Math.min(2000, f.limit ?? 200))) as Record<string, unknown>[];
		return rows.map((r) => {
			const aad = `scam_log:${r.chat_id}:${r.message_id}`;
			return {
				...(r as unknown as ScamLogRow),
				sender_name: this.#open(r.sender_name, aad + ":name"),
				text: this.#open(r.text, aad + ":text"),
				rules: JSON.parse(String(r.rules ?? "[]")) as string[],
			};
		});
	}

	// ---- AI 代聊 --------------------------------------------------------------
	ai(e: {
		chat_id: string;
		outbox_id?: number | null;
		origin: string;
		event: AiEvent;
		actor: string;
		trigger_msg_id?: string | null;
		trigger_sender?: string | null;
		trigger_text?: string | null;
		text?: string | null;
		detail?: string | null;
	}): number {
		const aad = `ai_log:${e.chat_id}`;
		const r = this.#store.db
			.prepare(
				`INSERT INTO ai_log(ts, chat_id, outbox_id, origin, event, actor, trigger_msg_id, trigger_sender, trigger_text, text, detail)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				Date.now(),
				e.chat_id,
				e.outbox_id ?? null,
				e.origin,
				e.event,
				e.actor,
				e.trigger_msg_id ?? null,
				this.#seal(e.trigger_sender, aad + ":who"),
				this.#seal(e.trigger_text, aad + ":trigger"),
				this.#seal(e.text, aad + ":text"),
				e.detail ? String(e.detail).slice(0, 120) : null,
			);
		return Number(r.lastInsertRowid);
	}

	aiList(f: LogFilter & { event?: string; outboxId?: number } = {}): AiLogRow[] {
		const w: string[] = [];
		const a: (string | number)[] = [];
		this.#where(f, w, a, "l");
		if (f.event) {
			w.push("l.event = ?");
			a.push(f.event);
		}
		if (f.outboxId != null) {
			w.push("l.outbox_id = ?");
			a.push(f.outboxId);
		}
		const rows = this.#store.db
			.prepare(`SELECT l.*, c.name AS chat_name FROM ai_log l LEFT JOIN chat c ON c.id = l.chat_id ${w.length ? "WHERE " + w.join(" AND ") : ""} ORDER BY l.id DESC LIMIT ?`)
			.all(...a, Math.max(1, Math.min(2000, f.limit ?? 200))) as Record<string, unknown>[];
		return rows.map((r) => {
			const aad = `ai_log:${r.chat_id}`;
			return {
				...(r as unknown as AiLogRow),
				trigger_sender: this.#open(r.trigger_sender, aad + ":who"),
				trigger_text: this.#open(r.trigger_text, aad + ":trigger"),
				text: this.#open(r.text, aad + ":text"),
			};
		});
	}

	#where(f: LogFilter, w: string[], a: (string | number)[], t: string): void {
		if (f.allowedOnly) w.push("c.allowed = 1");
		if (f.chatId) {
			w.push(`${t}.chat_id = ?`);
			a.push(f.chatId);
		}
		if (f.since) {
			w.push(`${t}.ts >= ?`);
			a.push(f.since);
		}
		if (f.until) {
			w.push(`${t}.ts < ?`);
			a.push(f.until);
		}
	}

	// ---- 保留 / 清除 ----------------------------------------------------------
	get retentionDays(): number {
		const n = Number(this.#store.getSetting("log_retention_days"));
		return Number.isFinite(n) && n >= 1 ? Math.min(365, Math.floor(n)) : 30;
	}
	setRetentionDays(n: number): number {
		const v = Math.max(1, Math.min(365, Math.floor(Number(n) || 30)));
		this.#store.setSetting("log_retention_days", String(v));
		this.prune();
		return v;
	}
	prune(now = Date.now()): number {
		const cut = now - this.retentionDays * 86_400_000;
		const a = this.#store.db.prepare("DELETE FROM scam_log WHERE ts < ?").run(cut).changes;
		const b = this.#store.db.prepare("DELETE FROM ai_log WHERE ts < ?").run(cut).changes;
		return Number(a) + Number(b);
	}
	clear(kind: "scam" | "ai" | "all"): number {
		let n = 0;
		this.#store.db.exec("PRAGMA secure_delete = ON");
		if (kind === "scam" || kind === "all") n += Number(this.#store.db.prepare("DELETE FROM scam_log").run().changes);
		if (kind === "ai" || kind === "all") n += Number(this.#store.db.prepare("DELETE FROM ai_log").run().changes);
		// secure_delete 已開：刪掉的頁面會被覆寫
		this.#store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		return n;
	}
}

/** CSV（UTF-8 BOM 讓 Excel 正確顯示中文） */
export function toCsv(rows: Record<string, unknown>[], cols: string[]): string {
	const esc = (v: unknown) => {
		let s = v == null ? "" : Array.isArray(v) ? v.join("|") : String(v);
		// 防 CSV 公式注入
		if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
		return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
	};
	const lines = [cols.join(",")];
	for (const r of rows) lines.push(cols.map((c) => esc(c === "ts" ? new Date(Number(r.ts)).toISOString() : r[c])).join(","));
	return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

export const SCAM_CSV_COLS = ["ts", "chat_name", "chat_id", "sender_name", "sender_mid", "message_id", "text", "level", "score", "category", "rules", "action", "detail"];
export const AI_CSV_COLS = ["ts", "chat_name", "chat_id", "origin", "event", "actor", "trigger_sender", "trigger_text", "text", "detail", "outbox_id"];
