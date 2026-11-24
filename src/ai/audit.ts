/**
 * 稽核紀錄：誰（ui / mcp / auto / system）對哪個會話做了什麼。
 * 規則：不寫入任何祕密（API key、token）；訊息內容最多保留 80 字。
 */
import type { Store } from "../storage/db.ts";

export type Actor = "ui" | "mcp" | "auto" | "system";

export interface AuditEntry {
	id: number;
	ts: number;
	actor: Actor;
	action: string;
	chat_id: string | null;
	ok: number;
	detail: string | null;
}

const SECRET_RE = /(sk-[A-Za-z0-9_\-]{8,}|xai-[A-Za-z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9._\-]{8,}|[a-f0-9]{40,})/g;

/** 去掉看起來像金鑰的字串並截斷 */
export function redact(s: string, max = 80): string {
	const r = s.replace(SECRET_RE, "[redacted]");
	return [...r].length > max ? [...r].slice(0, max).join("") + "…" : r;
}

export class Audit {
	#store: Store;
	#keep: number;
	constructor(store: Store, keep = 5000) {
		this.#store = store;
		this.#keep = keep;
	}

	log(actor: Actor, action: string, opts: { chatId?: string | null; ok?: boolean; detail?: Record<string, unknown> | string } = {}): void {
		let detail: string | null = null;
		if (opts.detail !== undefined) {
			const raw = typeof opts.detail === "string" ? opts.detail : JSON.stringify(opts.detail);
			detail = redact(raw, 400);
		}
		const r = this.#store.db
			.prepare("INSERT INTO audit_log(ts, actor, action, chat_id, ok, detail) VALUES (?, ?, ?, ?, ?, ?)")
			.run(Date.now(), actor, action, opts.chatId ?? null, opts.ok === false ? 0 : 1, detail);
		const id = Number(r.lastInsertRowid);
		if (id % 200 === 0) this.#store.db.prepare("DELETE FROM audit_log WHERE id <= ?").run(id - this.#keep);
	}

	recent(opts: { limit?: number; actor?: Actor; sinceTs?: number } = {}): AuditEntry[] {
		const lim = Math.max(1, Math.min(500, opts.limit ?? 50));
		const where: string[] = [];
		const args: (string | number)[] = [];
		if (opts.actor) {
			where.push("actor = ?");
			args.push(opts.actor);
		}
		if (opts.sinceTs) {
			where.push("ts >= ?");
			args.push(opts.sinceTs);
		}
		const w = where.length ? `WHERE ${where.join(" AND ")}` : "";
		return this.#store.db.prepare(`SELECT * FROM audit_log ${w} ORDER BY id DESC LIMIT ?`).all(...args, lim) as unknown as AuditEntry[];
	}
}
