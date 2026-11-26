/**
 * 稽核紀錄：誰（ui / mcp / auto / system）對哪個會話做了什麼。
 * 規則：不寫入任何祕密（API key、token）；一般 audit 僅保留固定種類的 metadata；訊息與提示詞不寫入此表。
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
	stream?: "activity" | "security";
}

const SECRET_RE = /(sk-[A-Za-z0-9_\-]{8,}|xai-[A-Za-z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9._\-]{8,}|[a-f0-9]{40,})/g;

/** 去掉看起來像金鑰的字串並截斷 */
export function redact(s: string, max = 80): string {
	const r = s.replace(SECRET_RE, "[redacted]");
	return [...r].length > max ? [...r].slice(0, max).join("") + "…" : r;
}


// General audit is deliberately metadata-only. Free-form strings (including provider
// errors, client names, URLs, prompts and message excerpts) belong in neither stream.
const NUMBER_FIELDS = new Set(["id", "alert", "alert_id", "count", "n", "ms", "rows", "bytes", "items", "warnings", "sources", "completed_parts", "attempted_parts", "returned_to_pending", "cancelled", "rate_limited", "report_failures", "unauthorized", "forbidden", "replay", "expired", "invalid_request"]);
const BOOLEAN_FIELDS = new Set(["enabled", "edited", "approved_by_user", "ai_allowed", "confirm_send", "trusted", "deidentify", "vision", "image_gen", "voice", "on"]);
const ENUM_FIELDS: Record<string, ReadonlySet<string>> = {
 reason: new Set(["kill_switch", "ai_disabled", "chat_not_allowed", "ai_not_allowed", "mode_off", "image_not_allowed", "outside_active_hours", "rate_interval", "hourly_cap", "chat_daily_cap", "daily_cap", "no_digest", "port_in_use", "start_failed"]),
 kind: new Set(["text", "sticker", "image"]),
 origin: new Set(["mcp", "ui", "auto", "scam_warn"]),
 mode: new Set(["off", "review", "auto", "suggest"]),
 driver: new Set(["builtin", "external"]),
 route: new Set(["pending", "scheduled"]),
 state: new Set(["up", "down", "starting", "error", "stopped"]),
};

export function auditMetadata(value: unknown): string | null {
 if (!value || typeof value !== "object" || Array.isArray(value)) return null;
 const out: Record<string, unknown> = {};
 for (const key of [...NUMBER_FIELDS, ...BOOLEAN_FIELDS, ...Object.keys(ENUM_FIELDS)]) {
  if (!Object.hasOwn(value, key)) continue;
  const item = (value as Record<string, unknown>)[key];
  if (NUMBER_FIELDS.has(key) && typeof item === "number" && Number.isFinite(item)) out[key] = item;
  else if (BOOLEAN_FIELDS.has(key) && typeof item === "boolean") out[key] = item;
  else if (typeof item === "string" && ENUM_FIELDS[key]?.has(item)) out[key] = item;
 }
 // Authentication summaries contain one fixed, flat numeric map.
 const counts = (value as Record<string, unknown>).counts;
 if (counts && typeof counts === "object" && !Array.isArray(counts)) {
  const clean: Record<string, number> = {};
  for (const key of ["unauthorized", "forbidden", "replay", "expired", "invalid_request"]) {
   const n = (counts as Record<string, unknown>)[key];
   if (Object.hasOwn(counts, key) && typeof n === "number" && Number.isFinite(n)) clean[key] = n;
  }
  if (Object.keys(clean).length) out.counts = clean;
 }
 return Object.keys(out).length ? JSON.stringify(out) : null;
}

export class Audit {
	#store: Store;
	#keep: number;
	constructor(store: Store, keep = 5000) {
		this.#store = store;
		this.#keep = keep;
		// Unauthenticated traffic must never evict permission changes or send history.
		store.db.exec("CREATE TABLE IF NOT EXISTS security_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, chat_id TEXT, ok INTEGER NOT NULL DEFAULT 0, detail TEXT)");
        if (store.getSetting("audit_metadata_v1") !== "1") {
            store.db.exec("PRAGMA secure_delete = ON; BEGIN IMMEDIATE");
            try {
                for (const table of ["audit_log", "security_log"]) {
                    const update = store.db.prepare(`UPDATE ${table} SET detail = ? WHERE id = ?`);
                    for (const row of store.db.prepare(`SELECT id, detail FROM ${table} WHERE detail IS NOT NULL`).all()) {
                        let value: unknown;
                        try { value = JSON.parse(String(row.detail)); } catch { value = null; }
                        update.run(auditMetadata(value), row.id);
                    }
                }
                store.setSetting("audit_metadata_v1", "1");
                store.db.exec("COMMIT");
            } catch (error) { store.db.exec("ROLLBACK"); throw error; }
        }
        // Also retry truncation after a prior busy checkpoint or interrupted startup.
        store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	}

	/** Aggregated authentication events have a separate, bounded 500-row retention ring. */
	logSecurity(actor: Actor, action: string, detail: Record<string, unknown>): void {
		const r = this.#store.db.prepare("INSERT INTO security_log(ts, actor, action, ok, detail) VALUES (?, ?, ?, 0, ?)")
			.run(Date.now(), actor, action, auditMetadata(detail));
		this.#store.db.prepare("DELETE FROM security_log WHERE id <= ?").run(Number(r.lastInsertRowid) - 500);
	}

	securityRecent(limit = 50): AuditEntry[] {
		return this.#store.db.prepare("SELECT *, 'security' AS stream FROM security_log ORDER BY id DESC LIMIT ?")
			.all(Math.max(1, Math.min(500, limit))) as unknown as AuditEntry[];
	}

	log(actor: Actor, action: string, opts: { chatId?: string | null; ok?: boolean; detail?: Record<string, unknown> | string } = {}): void {
		const detail = auditMetadata(opts.detail);
		const r = this.#store.db
			.prepare("INSERT INTO audit_log(ts, actor, action, chat_id, ok, detail) VALUES (?, ?, ?, ?, ?, ?)")
			.run(Date.now(), actor, action, opts.chatId ?? null, opts.ok === false ? 0 : 1, detail);
		const id = Number(r.lastInsertRowid);
		if (id % 200 === 0) this.#store.db.prepare("DELETE FROM audit_log WHERE id <= ?").run(id - this.#keep);
	}

	recent(opts: { limit?: number; actor?: Actor; sinceTs?: number; includeSecurity?: boolean } = {}): AuditEntry[] {
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
		const source = opts.includeSecurity
			? "(SELECT *, 'activity' AS stream FROM audit_log UNION ALL SELECT *, 'security' AS stream FROM security_log)"
			: "audit_log";
		return this.#store.db.prepare(`SELECT * FROM ${source} ${w} ORDER BY ${opts.includeSecurity ? "ts DESC, " : ""}id DESC LIMIT ?`).all(...args, lim) as unknown as AuditEntry[];
	}
}
