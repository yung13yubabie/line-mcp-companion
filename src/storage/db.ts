import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL, SCHEMA_VERSION } from "./schema.ts";

export type ChatType = "USER" | "GROUP" | "ROOM" | "SQUARE";

export interface ChatRow {
	id: string;
	type: ChatType;
	name: string | null;
	member_count: number | null;
	last_message_at: number | null;
	allowed: number;
	ai_mode: string;
	updated_at: number;
}

export interface MessageInput {
	chatId: string;
	id: string;
	senderMid?: string | null;
	fromSelf?: boolean;
	sentAt: number;
	contentType?: string;
	text?: string | null;
	mediaName?: string | null;
	mediaSize?: number | null;
	decryptState?: string;
	meta?: Record<string, unknown> | null;
}

export interface MessageRow {
	chat_id: string;
	id: string;
	sender_mid: string | null;
	sender_name: string | null;
	from_self: number;
	sent_at: number;
	content_type: string;
	text: string | null;
	media_name: string | null;
	media_size: number | null;
	decrypt_state: string;
}

/** 開啟（或建立）資料庫並套用 schema。path 可為 ":memory:"。 */
export function openDatabase(path: string): Store {
	if (path !== ":memory:") {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	}
	const db = new DatabaseSync(path);
	db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY;");
	db.exec(SCHEMA_SQL);
	db.prepare("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)").run(String(SCHEMA_VERSION));
	if (path !== ":memory:") {
		try {
			chmodSync(path, 0o600);
		} catch {
			/* Android 內部儲存本來就是 App 私有 */
		}
	}
	return new Store(db);
}

export class Store {
	readonly db: DatabaseSync;
	constructor(db: DatabaseSync) {
		this.db = db;
	}

	close(): void {
		this.db.close();
	}

	transaction<T>(fn: () => T): T {
		this.db.exec("BEGIN IMMEDIATE");
		try {
			const out = fn();
			this.db.exec("COMMIT");
			return out;
		} catch (e) {
			this.db.exec("ROLLBACK");
			throw e;
		}
	}

	// ---- settings / sync_state -------------------------------------------
	getSetting(key: string): string | undefined {
		const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined;
		return row?.value;
	}
	setSetting(key: string, value: string): void {
		this.db.prepare("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(key, value);
	}
	getSyncState(key: string): string | undefined {
		const row = this.db.prepare("SELECT value FROM sync_state WHERE key = ?").get(key) as { value: string } | undefined;
		return row?.value;
	}
	setSyncState(key: string, value: string): void {
		this.db.prepare("INSERT INTO sync_state(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(key, value);
	}
	allSyncState(): Record<string, string> {
		const rows = this.db.prepare("SELECT key, value FROM sync_state").all() as { key: string; value: string }[];
		return Object.fromEntries(rows.map((r) => [r.key, r.value]));
	}

	// ---- chats ----------------------------------------------------------
	upsertChat(c: { id: string; type: ChatType; name?: string | null; memberCount?: number | null; lastMessageAt?: number | null }): void {
		this.db
			.prepare(
				`INSERT INTO chat(id, type, name, member_count, last_message_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(id) DO UPDATE SET
				   type = excluded.type,
				   name = COALESCE(excluded.name, chat.name),
				   member_count = COALESCE(excluded.member_count, chat.member_count),
				   last_message_at = MAX(COALESCE(chat.last_message_at, 0), COALESCE(excluded.last_message_at, 0)),
				   updated_at = excluded.updated_at`,
			)
			.run(c.id, c.type, c.name ?? null, c.memberCount ?? null, c.lastMessageAt ?? null, Date.now());
	}
	getChat(id: string): ChatRow | undefined {
		return this.db.prepare("SELECT * FROM chat WHERE id = ?").get(id) as ChatRow | undefined;
	}
	listChats(opts: { allowedOnly?: boolean } = {}): ChatRow[] {
		const where = opts.allowedOnly ? "WHERE allowed = 1" : "";
		return this.db.prepare(`SELECT * FROM chat ${where} ORDER BY COALESCE(last_message_at, 0) DESC, id`).all() as unknown as ChatRow[];
	}
	setAllowed(id: string, allowed: boolean): boolean {
		const r = this.db.prepare("UPDATE chat SET allowed = ? WHERE id = ?").run(allowed ? 1 : 0, id);
		return Number(r.changes) > 0;
	}

	upsertParticipant(mid: string, displayName: string | null): void {
		this.db.prepare("INSERT INTO participant(mid, display_name) VALUES (?, ?) ON CONFLICT(mid) DO UPDATE SET display_name = COALESCE(excluded.display_name, participant.display_name)").run(mid, displayName);
	}

	// ---- messages -------------------------------------------------------
	/** 冪等寫入；回傳是否為新訊息。 */
	insertMessage(m: MessageInput): boolean {
		const r = this.db
			.prepare(
				`INSERT OR IGNORE INTO message(chat_id, id, sender_mid, from_self, sent_at, content_type, text, media_name, media_size, decrypt_state, meta_json)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				m.chatId,
				m.id,
				m.senderMid ?? null,
				m.fromSelf ? 1 : 0,
				m.sentAt,
				m.contentType ?? "NONE",
				m.text ?? null,
				m.mediaName ?? null,
				m.mediaSize ?? null,
				m.decryptState ?? "plain",
				m.meta ? JSON.stringify(m.meta) : null,
			);
		const inserted = Number(r.changes) > 0;
		if (inserted) {
			this.db.prepare("UPDATE chat SET last_message_at = MAX(COALESCE(last_message_at, 0), ?) WHERE id = ?").run(m.sentAt, m.chatId);
		}
		return inserted;
	}

	getMessage(chatId: string, id: string): (MessageRow & { meta_json: string | null }) | undefined {
		return this.db
			.prepare(
				`SELECT m.*, p.display_name AS sender_name FROM message m
				 LEFT JOIN participant p ON p.mid = m.sender_mid
				 WHERE m.chat_id = ? AND m.id = ?`,
			)
			.get(chatId, id) as (MessageRow & { meta_json: string | null }) | undefined;
	}

	/** 依時間倒序分頁；before/after 為 epoch ms。 */
	getMessages(chatId: string, opts: { limit?: number; before?: number; after?: number } = {}): MessageRow[] {
		const limit = clamp(opts.limit ?? 50, 1, 500);
		return this.db
			.prepare(
				`SELECT m.chat_id, m.id, m.sender_mid, p.display_name AS sender_name, m.from_self, m.sent_at,
				        m.content_type, m.text, m.media_name, m.media_size, m.decrypt_state
				 FROM message m LEFT JOIN participant p ON p.mid = m.sender_mid
				 WHERE m.chat_id = ? AND m.sent_at < ? AND m.sent_at > ?
				 ORDER BY m.sent_at DESC, m.id DESC LIMIT ?`,
			)
			.all(chatId, opts.before ?? Number.MAX_SAFE_INTEGER, opts.after ?? -1, limit) as unknown as MessageRow[];
	}

	/** 全文搜尋，只在 chatIds 範圍內（呼叫端負責傳入白名單）。 */
	searchMessages(query: string, chatIds: string[], limit = 50): MessageRow[] {
		if (chatIds.length === 0 || query.trim() === "") return [];
		const ph = chatIds.map(() => "?").join(",");
		const lim = clamp(limit, 1, 200);
		const cols = `m.chat_id, m.id, m.sender_mid, p.display_name AS sender_name, m.from_self, m.sent_at,
		              m.content_type, m.text, m.media_name, m.media_size, m.decrypt_state`;
		if ([...query].length >= 3) {
			const fts = '"' + query.replaceAll('"', '""') + '"';
			return this.db
				.prepare(
					`SELECT ${cols} FROM message_fts f JOIN message m ON m.rowid = f.rowid
					 LEFT JOIN participant p ON p.mid = m.sender_mid
					 WHERE message_fts MATCH ? AND m.chat_id IN (${ph})
					 ORDER BY m.sent_at DESC LIMIT ?`,
				)
				.all(fts, ...chatIds, lim) as unknown as MessageRow[];
		}
		return this.db
			.prepare(
				`SELECT ${cols} FROM message m LEFT JOIN participant p ON p.mid = m.sender_mid
				 WHERE instr(m.text, ?) > 0 AND m.chat_id IN (${ph})
				 ORDER BY m.sent_at DESC LIMIT ?`,
			)
			.all(query, ...chatIds, lim) as unknown as MessageRow[];
	}

	// ---- read state ------------------------------------------------------
	setReadState(chatId: string, lastReadMessageId: string | null, lastReadAt: number | null): void {
		this.db
			.prepare(
				`INSERT INTO read_state(chat_id, last_read_message_id, last_read_at) VALUES (?, ?, ?)
				 ON CONFLICT(chat_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id, last_read_at = excluded.last_read_at`,
			)
			.run(chatId, lastReadMessageId, lastReadAt);
	}

	/** 本機計算未讀：read_state 之後、非自己發的訊息。 */
	unreadSummary(chatIds: string[], perChat = 5): { chat_id: string; unread: number; latest: MessageRow[] }[] {
		const out: { chat_id: string; unread: number; latest: MessageRow[] }[] = [];
		for (const chatId of chatIds) {
			const rs = this.db.prepare("SELECT last_read_at FROM read_state WHERE chat_id = ?").get(chatId) as { last_read_at: number | null } | undefined;
			const since = rs?.last_read_at ?? -1;
			const cnt = this.db.prepare("SELECT COUNT(*) AS n FROM message WHERE chat_id = ? AND from_self = 0 AND sent_at > ?").get(chatId, since) as { n: number };
			if (Number(cnt.n) === 0) continue;
			out.push({ chat_id: chatId, unread: Number(cnt.n), latest: this.getMessages(chatId, { after: since, limit: perChat }) });
		}
		return out;
	}

	// ---- media -----------------------------------------------------------
	getMedia(chatId: string, messageId: string): { path: string; mime: string | null; size: number | null } | undefined {
		return this.db.prepare("SELECT path, mime, size FROM media WHERE chat_id = ? AND message_id = ?").get(chatId, messageId) as
			| { path: string; mime: string | null; size: number | null }
			| undefined;
	}
	putMedia(chatId: string, messageId: string, path: string, mime: string | null, size: number): void {
		this.db
			.prepare("INSERT OR REPLACE INTO media(chat_id, message_id, path, mime, size, downloaded_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(chatId, messageId, path, mime, size, Date.now());
	}

	counts(): { chats: number; allowed: number; messages: number } {
		const c = this.db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(allowed), 0) AS a FROM chat").get() as { n: number; a: number };
		const m = this.db.prepare("SELECT COUNT(*) AS n FROM message").get() as { n: number };
		return { chats: Number(c.n), allowed: Number(c.a), messages: Number(m.n) };
	}
}

function clamp(n: number, lo: number, hi: number): number {
	return Math.max(lo, Math.min(hi, Math.floor(n)));
}
