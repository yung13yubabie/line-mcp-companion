import { BaseStorage } from "@evex-dev/linejs/storage";
import type { Store } from "./db.ts";

type Value = string | number | boolean | null | Record<string | number, unknown>;

/**
 * LINEJS 的 BaseStorage 實作，存在同一個 SQLite（line_kv 表）。
 * 同步寫入：LINEJS 從 response header 發出新 token 時不會 await handler。
 */
export class SqliteKvStorage extends BaseStorage {
	#store: Store;
	constructor(store: Store) {
		super();
		this.#store = store;
	}
	async set(key: string, value: Value): Promise<void> {
		this.#store.db
			.prepare("INSERT INTO line_kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
			.run(key, JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? { $bigint: v.toString() } : v)));
	}
	async get(key: string): Promise<Value | undefined> {
		const row = this.#store.db.prepare("SELECT value FROM line_kv WHERE key = ?").get(key) as { value: string } | undefined;
		if (!row) return undefined;
		return JSON.parse(row.value, (_k, v) => (v && typeof v === "object" && "$bigint" in v ? BigInt(v.$bigint) : v));
	}
	async delete(key: string): Promise<void> {
		this.#store.db.prepare("DELETE FROM line_kv WHERE key = ?").run(key);
	}
	async clear(): Promise<void> {
		this.#store.db.exec("DELETE FROM line_kv");
	}
	async migrate(storage: BaseStorage): Promise<void> {
		const rows = this.#store.db.prepare("SELECT key FROM line_kv").all() as { key: string }[];
		for (const { key } of rows) {
			const v = await this.get(key);
			if (v !== undefined) await storage.set(key, v as never);
		}
	}
}
