import { BaseStorage } from "@evex-dev/linejs/storage";
import { randomBytes } from "node:crypto";
import type { Store } from "./db.ts";
import { SecretBox, isSealed } from "./secret-box.ts";

type Value = string | number | boolean | null | Record<string | number, unknown>;

const enc = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x));
const dec = (s: string) => JSON.parse(s, (_k, v) => (v && typeof v === "object" && "$bigint" in v ? BigInt(v.$bigint) : v));

/**
 * LINEJS 的 BaseStorage 實作，存在同一個 SQLite（line_kv 表）。
 * line_kv 裡是 auth token、E2EE 私鑰等秘密 → 一律以 SecretBox（AES-256-GCM）加密後才寫入。
 * 同步寫入：LINEJS 從 response header 發出新 token 時不會 await handler。
 */
export class SqliteKvStorage extends BaseStorage {
	#store: Store;
	#box: SecretBox;
	constructor(store: Store, box: SecretBox) {
		super();
		this.#store = store;
		this.#box = box;
	}
	setSync(key: string, value: unknown): void {
		this.#store.db
			.prepare("INSERT INTO line_kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
			.run(key, this.#box.seal(enc(value), `line_kv:${key}`));
	}
	getSync(key: string): unknown {
		const row = this.#store.db.prepare("SELECT value FROM line_kv WHERE key = ?").get(key) as { value: string } | undefined;
		if (!row) return undefined;
		return dec(this.#box.open(row.value, `line_kv:${key}`));
	}
	async set(key: string, value: Value): Promise<void> {
		this.setSync(key, value);
	}
	async get(key: string): Promise<Value | undefined> {
		return this.getSync(key) as Value | undefined;
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

/**
 * 開啟秘密儲存：
 *  1. 確認金鑰跟 DB 對得上（settings.data_key_check 存金鑰指紋）；換錯金鑰直接拒絕，不會把資料蓋掉
 *  2. 把舊版明文 line_kv 列加密改寫，並用 secure_delete + VACUUM + WAL checkpoint 把舊明文從檔案裡清掉
 * 回傳遷移的列數。
 */
export function openSecretStore(store: Store, box: SecretBox): number {
	const check = store.getSetting("data_key_check");
	const fp = box.fingerprint();
	if (check && check !== fp) throw new Error("data key does not match this database (wrong key or passphrase)");
	if (!check) store.setSetting("data_key_check", fp);
	const plain = (store.db.prepare("SELECT key, value FROM line_kv").all() as { key: string; value: string }[]).filter((r) => !isSealed(r.value));
	if (!plain.length) return 0;
	store.db.exec("PRAGMA secure_delete = ON");
	store.transaction(() => {
		const up = store.db.prepare("UPDATE line_kv SET value = ? WHERE key = ?");
		for (const r of plain) up.run(box.seal(r.value, `line_kv:${r.key}`), r.key);
	});
	store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	store.db.exec("VACUUM");
	store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	return plain.length;
}

/** 桌面模式：用 passphrase 衍生金鑰（salt 存在 settings，不是秘密） */
export function boxFromPassphrase(store: Store, pass: string): SecretBox {
	let salt = store.getSetting("data_key_salt");
	if (!salt) {
		salt = randomBytes(16).toString("base64");
		store.setSetting("data_key_salt", salt);
	}
	return SecretBox.fromPassphrase(pass, Buffer.from(salt, "base64"));
}
