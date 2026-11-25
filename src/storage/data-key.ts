import { randomBytes } from "node:crypto";
import type { Store } from "./db.ts";
import { SecretBox } from "./secret-box.ts";
import { boxFromPassphrase, openSecretStore } from "./kv-storage.ts";

/**
 * 決定秘密儲存的金鑰。讀到後立即從 process.env 移除。
 *   LMA_DATA_KEY   Android：Keystore 解開的 32-byte 金鑰（base64）
 *   LMA_PASSPHRASE 桌面 / 開發：passphrase（≥12 字）
 *   mock 模式且兩者皆無：用一次性的隨機金鑰（mock DB 不含任何真實秘密）
 * 都沒有 → 丟出錯誤，呼叫端應拒絕啟動。
 */
export function resolveDataKey(store: Store, env: NodeJS.ProcessEnv, opts: { mock?: boolean } = {}): { box: SecretBox; migrated: number; source: "keystore" | "passphrase" | "ephemeral" } {
	const k = env.LMA_DATA_KEY;
	const p = env.LMA_PASSPHRASE;
	delete env.LMA_DATA_KEY;
	delete env.LMA_PASSPHRASE;
	let box: SecretBox;
	let source: "keystore" | "passphrase" | "ephemeral";
	if (k) {
		box = SecretBox.fromBase64(k);
		source = "keystore";
	} else if (p) {
		box = boxFromPassphrase(store, p);
		source = "passphrase";
	} else if (opts.mock) {
		store.setSetting("data_key_check", "");
		store.db.exec("DELETE FROM line_kv");
		box = new SecretBox(randomBytes(32));
		source = "ephemeral";
	} else {
		throw new Error("refusing to start: no data key. On Android the app provides LMA_DATA_KEY; for desktop/dev set LMA_PASSPHRASE (>= 12 chars).");
	}
	const migrated = openSecretStore(store, box);
	return { box, migrated, source };
}
