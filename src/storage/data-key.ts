import type { Store } from "./db.ts";
import { SecretBox } from "./secret-box.ts";
import { boxFromPassphrase, openSecretStore } from "./kv-storage.ts";

/**
 * 決定秘密儲存的金鑰。讀到後立即從 process.env 移除。
 *   LMA_DATA_KEY   Android：Keystore 解開的 32-byte 金鑰（base64）
 *   LMA_PASSPHRASE 桌面 / 開發：passphrase（≥12 字）
 * 都沒有 → 丟出錯誤，呼叫端應拒絕啟動。
 */
export interface DataKeyResolution { box: SecretBox; migrated: number; source: "keystore" | "passphrase" | "ephemeral" }

export function resolveDataKey(store: Store, env: NodeJS.ProcessEnv): DataKeyResolution {
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
	} else {
		throw new Error("refusing to start: no data key. On Android the app provides LMA_DATA_KEY; for desktop/dev set LMA_PASSPHRASE (>= 12 chars).");
	}
	const migrated = openSecretStore(store, box);
	return { box, migrated, source };
}
