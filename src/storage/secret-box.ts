/**
 * 靜態加密（AES-256-GCM）：LINE auth token、E2EE 金鑰等秘密寫入 SQLite 前先加密。
 * 金鑰來源：
 *   - Android：Kotlin 產生 32-byte 資料金鑰，用 Android Keystore（AES-GCM，不可匯出）包起來存在 App 私有設定；
 *     啟動 Node 時解開，經環境變數 LMA_DATA_KEY（base64）傳入，Node 讀到記憶體後立即從環境變數刪除。不寫入磁碟。
 *   - 桌面 / 開發：LMA_PASSPHRASE（scrypt 衍生，salt 存在 DB；salt 不是秘密）。兩者都沒有 → 拒絕啟動（mock 模式除外）。
 * 格式："enc:v1:" + base64(iv[12] | tag[16] | ciphertext)；AAD = 欄位名稱（防止密文被搬到別的 key 底下）。
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync, createHash } from "node:crypto";

export const ENC_PREFIX = "enc:v1:";

export class SecretBox {
	#key: Buffer;
	constructor(key: Uint8Array) {
		if (key.byteLength !== 32) throw new Error("data key must be 32 bytes");
		this.#key = Buffer.from(key);
	}
	static fromBase64(b64: string): SecretBox {
		const k = Buffer.from(b64, "base64");
		if (k.byteLength !== 32) throw new Error("LMA_DATA_KEY must be 32 bytes (base64)");
		return new SecretBox(k);
	}
	static fromPassphrase(pass: string, salt: Buffer): SecretBox {
		if (pass.length < 12) throw new Error("passphrase must be at least 12 characters");
		return new SecretBox(scryptSync(pass.normalize("NFKC"), salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }));
	}
	/** 用來確認金鑰沒換錯（存在 DB 的是雜湊，不是金鑰本身） */
	fingerprint(): string {
		return createHash("sha256").update("lma-key-check").update(this.#key).digest("base64url").slice(0, 16);
	}
	seal(plain: string, aad: string): string {
		const iv = randomBytes(12);
		const c = createCipheriv("aes-256-gcm", this.#key, iv, { authTagLength: 16 });
		c.setAAD(Buffer.from(aad));
		const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
		return ENC_PREFIX + Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
	}
	open(sealed: string, aad: string): string {
		if (!sealed.startsWith(ENC_PREFIX)) throw new Error("not encrypted");
		const b = Buffer.from(sealed.slice(ENC_PREFIX.length), "base64");
		// iv(12) + tag(16) 至少 28 bytes；明確要求 16-byte tag（避免接受被截短的 GCM tag，CWE-310 / semgrep gcm-no-tag-length）
		if (b.byteLength < 28) throw new Error("invalid sealed value");
		const d = createDecipheriv("aes-256-gcm", this.#key, b.subarray(0, 12), { authTagLength: 16 });
		d.setAAD(Buffer.from(aad));
		d.setAuthTag(b.subarray(12, 28));
		return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
	}
}

export function isSealed(v: string): boolean {
	return v.startsWith(ENC_PREFIX);
}
