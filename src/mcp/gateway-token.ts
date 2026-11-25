/**
 * H-2：雲端連接器的「靜態 token」（給不能跑 OAuth 的用戶端，例如 xAI API remote MCP、Inspector）。
 *
 * - 預設關（connector_allow_static 不是 "on" 就不接受）
 * - 與本機 MCP token **分開**：專用 gateway token，`lmg_` 開頭；只存 SHA-256 雜湊，明文只在建立 / 輪替時回傳一次
 * - 預設只讀（line.read 工具）；送出權限另外開（connector_static_send，UI 要生物辨識），輪替時自動關回只讀
 * - 30 天到期；可輪替、撤銷；使用會寫稽核紀錄（每 10 分鐘最多一筆，含是否可寫）
 * 建議優先用 OAuth（有配對碼、可撤銷單一用戶端、scope 由使用者勾選）。
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Store } from "../storage/db.ts";
import type { Audit, Actor } from "../ai/audit.ts";

export const GATEWAY_TOKEN_TTL = 30 * 86_400_000;
const K = {
	hash: "connector_static_hash",
	created: "connector_static_created",
	expires: "connector_static_expires",
	send: "connector_static_send",
	lastUsed: "connector_static_last_used",
	lastAudit: "connector_static_last_audit",
} as const;

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export interface GatewayTokenStatus {
	exists: boolean;
	created_at: number | null;
	expires_at: number | null;
	expired: boolean;
	allow_send: boolean;
	last_used_at: number | null;
}

export class GatewayToken {
	#store: Store;
	#audit: Audit | null;
	#now: () => number;
	constructor(store: Store, audit: Audit | null = null, now: () => number = Date.now) {
		this.#store = store;
		this.#audit = audit;
		this.#now = now;
	}

	#num(k: string): number | null {
		const v = this.#store.getSetting(k);
		return v ? Number(v) : null;
	}

	status(): GatewayTokenStatus {
		const exp = this.#num(K.expires);
		return {
			exists: !!this.#store.getSetting(K.hash),
			created_at: this.#num(K.created),
			expires_at: exp,
			expired: exp != null && exp < this.#now(),
			allow_send: this.#store.getSetting(K.send) === "on",
			last_used_at: this.#num(K.lastUsed),
		};
	}

	/** 建立 / 輪替：舊的立即失效；送出權限回到關閉。回傳明文（只有這一次） */
	rotate(actor: Actor): { token: string; expires_at: number } {
		const token = "lmg_" + randomBytes(32).toString("base64url");
		const t = this.#now();
		this.#store.setSetting(K.hash, sha(token));
		this.#store.setSetting(K.created, String(t));
		this.#store.setSetting(K.expires, String(t + GATEWAY_TOKEN_TTL));
		this.#store.setSetting(K.send, "off");
		this.#store.setSetting(K.lastUsed, "");
		this.#audit?.log(actor, "connector_static_rotated", { detail: { expires_at: t + GATEWAY_TOKEN_TTL } });
		return { token, expires_at: t + GATEWAY_TOKEN_TTL };
	}

	revoke(actor: Actor): void {
		for (const k of [K.hash, K.created, K.expires, K.send, K.lastUsed]) this.#store.setSetting(k, "");
		this.#audit?.log(actor, "connector_static_revoked");
	}

	/** 送出權限（UI 需生物辨識後才呼叫）；只有已存在且未過期的 token 才能開 */
	setSend(on: boolean, actor: Actor): void {
		const st = this.status();
		if (on && (!st.exists || st.expired)) throw new Error("create a gateway token first");
		this.#store.setSetting(K.send, on ? "on" : "off");
		this.#audit?.log(actor, on ? "connector_static_send_on" : "connector_static_send_off");
	}

	/** Bearer 值 → 權限；不是 / 過期 / 未開啟回 null */
	verify(tok: string): { allowWrite: boolean } | null {
		if (this.#store.getSetting("connector_allow_static") !== "on") return null;
		const h = this.#store.getSetting(K.hash);
		if (!h || !tok.startsWith("lmg_")) return null;
		const a = Buffer.from(sha(tok));
		const b = Buffer.from(h);
		if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
		const st = this.status();
		if (st.expired) {
			this.#auditThrottled("connector_static_expired", false, st.allow_send);
			return null;
		}
		const t = this.#now();
		this.#store.setSetting(K.lastUsed, String(t));
		this.#auditThrottled("connector_static_used", true, st.allow_send);
		return { allowWrite: st.allow_send };
	}

	#auditThrottled(action: string, ok: boolean, write: boolean) {
		const t = this.#now();
		const last = this.#num(K.lastAudit) ?? 0;
		if (t - last < 10 * 60_000) return;
		this.#store.setSetting(K.lastAudit, String(t));
		this.#audit?.log("mcp", action, { ok, detail: { write } });
	}
}
