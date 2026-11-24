/**
 * AI 發送權限與限制（階段 5）。所有「會從使用者帳號送出訊息」的路徑都必須經過 checkSend()。
 *
 * 安全預設：
 *   - 全域 ai_enabled 預設關、kill_switch 可一鍵停止所有 AI 發送
 *   - 只對白名單會話生效；沒有 chat_ai 資料列 = mode off
 *   - 發送前確認預設開；圖片預設不允許
 *   - 全域每日上限（預設 20）、每會話每日 / 每小時上限、最短間隔、活躍時段
 */
import type { Store } from "../storage/db.ts";
import { ChatNotAllowedError } from "../whitelist.ts";

export type AiMode = "off" | "suggest" | "auto";
export type SendKind = "text" | "image" | "sticker";

export interface ChatAiConfig {
	chat_id: string;
	/** AI 代聊白名單（與 MCP 存取白名單分開，兩者都要勾才會生效） */
	ai_allowed: boolean;
	mode: AiMode;
	/** 去 AI 味（Lieflat Less AI Tone 規則）檢查 / 改寫 */
	style_lieflat: boolean;
	allow_image: boolean;
	confirm_send: boolean;
	min_interval_sec: number;
	delay_sec: number;
	max_per_hour: number;
	max_per_day: number;
	active_start: number | null; // 當地分鐘 0-1439
	active_end: number | null;
}

export const DEFAULT_CHAT_AI: Omit<ChatAiConfig, "chat_id"> = {
	ai_allowed: false,
	mode: "off",
	style_lieflat: true,
	allow_image: false,
	confirm_send: true,
	min_interval_sec: 300,
	delay_sec: 30,
	max_per_hour: 4,
	max_per_day: 10,
	active_start: null,
	active_end: null,
};

export const DEFAULT_DAILY_CAP = 20;

export type DenyReason =
	| "kill_switch"
	| "ai_disabled"
	| "chat_not_allowed"
	| "ai_not_allowed"
	| "mode_off"
	| "image_not_allowed"
	| "outside_active_hours"
	| "rate_interval"
	| "hourly_cap"
	| "chat_daily_cap"
	| "daily_cap";

export class PermissionDeniedError extends Error {
	readonly code: string;
	readonly reason: DenyReason;
	constructor(reason: DenyReason) {
		super(`permission denied: ${reason}`);
		this.reason = reason;
		this.code = `permission_denied:${reason}`;
	}
}

export interface Clock {
	now(): number;
	/** 當地時間的「當天第幾分鐘」 */
	minuteOfDay(ts: number): number;
	/** 當地當天 00:00 的 epoch ms */
	startOfDay(ts: number): number;
}

export const systemClock: Clock = {
	now: () => Date.now(),
	minuteOfDay: (ts) => {
		const d = new Date(ts);
		return d.getHours() * 60 + d.getMinutes();
	},
	startOfDay: (ts) => {
		const d = new Date(ts);
		d.setHours(0, 0, 0, 0);
		return d.getTime();
	},
};

/** 活躍時段判斷；支援跨午夜（例如 22:00–07:00）。start=end 或任一為 null = 不限。 */
export function inActiveHours(minute: number, start: number | null, end: number | null): boolean {
	if (start === null || end === null || start === end) return true;
	return start < end ? minute >= start && minute < end : minute >= start || minute < end;
}

const int = (v: unknown, lo: number, hi: number, dflt: number) => {
	const n = Number(v);
	return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.floor(n))) : dflt;
};

export class AiPolicy {
	readonly store: Store;
	readonly clock: Clock;
	constructor(store: Store, clock: Clock = systemClock) {
		this.store = store;
		this.clock = clock;
	}

	// ---- 全域 -------------------------------------------------------------
	get killSwitch(): boolean {
		return this.store.getSetting("ai_kill_switch") === "on";
	}
	setKillSwitch(on: boolean): void {
		this.store.setSetting("ai_kill_switch", on ? "on" : "off");
	}
	get aiEnabled(): boolean {
		return this.store.getSetting("ai_enabled") === "on";
	}
	setAiEnabled(on: boolean): void {
		this.store.setSetting("ai_enabled", on ? "on" : "off");
	}
	get dailyCap(): number {
		return int(this.store.getSetting("ai_daily_cap"), 0, 500, DEFAULT_DAILY_CAP);
	}
	setDailyCap(n: number): void {
		this.store.setSetting("ai_daily_cap", String(int(n, 0, 500, DEFAULT_DAILY_CAP)));
	}

	// ---- 每會話設定 --------------------------------------------------------
	get(chatId: string): ChatAiConfig {
		const r = this.store.db.prepare("SELECT * FROM chat_ai WHERE chat_id = ?").get(chatId) as Record<string, unknown> | undefined;
		if (!r) return { chat_id: chatId, ...DEFAULT_CHAT_AI };
		return {
			chat_id: chatId,
			ai_allowed: r.ai_allowed === 1,
			style_lieflat: r.style_lieflat !== 0,
			mode: (["off", "suggest", "auto"].includes(String(r.mode)) ? r.mode : "off") as AiMode,
			allow_image: r.allow_image === 1,
			confirm_send: r.confirm_send !== 0,
			min_interval_sec: Number(r.min_interval_sec),
			delay_sec: Number(r.delay_sec),
			max_per_hour: Number(r.max_per_hour),
			max_per_day: Number(r.max_per_day),
			active_start: r.active_start === null ? null : Number(r.active_start),
			active_end: r.active_end === null ? null : Number(r.active_end),
		};
	}

	/** 只允許白名單會話設定 AI；值會被夾在安全範圍內。 */
	set(chatId: string, patch: Partial<Omit<ChatAiConfig, "chat_id">>): ChatAiConfig {
		const chat = this.store.getChat(chatId);
		if (!chat || chat.allowed !== 1) throw new ChatNotAllowedError();
		const c = { ...this.get(chatId), ...patch };
		const mode: AiMode = ["off", "suggest", "auto"].includes(c.mode) ? c.mode : "off";
		const minute = (v: unknown) => (v === null || v === undefined || v === "" ? null : int(v, 0, 1439, 0));
		this.store.db
			.prepare(
				`INSERT INTO chat_ai(chat_id, ai_allowed, mode, style_lieflat, allow_image, confirm_send, min_interval_sec, delay_sec, max_per_hour, max_per_day, active_start, active_end, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(chat_id) DO UPDATE SET ai_allowed=excluded.ai_allowed, mode=excluded.mode, style_lieflat=excluded.style_lieflat, allow_image=excluded.allow_image, confirm_send=excluded.confirm_send,
				   min_interval_sec=excluded.min_interval_sec, delay_sec=excluded.delay_sec, max_per_hour=excluded.max_per_hour,
				   max_per_day=excluded.max_per_day, active_start=excluded.active_start, active_end=excluded.active_end, updated_at=excluded.updated_at`,
			)
			.run(
				chatId,
				c.ai_allowed ? 1 : 0,
				mode,
				c.style_lieflat === false ? 0 : 1,
				c.allow_image ? 1 : 0,
				c.confirm_send === false ? 0 : 1,
				int(c.min_interval_sec, 10, 86_400, 300),
				int(c.delay_sec, 0, 3_600, 30),
				int(c.max_per_hour, 0, 60, 4),
				int(c.max_per_day, 0, 200, 10),
				minute(c.active_start),
				minute(c.active_end),
				this.clock.now(),
			);
		return this.get(chatId);
	}

	/** 白名單內、mode != off 的會話 AI 設定一覽（取消白名單的會話自動視為 off）。 */
	overview(): (ChatAiConfig & { name: string | null; allowed: boolean; sent_today: number })[] {
		const rows = this.store.db.prepare("SELECT c.id, c.name, c.allowed FROM chat c WHERE c.allowed = 1 ORDER BY COALESCE(c.last_message_at,0) DESC").all() as {
			id: string;
			name: string | null;
			allowed: number;
		}[];
		return rows.map((r) => ({ ...this.get(r.id), name: r.name, allowed: true, sent_today: this.sentSince(this.clock.startOfDay(this.clock.now()), r.id) }));
	}

	// ---- 計數 -------------------------------------------------------------
	sentSince(ts: number, chatId?: string): number {
		const row = chatId
			? (this.store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE status='sent' AND sent_at >= ? AND chat_id = ?").get(ts, chatId) as { n: number })
			: (this.store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE status='sent' AND sent_at >= ?").get(ts) as { n: number });
		return Number(row.n);
	}
	lastSentAt(chatId: string): number | null {
		const r = this.store.db.prepare("SELECT MAX(sent_at) AS t FROM outbox WHERE status='sent' AND chat_id = ?").get(chatId) as { t: number | null };
		return r.t === null ? null : Number(r.t);
	}
	counters(): { sent_today: number; daily_cap: number } {
		return { sent_today: this.sentSince(this.clock.startOfDay(this.clock.now())), daily_cap: this.dailyCap };
	}

	/**
	 * 基本閘門（排入佇列前就要通過）：kill switch、全域開關、白名單、mode、圖片權限。
	 * 白名單失敗一律丟 ChatNotAllowedError（與讀取工具相同，不洩漏會話是否存在）。
	 */
	checkBasic(chatId: string, kind: SendKind): { ok: true; cfg: ChatAiConfig } | { ok: false; reason: DenyReason } {
		if (this.killSwitch) return { ok: false, reason: "kill_switch" };
		if (!this.aiEnabled) return { ok: false, reason: "ai_disabled" };
		const chat = this.store.getChat(chatId);
		if (!chat || chat.allowed !== 1) return { ok: false, reason: "chat_not_allowed" };
		const cfg = this.get(chatId);
		if (!cfg.ai_allowed) return { ok: false, reason: "ai_not_allowed" };
		if (cfg.mode === "off") return { ok: false, reason: "mode_off" };
		if (kind === "image" && !cfg.allow_image) return { ok: false, reason: "image_not_allowed" };
		return { ok: true, cfg };
	}

	/**
	 * 實際送出前的完整檢查。approvedByUser=true（使用者在佇列按核准）時略過活躍時段、間隔與每小時上限，
	 * 但 kill switch、白名單、mode、圖片權限與「每日上限」永遠生效。
	 */
	checkSend(chatId: string, kind: SendKind, opts: { approvedByUser?: boolean } = {}): { ok: true } | { ok: false; reason: DenyReason } {
		const b = this.checkBasic(chatId, kind);
		if (!b.ok) return b;
		const cfg = b.cfg;
		const now = this.clock.now();
		if (!opts.approvedByUser) {
			if (!inActiveHours(this.clock.minuteOfDay(now), cfg.active_start, cfg.active_end)) return { ok: false, reason: "outside_active_hours" };
			const last = this.lastSentAt(chatId);
			if (last !== null && now - last < cfg.min_interval_sec * 1000) return { ok: false, reason: "rate_interval" };
			if (this.sentSince(now - 3_600_000, chatId) >= cfg.max_per_hour) return { ok: false, reason: "hourly_cap" };
		}
		const sod = this.clock.startOfDay(now);
		if (this.sentSince(sod, chatId) >= cfg.max_per_day) return { ok: false, reason: "chat_daily_cap" };
		if (this.sentSince(sod) >= this.dailyCap) return { ok: false, reason: "daily_cap" };
		return { ok: true };
	}

	/** 要不要先進確認佇列（而不是自動送）。 */
	needsConfirmation(cfg: ChatAiConfig, flags: string[]): boolean {
		return cfg.mode !== "auto" || cfg.confirm_send || flags.length > 0;
	}
}

/** 把 DenyReason 轉成例外（白名單用 ChatNotAllowedError） */
export function denyError(reason: DenyReason): Error {
	return reason === "chat_not_allowed" ? new ChatNotAllowedError() : new PermissionDeniedError(reason);
}
