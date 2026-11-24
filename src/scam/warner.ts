/**
 * 反詐即時提醒：本機規則偵測到詐騙 / 換群時，立刻以「引用回覆」在群組發一則提醒（不需要 AI）。
 *   - 每群組開關，預設關；使用者開啟後不進確認佇列
 *   - 同一發送者＋同類型冷卻（預設 30 分）、同一則只提醒一次、每群每日上限（預設 10）
 *   - kill switch、MCP 白名單仍然生效；全部寫入稽核紀錄
 * 範本改作自 mars-tw/anti-scam-helper（Apache-2.0）guard/notice.mjs 與 guard.mjs 的提醒文字：
 *   不引用詐騙內容、暱稱去掉網址 / LINE ID、把群組常設的禁字（「換群」）換掉，結尾標示自動提醒。
 */
import type { Store } from "../storage/db.ts";
import type { Outbox, OutboxItem } from "../ai/outbox.ts";
import type { Audit } from "../ai/audit.ts";
import type { ScamDetector } from "./detector.ts";

export interface WarnConfig {
	chat_id: string;
	enabled: boolean;
	min_level: "high" | "suspicious";
	cooldown_min: number;
	daily_cap: number;
}

export type TemplateKey = "fake_group" | "investment" | "link" | "customer_service" | "generic";

export const DEFAULT_TEMPLATES: Record<TemplateKey, string> = {
	fake_group: "⚠️ 反詐提醒：這則「搬新群／加入新群組」的公告有詐騙特徵。正常的群組不會要求大家移到新群或備用群，請不要點連結、直接檢舉。有疑問可撥 165 查證。（自動提醒）",
	investment: "⚠️ 反詐提醒：「{sender}」的訊息有投資帶單／保證獲利的詐騙特徵，請不要加好友、不要匯款。可撥 165 反詐騙專線查證。（自動提醒）",
	link: "⚠️ 反詐提醒：這則訊息含短網址或外部邀請連結，疑似詐騙，請不要點擊或填寫資料。（自動提醒）",
	customer_service: "⚠️ 反詐提醒：要你「解除分期、實名驗證、提供驗證碼」的都是詐騙，請不要照做。可撥 165 查證。（自動提醒）",
	generic: "⚠️ 反詐提醒：「{sender}」的訊息疑似詐騙（{reason}），請大家先不要點連結或私下聯繫，可撥 165 查證。（自動提醒）",
};

/** LINE 群組常設禁字：含禁字的訊息別人看不到，所以送出前替換（改作自 notice.mjs scrubNotice） */
export const BLOCKED_WORDS: Record<string, string> = { 換群: "假群組" };

export function scrubNotice(text: string, blocked: Record<string, string> = BLOCKED_WORDS): string {
	let out = text;
	for (const [w, rep] of Object.entries(blocked)) {
		const spaced = [...w].map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[\\s\\u3000]*");
		out = out.replace(new RegExp(spaced, "g"), rep);
	}
	return out;
}

/** 通知裡的暱稱：去網址、LINE ID 樣式、換行，最多 20 字（改作自 notice.mjs safeName） */
export function safeName(name: string | null | undefined): string {
	const cleaned = String(name ?? "")
		.normalize("NFKC")
		.replace(/(https?:\/\/)?([\w-]+\.)+[a-z]{2,}(\/\S*)?/gi, "")
		.replace(/@?[\w.-]*\d[\w.-]{4,}/g, "")
		.replace(/[\r\n\t]+/g, " ")
		.trim()
		.slice(0, 20);
	return scrubNotice(cleaned) || "某位成員";
}

export function pickTemplate(rules: string[]): TemplateKey {
	if (rules.some((r) => /換群|群組公告|群組連結|催促加入新群|群組邀請/.test(r))) return "fake_group";
	if (rules.some((r) => /投資|報牌|虛幣|假投資平台/.test(r))) return "investment";
	if (rules.some((r) => /客服|中獎|驗證碼|收帳戶/.test(r))) return "customer_service";
	if (rules.some((r) => /短網址|子網域/.test(r))) return "link";
	return "generic";
}

export class ScamWarner {
	#store: Store;
	#outbox: Outbox;
	#audit: Audit;
	#detector: ScamDetector;

	constructor(store: Store, outbox: Outbox, audit: Audit, detector: ScamDetector) {
		this.#store = store;
		this.#outbox = outbox;
		this.#audit = audit;
		this.#detector = detector;
		outbox.warnCheck = (it) => this.#sendCheck(it);
	}

	get(chatId: string): WarnConfig {
		const r = this.#store.db.prepare("SELECT * FROM scam_warn WHERE chat_id = ?").get(chatId) as Record<string, unknown> | undefined;
		if (!r) return { chat_id: chatId, enabled: false, min_level: "high", cooldown_min: 30, daily_cap: 10 };
		return { chat_id: chatId, enabled: r.enabled === 1, min_level: r.min_level === "suspicious" ? "suspicious" : "high", cooldown_min: Number(r.cooldown_min), daily_cap: Number(r.daily_cap) };
	}

	set(chatId: string, patch: Partial<Omit<WarnConfig, "chat_id">>): WarnConfig {
		const chat = this.#store.getChat(chatId);
		if (!chat || chat.allowed !== 1) throw new Error("chat not found or not allowed for MCP access");
		const c = { ...this.get(chatId), ...patch };
		const n = (v: unknown, lo: number, hi: number, d: number) => (Number.isFinite(Number(v)) ? Math.max(lo, Math.min(hi, Math.floor(Number(v)))) : d);
		this.#store.db
			.prepare(
				`INSERT INTO scam_warn(chat_id, enabled, min_level, cooldown_min, daily_cap, updated_at) VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(chat_id) DO UPDATE SET enabled=excluded.enabled, min_level=excluded.min_level, cooldown_min=excluded.cooldown_min, daily_cap=excluded.daily_cap, updated_at=excluded.updated_at`,
			)
			.run(chatId, c.enabled ? 1 : 0, c.min_level === "suspicious" ? "suspicious" : "high", n(c.cooldown_min, 1, 1440, 30), n(c.daily_cap, 0, 100, 10), Date.now());
		this.#audit.log("ui", c.enabled ? "scam_warn_enabled" : "scam_warn_disabled", { chatId });
		return this.get(chatId);
	}

	templates(): Record<TemplateKey, string> {
		try {
			return { ...DEFAULT_TEMPLATES, ...(JSON.parse(this.#store.getSetting("scam_warn_templates") ?? "{}") as Partial<Record<TemplateKey, string>>) };
		} catch {
			return DEFAULT_TEMPLATES;
		}
	}

	setTemplates(t: Partial<Record<TemplateKey, string>>): Record<TemplateKey, string> {
		const cur = this.templates();
		for (const k of Object.keys(DEFAULT_TEMPLATES) as TemplateKey[]) {
			const v = t[k];
			if (typeof v === "string") cur[k] = v.trim().slice(0, 300) || DEFAULT_TEMPLATES[k];
		}
		this.#store.setSetting("scam_warn_templates", JSON.stringify(cur));
		return cur;
	}

	#sentToday(chatId: string): number {
		const sod = new Date();
		sod.setHours(0, 0, 0, 0);
		return Number(
			(this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND status IN ('approved','sent') AND created_at >= ?").get(chatId, sod.getTime()) as { n: number }).n,
		);
	}

	#sendCheck(it: OutboxItem): string | null {
		const c = this.get(it.chat_id);
		if (!c.enabled) return "scam_warn_disabled";
		const sod = new Date();
		sod.setHours(0, 0, 0, 0);
		const sent = Number((this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND status='sent' AND sent_at >= ?").get(it.chat_id, sod.getTime()) as { n: number }).n);
		return sent >= c.daily_cap ? "scam_warn_daily_cap" : null;
	}

	/** 對新警示決定要不要發提醒。回傳排入的 outbox 項目或略過原因。 */
	onAlert(alertId: number): { item?: OutboxItem; skipped?: string } {
		const a = this.#store.db.prepare("SELECT * FROM scam_alert WHERE id = ?").get(alertId) as { chat_id: string; message_id: string; level: string; rules: string } | undefined;
		if (!a) return { skipped: "no_alert" };
		const c = this.get(a.chat_id);
		const skip = (why: string) => {
			if (c.enabled) this.#audit.log("system", "scam_warning_skipped", { chatId: a.chat_id, detail: { alert: alertId, reason: why } });
			return { skipped: why };
		};
		if (!c.enabled) return { skipped: "disabled" };
		if (c.min_level === "high" && a.level !== "high") return skip("below_min_level");
		const m = this.#store.getMessage(a.chat_id, a.message_id);
		if (!m || m.from_self === 1) return skip("no_message");
		const rules = JSON.parse(a.rules) as string[];
		const key = pickTemplate(rules);
		const sender = m.sender_mid ?? "?";
		const detail = `${key}:${sender}`.slice(0, 60);
		// 同一則只提醒一次；同發送者＋同類型冷卻
		const dupe = this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND reply_to=?").get(a.chat_id, a.message_id) as { n: number };
		if (Number(dupe.n) > 0) return skip("already_warned");
		const recent = this.#store.db
			.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND origin_detail=? AND status IN ('approved','sent') AND created_at >= ?")
			.get(a.chat_id, detail, Date.now() - c.cooldown_min * 60_000) as { n: number };
		if (Number(recent.n) > 0) return skip("cooldown");
		if (this.#sentToday(a.chat_id) >= c.daily_cap) return skip("daily_cap");
		const reason = rules.filter((r) => !/扣分/.test(r)).slice(0, 2).join("、") || "可疑內容";
		const text = scrubNotice(this.templates()[key].replaceAll("{sender}", safeName(m.sender_name)).replaceAll("{reason}", scrubNotice(reason)));
		try {
			return { item: this.#outbox.enqueueWarning(a.chat_id, text, a.message_id, detail) };
		} catch (e) {
			return skip((e as Error).message);
		}
	}

	/** 偵測器產生警示後呼叫 */
	handle(alertIds: number[]): void {
		for (const id of alertIds) this.onAlert(id);
	}

	detector(): ScamDetector {
		return this.#detector;
	}
}
