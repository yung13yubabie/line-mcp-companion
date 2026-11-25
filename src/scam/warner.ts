/**
 * 反詐即時提醒：本機規則偵測到詐騙 / 換群時，立刻以「引用回覆」在群組發一則提醒（不需要 AI）。
 *   - 每群組開關，預設關；使用者開啟後不進確認佇列
 *   - 同一則只提醒一次、同一發送者＋同類型冷卻（預設 30 分）、每群每日上限（預設 10）
 *   - kill switch、MCP 白名單仍然生效；全部寫入稽核紀錄
 *   - 可 @ 這群的管理員（每群開關，最多 3 位）；範本可全域或每群自訂
 *
 * 改作自 mars-tw/anti-scam-helper（Apache-2.0）guard/notice.mjs：scrubNotice、safeName、stripMentions，
 * 以及「通知一律引用回覆那則訊息、不引用詐騙內容、@ 最多 3 人、@ 失敗就拿掉 @ 段落重送」的作法。
 * 修改：TypeScript 移植；範本改為「疑似類型＋一句話提示＋@管理員」，不加（AI代理）等標籤。
 */
import type { Store } from "../storage/db.ts";
import type { Outbox, OutboxItem } from "../ai/outbox.ts";
import type { Audit } from "../ai/audit.ts";
import type { ScamDetector } from "./detector.ts";
import { CATEGORY_TIPS } from "./rules.ts";
import type { EventLog } from "../storage/event-log.ts";

export interface WarnConfig {
	chat_id: string;
	enabled: boolean;
	min_level: "high" | "suspicious";
	cooldown_min: number;
	daily_cap: number;
	mention_admins: boolean;
	/** null = 用全域範本 */
	template: string | null;
}

export interface Mention {
	start: number;
	end: number;
	mid: string;
}

export const DEFAULT_TEMPLATE = "⚠️ 這則疑似「{category}」詐騙：{tip}。@{admins} 請確認處理。";
export const MAX_NOTICE_MENTIONS = 3;

/** LINE 群組常設禁字：含禁字的訊息別人看不到，所以送出前替換 */
export const BLOCKED_WORDS: Record<string, string> = { 換群: "假群組" };

export function scrubNotice(text: string, blocked: Record<string, string> = BLOCKED_WORDS): string {
	let out = String(text ?? "");
	for (const [w, rep] of Object.entries(blocked)) {
		if (!w) continue;
		const spaced = [...w].map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[\\s\\u3000]*");
		out = out.replace(new RegExp(spaced, "g"), rep);
	}
	return out;
}

/** 通知裡的暱稱：去網址、LINE ID 樣式、換行，最多 20 字，再過禁字 */
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

/** 拿掉 @ 段落（含後面一個空白）；@ 沒送成功時不能留下看起來像標人的純文字 */
export function stripMentions(text: string, mentions: Mention[] = []): string {
	let out = String(text ?? "");
	for (const m of [...mentions].sort((a, b) => b.start - a.start)) {
		let end = m.end;
		if (out[end] === " ") end += 1;
		out = out.slice(0, m.start) + out.slice(end);
	}
	return out.replace(/\n[ \t]+/g, "\n").replace(/ {2,}/g, " ");
}

/**
 * 自訂提醒文字（使用者 / 連接器 / AI 寫的）。範本與範例只是參考，文字可以自由寫，但：
 *   - 套 scrubNotice（LINE 禁字替換）
 *   - 不可含任何連結 / 網域 / LINE 加好友連結
 *   - 不可引用詐騙訊息內容（與原訊息有連續 10 字以上相同就拒絕）
 * 回傳處理後的文字；不合格丟錯。可含 {category} {tip} {admins} {sender} 佔位字。
 */
export function checkCustomWarning(text: string, scamText: string | null | undefined): string {
	const t = String(text ?? "").normalize("NFC").trim();
	if (!t) throw new Error("warning text is required");
	if ([...t].length > 300) throw new Error("warning text too long (max 300)");
	if (/(https?:\/\/|www\.|line\.me|lin\.ee|\b[a-z0-9-]+\.[a-z]{2,}\b)/i.test(t)) throw new Error("warning_contains_link: 提醒文字不能有連結或網址");
	if (/(line|賴)\s*id\s*[:：]?\s*@?[a-z0-9._-]{3,}|@[a-z0-9._-]*\d[a-z0-9._-]{3,}/i.test(t.replace(/\{[a-z]+\}/g, ""))) throw new Error("warning_contains_contact: 提醒文字不能有 LINE ID");
	const norm = (s: string) => s.normalize("NFKC").replace(/[\s\u3000，。！？、,.!?:：;；「」『』"'（）()]/g, "").toLowerCase();
	const a = norm(scamText ?? "");
	const b = norm(t);
	const W = 10;
	for (let i = 0; i + W <= a.length && i < 2000; i++) if (b.includes(a.slice(i, i + W))) throw new Error("warning_quotes_scam: 提醒文字不能引用詐騙內容");
	return scrubNotice(t);
}

/**
 * 套範本。{category} {tip} {sender} 直接替換；{admins} 展開成「@名字 @名字」並回傳 mention 位置。
 * 沒有要 @ 的人時，整句含 {admins} 的句子拿掉。絕不放入詐騙訊息內容。
 */
export function renderNotice(
	template: string,
	vars: { category: string; tip: string; sender?: string | null },
	admins: { mid: string; name: string | null }[],
): { text: string; mentions: Mention[] } {
	let t = scrubNotice(template || DEFAULT_TEMPLATE)
		.replaceAll("{category}", scrubNotice(vars.category))
		.replaceAll("{tip}", scrubNotice(vars.tip))
		.replaceAll("{sender}", safeName(vars.sender));
	const list = admins.slice(0, MAX_NOTICE_MENTIONS);
	if (!list.length) {
		// 拿掉含 {admins} 的那一句（以「。！!？?」分句）
		t = t.replace(/[^。！!？?\n]*\{admins\}[^。！!？?\n]*[。！!？?]?/g, "").trim();
		return { text: t, mentions: [] };
	}
	const idx = t.indexOf("@{admins}") >= 0 ? t.indexOf("@{admins}") : t.indexOf("{admins}");
	const token = t.indexOf("@{admins}") >= 0 ? "@{admins}" : "{admins}";
	if (idx < 0) return { text: t, mentions: [] };
	const mentions: Mention[] = [];
	let seg = "";
	const before = t.slice(0, idx);
	for (const [i, a] of list.entries()) {
		const label = `@${safeName(a.name)}`;
		const start = before.length + seg.length;
		mentions.push({ start, end: start + label.length, mid: a.mid });
		seg += label + (i < list.length - 1 ? " " : "");
	}
	// 其餘 {admins} 出現處不重複 @
	const rest = t.slice(idx + token.length).replaceAll("@{admins}", "管理員").replaceAll("{admins}", "管理員");
	return { text: before + seg + rest, mentions };
}

export class ScamWarner {
	#store: Store;
	#outbox: Outbox;
	#audit: Audit;
	#detector: ScamDetector;
	events: EventLog | null = null;

	constructor(store: Store, outbox: Outbox, audit: Audit, detector: ScamDetector) {
		this.#store = store;
		this.#outbox = outbox;
		this.#audit = audit;
		this.#detector = detector;
		outbox.warnCheck = (it) => this.#sendCheck(it);
	}

	get(chatId: string): WarnConfig {
		const r = this.#store.db.prepare("SELECT * FROM scam_warn WHERE chat_id = ?").get(chatId) as Record<string, unknown> | undefined;
		if (!r) return { chat_id: chatId, enabled: false, min_level: "high", cooldown_min: 30, daily_cap: 10, mention_admins: true, template: null };
		return {
			chat_id: chatId,
			enabled: r.enabled === 1,
			min_level: r.min_level === "suspicious" ? "suspicious" : "high",
			cooldown_min: Number(r.cooldown_min),
			daily_cap: Number(r.daily_cap),
			mention_admins: r.mention_admins !== 0,
			template: r.template == null ? null : String(r.template),
		};
	}

	set(chatId: string, patch: Partial<Omit<WarnConfig, "chat_id">>): WarnConfig {
		const chat = this.#store.getChat(chatId);
		if (!chat || chat.allowed !== 1) throw new Error("chat not found or not allowed for MCP access");
		const prev = this.get(chatId);
		const c = { ...prev, ...patch };
		const n = (v: unknown, lo: number, hi: number, d: number) => (Number.isFinite(Number(v)) ? Math.max(lo, Math.min(hi, Math.floor(Number(v)))) : d);
		const tpl = c.template == null || !String(c.template).trim() ? null : String(c.template).trim().slice(0, 300);
		this.#store.db
			.prepare(
				`INSERT INTO scam_warn(chat_id, enabled, min_level, cooldown_min, daily_cap, mention_admins, template, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(chat_id) DO UPDATE SET enabled=excluded.enabled, min_level=excluded.min_level, cooldown_min=excluded.cooldown_min,
				   daily_cap=excluded.daily_cap, mention_admins=excluded.mention_admins, template=excluded.template, updated_at=excluded.updated_at`,
			)
			.run(chatId, c.enabled ? 1 : 0, c.min_level === "suspicious" ? "suspicious" : "high", n(c.cooldown_min, 1, 1440, 30), n(c.daily_cap, 0, 100, 10), c.mention_admins ? 1 : 0, tpl, Date.now());
		if (prev.enabled !== !!c.enabled) this.#audit.log("ui", c.enabled ? "scam_warn_enabled" : "scam_warn_disabled", { chatId });
		return this.get(chatId);
	}

	/** 全域預設範本 */
	template(): string {
		return this.#store.getSetting("scam_warn_template") || DEFAULT_TEMPLATE;
	}
	setTemplate(t: string | null): string {
		const v = String(t ?? "").trim().slice(0, 300);
		this.#store.setSetting("scam_warn_template", v || DEFAULT_TEMPLATE);
		return this.template();
	}

	/** 範本預覽（UI 用） */
	preview(chatId: string, category = "假搬家群"): { text: string; mentions: Mention[] } {
		const c = this.get(chatId);
		const admins = c.mention_admins ? this.#detector.admins(chatId).filter((a) => a.mention) : [];
		return renderNotice(c.template ?? this.template(), { category, tip: CATEGORY_TIPS[category] ?? CATEGORY_TIPS["可疑連結"]! }, admins);
	}

	#sod(): number {
		const c = this.#outbox.policy.clock;
		return c.startOfDay(c.now());
	}

	#sendCheck(it: OutboxItem): string | null {
		const c = this.get(it.chat_id);
		if (!c.enabled) return "scam_warn_disabled";
		const sent = Number((this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND status='sent' AND sent_at >= ?").get(it.chat_id, this.#sod()) as { n: number }).n);
		return sent >= c.daily_cap ? "scam_warn_daily_cap" : null;
	}

	/** 對新警示決定要不要發提醒。回傳排入的 outbox 項目或略過原因。 */
	onAlert(alertId: number): { item?: OutboxItem; skipped?: string } {
		const a = this.#store.db.prepare("SELECT * FROM scam_alert WHERE id = ?").get(alertId) as { chat_id: string; message_id: string; level: string; category: string | null } | undefined;
		if (!a) return { skipped: "no_alert" };
		const c = this.get(a.chat_id);
		const skip = (why: string) => {
			if (c.enabled) {
				this.#audit.log("system", "scam_warning_skipped", { chatId: a.chat_id, detail: { alert: alertId, reason: why } });
				const act = (["cooldown", "daily_cap", "below_min_level", "already_warned"] as const).find((x) => x === why);
				this.events?.setScamAction({ alertId }, act ?? "error", act ? null : why);
			}
			return { skipped: why };
		};
		if (!c.enabled) return { skipped: "disabled" };
		if (c.min_level === "high" && a.level !== "high") return skip("below_min_level");
		const m = this.#store.getMessage(a.chat_id, a.message_id);
		if (!m || m.from_self === 1) return skip("no_message");
		// 公開警告不經確認佇列：只依「內建規則 + 內建 / 使用者自己加的範例」判斷。
		// MCP（外部 AI，可能被提示注入）加入的範例只能產生警示，不能單獨觸發公開警告。
		if (m.text) {
			const strict = this.#detector.evaluate(m.text, { excludeSources: ["mcp"] });
			const need = c.min_level === "high" ? "high" : "suspicious";
			if (!strict.level || (need === "high" && strict.level !== "high")) return skip("mcp_sample_requires_review");
		}
		const category = a.category ?? "可疑連結";
		const sender = m.sender_mid ?? "?";
		const detail = `${category}:${sender}`.slice(0, 60);
		const dupe = this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND reply_to=?").get(a.chat_id, a.message_id) as { n: number };
		if (Number(dupe.n) > 0) return skip("already_warned");
		const recent = this.#store.db
			.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND origin_detail=? AND status IN ('pending','approved','sent') AND created_at >= ?")
			.get(a.chat_id, detail, this.#outbox.policy.clock.now() - c.cooldown_min * 60_000) as { n: number };
		if (Number(recent.n) > 0) return skip("cooldown");
		const today = Number((this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND status IN ('approved','sent') AND created_at >= ?").get(a.chat_id, this.#sod()) as { n: number }).n);
		if (today >= c.daily_cap) return skip("daily_cap");
		// 被 @ 的人不能是這則訊息的發送者
		const admins = c.mention_admins ? this.#detector.admins(a.chat_id).filter((x) => x.mention && x.mid !== sender) : [];
		const { text, mentions } = renderNotice(c.template ?? this.template(), { category, tip: CATEGORY_TIPS[category] ?? CATEGORY_TIPS["可疑連結"]!, sender: m.sender_name }, admins);
		try {
			const item = this.#outbox.enqueueWarning(a.chat_id, text, a.message_id, detail, mentions);
			this.events?.setScamAction({ alertId }, item.status === "pending" ? "queued" : "scheduled", null, item.id);
			return { item };
		} catch (e) {
			return skip((e as Error).message);
		}
	}

	/**
	 * 自訂提醒（使用者在 App、或連接器經 MCP 寫的）。範本 / 範例只是參考：
	 * text 可自由寫（null = 用該群範本），會過 checkCustomWarning（禁字、無連結、不引用詐騙內容），
	 * 一樣依信任狀態（review → 確認佇列；auto → 直接排程），受緊急停止、白名單、每日上限、同則只提醒一次限制。
	 */
	compose(chatId: string, messageId: string, text: string | null, actor: "ui" | "mcp"): OutboxItem {
		const chat = this.#store.getChat(chatId);
		if (!chat || chat.allowed !== 1) throw new Error("chat not found or not allowed for MCP access");
		const c = this.get(chatId);
		if (!c.enabled) throw new Error("scam_warn_disabled: 這個群組沒有開啟反詐提醒");
		const m = this.#store.getMessage(chatId, messageId);
		if (!m || m.from_self === 1) throw new Error("message not found in this chat");
		if (m.hidden) throw new Error("message_hidden: 這則訊息已被隱藏或收回");
		const dupe = this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND reply_to=? AND status IN ('pending','approved','sent')").get(chatId, messageId) as { n: number };
		if (Number(dupe.n) > 0) throw new Error("already_warned: 這則已經提醒過或在佇列中");
		const today = Number((this.#store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE origin='scam_warn' AND chat_id=? AND status IN ('approved','sent') AND created_at >= ?").get(chatId, this.#sod()) as { n: number }).n);
		if (today >= c.daily_cap) throw new Error("scam_warn_daily_cap");
		const alert = this.#store.db.prepare("SELECT id, category FROM scam_alert WHERE chat_id = ? AND message_id = ?").get(chatId, messageId) as { id: number; category: string | null } | undefined;
		const category = alert?.category ?? "可疑訊息";
		const sender = m.sender_mid ?? "?";
		const tpl = text == null || !String(text).trim() ? (c.template ?? this.template()) : checkCustomWarning(String(text), m.text);
		const admins = c.mention_admins ? this.#detector.admins(chatId).filter((x) => x.mention && x.mid !== sender) : [];
		const r = renderNotice(tpl, { category, tip: CATEGORY_TIPS[category] ?? CATEGORY_TIPS["可疑連結"]!, sender: m.sender_name }, admins);
		// 佔位字展開後再檢查一次（tip / 暱稱不會含連結，但保險）
		const finalText = checkCustomWarning(r.text, m.text);
		const item = this.#outbox.enqueueWarning(chatId, finalText, messageId, `${category}:${sender}`.slice(0, 60), finalText === r.text ? r.mentions : [], actor);
		if (this.events) {
			if (alert) this.events.setScamAction({ alertId: alert.id }, item.status === "pending" ? "queued" : "scheduled", "custom", item.id);
			else {
				const id = this.events.scam({ chat_id: chatId, message_id: messageId, sender_mid: m.sender_mid, sender_name: m.sender_name, text: m.text, category, action: item.status === "pending" ? "queued" : "scheduled", detail: `custom by ${actor}` });
				this.#store.db.prepare("UPDATE scam_log SET outbox_id = ? WHERE id = ?").run(item.id, id);
			}
		}
		return item;
	}

	handle(alertIds: number[]): void {
		for (const id of alertIds) this.onAlert(id);
	}

	/** 近期提醒紀錄（總控台） */
	log(limit = 30): { id: number; chat_id: string; status: string; text: string | null; reply_to: string | null; created_at: number; sent_at: number | null; error: string | null }[] {
		return this.#store.db.prepare("SELECT id, chat_id, status, text, reply_to, created_at, sent_at, error FROM outbox WHERE origin='scam_warn' ORDER BY id DESC LIMIT ?").all(limit) as never;
	}
}
