/**
 * 確認佇列 / 發送佇列。
 *   enqueue()     → pending（等使用者確認）或 approved（自動，排程在 delay 之後）
 *   approve()     → 使用者核准（可編輯文字）→ approved，立即排程
 *   reject()      → rejected
 *   processDue()  → 對到期的 approved 重新檢查權限與上限，再呼叫 MessageSender
 *   setKill(true) → 所有尚未送出的 approved 退回 pending
 */
import { readFileSync } from "node:fs";
import type { Store } from "../storage/db.ts";
import { AiPolicy, denyError, type DenyReason, type SendKind } from "./policy.ts";
import { validSticker, type StickerRef } from "./stickers.ts";
import type { MessageSender } from "./sender.ts";
import { Audit, redact, type Actor } from "./audit.ts";
import { sniffMime } from "./provider.ts";
import { stripMentions, checkCustomWarning } from "../scam/warner.ts";
import type { EventLog, AiEvent, ScamAction } from "../storage/event-log.ts";

export type OutboxStatus = "pending" | "approved" | "sent" | "rejected" | "failed" | "expired";
export type Origin = "auto" | "suggest" | "mcp" | "ui" | "scam_warn" | "digest";

export interface OutboxItem {
	id: number;
	chat_id: string;
	kind: SendKind;
	text: string | null;
	sticker_json: string | null;
	prompt: string | null;
	image_path: string | null;
	origin: Origin;
	origin_detail: string | null;
	reply_to: string | null;
	mentions_json: string | null;
	trigger_id: string | null;
	status: OutboxStatus;
	flags: string | null;
	created_at: number;
	scheduled_at: number | null;
	decided_at: number | null;
	sent_at: number | null;
	error: string | null;
}

export const MAX_PENDING_TOTAL = 50;
export const MAX_PENDING_PER_CHAT = 10;
export const PENDING_TTL_MS = 24 * 3_600_000;
export const MAX_TEXT = 2000;

export interface EnqueueInput {
	chatId: string;
	kind: SendKind;
	text?: string | null;
	sticker?: StickerRef | null;
	triggerId?: string | null;
	prompt?: string | null;
	imagePath?: string | null;
	origin: Origin;
	originDetail?: string | null;
	replyTo?: string | null;
	flags?: string[];
	/** 強制進確認佇列（例如「僅建議」） */
	forcePending?: boolean;
	/** 只看信任狀態（REVIEW/AUTO）與旗標決定要不要確認，不看代聊模式（日報貼文用） */
	trustOnly?: boolean;
}

export class Outbox {
	readonly store: Store;
	readonly policy: AiPolicy;
	readonly audit: Audit;
	sender: MessageSender;
	/** 貼圖是否可送（只有我送過的貼圖）；未設定 = 不允許任何貼圖 */
	stickerSendable: (s: StickerRef) => boolean = () => false;
	/** 反詐即時提醒（origin=scam_warn）的送出前檢查；回傳 null = 可送。未設定 = 不送。 */
	warnCheck: (it: OutboxItem) => string | null = () => "scam_warn_unavailable";
	/** 加密紀錄（AI 代聊紀錄 / 反詐紀錄）；未設定 = 不記 */
	log: EventLog | null = null;
	#busy = false;

	/** 佇列項目生命週期 → AI 代聊紀錄；反詐提醒 → 更新反詐紀錄的動作 */
	#event(it: OutboxItem, event: AiEvent, actor: string, opts: { text?: string | null; detail?: string | null; first?: boolean } = {}): void {
		if (!this.log) return;
		try {
			if (it.origin === "scam_warn") {
				const map: Partial<Record<AiEvent, ScamAction>> = { sent: "sent", rejected: "rejected", blocked: "blocked", failed: "error", expired: "rejected", approved: "scheduled" };
				const a = map[event];
				if (a) this.log.setScamAction({ outboxId: it.id }, a, opts.detail ?? null);
				return;
			}
			let trig: { id: string | null; who: string | null; text: string | null } = { id: null, who: null, text: null };
			if (opts.first) {
				const mid = it.trigger_id ?? it.reply_to;
				const m = mid ? this.store.getMessage(it.chat_id, mid) : undefined;
				if (m) trig = { id: m.id, who: m.sender_name ?? m.sender_mid ?? null, text: m.text ?? `[${m.content_type}]` };
			}
			const body = opts.text !== undefined ? opts.text : opts.first ? (it.text ?? (it.sticker_json ? `[貼圖] ${it.sticker_json}` : it.prompt ? `[圖片] ${it.prompt}` : null)) : null;
			this.log.ai({ chat_id: it.chat_id, outbox_id: it.id, origin: it.origin, event, actor, trigger_msg_id: trig.id, trigger_sender: trig.who, trigger_text: trig.text, text: body, detail: opts.detail ?? null });
		} catch {
			/* 紀錄失敗不影響送出流程 */
		}
	}

	constructor(store: Store, policy: AiPolicy, audit: Audit, sender: MessageSender) {
		this.store = store;
		this.policy = policy;
		this.audit = audit;
		this.sender = sender;
	}

	get(id: number): OutboxItem | undefined {
		return this.store.db.prepare("SELECT * FROM outbox WHERE id = ?").get(id) as OutboxItem | undefined;
	}

	list(opts: { status?: OutboxStatus | OutboxStatus[]; chatId?: string; limit?: number } = {}): OutboxItem[] {
		const where: string[] = [];
		const args: (string | number)[] = [];
		if (opts.status) {
			const s = Array.isArray(opts.status) ? opts.status : [opts.status];
			where.push(`status IN (${s.map(() => "?").join(",")})`);
			args.push(...s);
		}
		if (opts.chatId) {
			where.push("chat_id = ?");
			args.push(opts.chatId);
		}
		const w = where.length ? `WHERE ${where.join(" AND ")}` : "";
		return this.store.db.prepare(`SELECT * FROM outbox ${w} ORDER BY id DESC LIMIT ?`).all(...args, Math.min(500, opts.limit ?? 100)) as unknown as OutboxItem[];
	}

	#count(sql: string, ...a: (string | number)[]): number {
		return Number((this.store.db.prepare(sql).get(...a) as { n: number }).n);
	}

	/**
	 * 排入佇列。基本閘門不過 → 丟錯（白名單錯誤與讀取工具相同）。
	 * 自動路徑（auto + 不需確認 + 無可疑旗標）還要通過完整 checkSend，否則丟錯（不會偷偷改排隊）。
	 */
	enqueue(input: EnqueueInput, actor: Actor): { item: OutboxItem; route: "pending" | "scheduled" } {
		const basic = this.policy.checkBasic(input.chatId, input.kind);
		if (!basic.ok) {
			this.audit.log(actor, "enqueue_denied", { chatId: input.chatId, ok: false, detail: { reason: basic.reason, origin: input.origin } });
			throw denyError(basic.reason);
		}
		const text = input.text == null ? null : String(input.text);
		if (input.kind === "text" && (!text || !text.trim())) throw new Error("text is required");
		let stickerJson: string | null = null;
		if (input.kind === "sticker") {
			if (!validSticker(input.sticker)) throw new Error("invalid sticker");
			if (!this.stickerSendable(input.sticker)) throw new Error("sticker_not_owned: 只能送你自己用過的貼圖");
			stickerJson = JSON.stringify({ package_id: String(input.sticker.package_id), sticker_id: String(input.sticker.sticker_id), version: input.sticker.version ?? "1" });
		}
		if (input.replyTo != null && !this.store.getMessage(input.chatId, String(input.replyTo))) throw new Error("reply_to message not found in this chat");
		for (const mid of [input.replyTo, input.triggerId]) if (mid != null && this.store.isHidden(input.chatId, String(mid))) throw new Error("message_hidden: 這則訊息已被隱藏或收回，不能回覆");
		if (text && [...text].length > MAX_TEXT) throw new Error(`text too long (max ${MAX_TEXT})`);
		const flags = [...new Set(input.flags ?? [])];
		const pending = input.forcePending || (input.trustOnly ? basic.cfg.confirm_send || basic.cfg.mode !== "auto" || flags.length > 0 : this.policy.needsConfirmation(basic.cfg, flags));
		const now = this.policy.clock.now();
		let scheduled: number | null = null;
		if (pending) {
			if (this.#count("SELECT COUNT(*) AS n FROM outbox WHERE status='pending'") >= MAX_PENDING_TOTAL) throw new Error("pending queue full");
			if (this.#count("SELECT COUNT(*) AS n FROM outbox WHERE status='pending' AND chat_id = ?", input.chatId) >= MAX_PENDING_PER_CHAT)
				throw new Error("pending queue full for this chat");
		} else {
			const full = this.policy.checkSend(input.chatId, input.kind);
			if (!full.ok) {
				this.audit.log(actor, "enqueue_denied", { chatId: input.chatId, ok: false, detail: { reason: full.reason, origin: input.origin } });
				throw denyError(full.reason);
			}
			// 已排程但未送的也要算進每小時上限，避免連續排入繞過
			const queued = this.#count("SELECT COUNT(*) AS n FROM outbox WHERE status='approved' AND chat_id = ?", input.chatId);
			if (queued >= Math.max(1, basic.cfg.max_per_hour)) throw denyError("hourly_cap");
			scheduled = now + basic.cfg.delay_sec * 1000;
		}
		const r = this.store.db
			.prepare(
				`INSERT INTO outbox(chat_id, kind, text, sticker_json, prompt, image_path, origin, origin_detail, reply_to, trigger_id, status, flags, created_at, scheduled_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				input.chatId,
				input.kind,
				text,
				stickerJson,
				input.prompt ?? null,
				input.imagePath ?? null,
				input.origin,
				input.originDetail ? redact(input.originDetail, 60) : null,
				input.replyTo == null ? null : String(input.replyTo),
				input.triggerId ?? null,
				pending ? "pending" : "approved",
				flags.length ? flags.join(",") : null,
				now,
				scheduled,
			);
		const item = this.get(Number(r.lastInsertRowid))!;
		this.#event(item, "generated", actor, { first: true, detail: pending ? "queued" : "scheduled" });
		this.audit.log(actor, pending ? "queued_for_confirmation" : "scheduled_send", {
			chatId: input.chatId,
			detail: { id: item.id, kind: input.kind, origin: input.origin, flags, text: text ? redact(text) : undefined },
		});
		return { item, route: pending ? "pending" : "scheduled" };
	}

	/** 使用者核准（可編輯）。重新檢查（approvedByUser=true：略過時段/間隔/每小時，但不略過 kill switch、白名單、每日上限）。 */
	approve(id: number, editedText?: string | null, actor: Actor = "ui"): OutboxItem {
		const it = this.get(id);
		if (!it) throw new Error("outbox item not found");
		if (it.status !== "pending") throw new Error(`cannot approve item in status ${it.status}`);
		const chk: { ok: true } | { ok: false; reason: DenyReason } =
			it.origin === "scam_warn"
				? this.policy.killSwitch
					? { ok: false, reason: "kill_switch" }
					: this.store.getChat(it.chat_id)?.allowed !== 1
						? { ok: false, reason: "chat_not_allowed" }
						: { ok: true }
				: this.policy.checkSend(it.chat_id, it.kind, { approvedByUser: true });
		if (!chk.ok) {
			this.audit.log(actor, "approve_denied", { chatId: it.chat_id, ok: false, detail: { id, reason: chk.reason } });
			throw denyError(chk.reason);
		}
		const edited = editedText !== undefined && editedText !== null && editedText !== it.text;
		if (edited) this.edit(id, { text: editedText }, actor);
		const now = this.policy.clock.now();
		this.store.db.prepare("UPDATE outbox SET status='approved', decided_at=?, scheduled_at=? WHERE id=? AND status='pending'").run(now, now, id);
		this.audit.log(actor, "approved", { chatId: it.chat_id, detail: { id, edited } });
		// M-1：使用者在 App 核准過一次 MCP 送出 → 該聊天之後的 MCP 送出才看信任設定
		if (it.origin === "mcp" && actor === "ui") this.store.setSetting(`mcp_send_ok:${it.chat_id}`, "on");
		const done = this.get(id)!;
		this.#event(done, "approved", actor);
		return done;
	}

	/**
	 * 編輯待確認項目（仍為 pending）。文字 / 貼圖；反詐提醒的自訂文字要過 checkCustomWarning
	 * （禁字替換、不可含連結、不可引用詐騙內容）。@ 標記依原字串重新定位，找不到就拿掉。
	 */
	edit(id: number, patch: { text?: string | null; sticker?: StickerRef | null }, actor: Actor = "ui"): OutboxItem {
		const it = this.get(id);
		if (!it) throw new Error("outbox item not found");
		if (it.status !== "pending") throw new Error(`cannot edit item in status ${it.status}`);
		let text = it.text;
		let kind = it.kind;
		let stickerJson = it.sticker_json;
		if (patch.text !== undefined) {
			const t = patch.text == null ? null : String(patch.text);
			if (t != null && [...t].length > MAX_TEXT) throw new Error(`text too long (max ${MAX_TEXT})`);
			if (it.origin === "scam_warn") {
				const scam = it.reply_to ? this.store.getMessage(it.chat_id, it.reply_to)?.text ?? null : null;
				text = checkCustomWarning(t ?? "", scam);
			} else text = t != null && t.trim() ? t : null;
		}
		if (patch.sticker) {
			if (it.origin === "scam_warn" || it.kind === "image") throw new Error("this item cannot carry a sticker");
			if (!validSticker(patch.sticker)) throw new Error("invalid sticker");
			if (!this.stickerSendable(patch.sticker)) throw new Error("sticker_not_owned: 只能送你自己用過的貼圖");
			stickerJson = JSON.stringify({ package_id: String(patch.sticker.package_id), sticker_id: String(patch.sticker.sticker_id), version: patch.sticker.version ?? "1" });
			kind = "sticker";
		} else if (patch.sticker === null && it.kind === "sticker") {
			stickerJson = null;
			kind = "text";
		}
		if (kind === "text" && !text?.trim()) throw new Error("text is required");
		let mentionsJson = it.mentions_json;
		if (mentionsJson && text !== it.text && it.text) {
			const old = JSON.parse(mentionsJson) as { start: number; end: number; mid: string }[];
			const moved: typeof old = [];
			let from = 0;
			for (const m of old) {
				const label = it.text.slice(m.start, m.end);
				const at = text ? text.indexOf(label, from) : -1;
				if (label && at >= 0) {
					moved.push({ start: at, end: at + label.length, mid: m.mid });
					from = at + label.length;
				}
			}
			mentionsJson = moved.length ? JSON.stringify(moved) : null;
		}
		this.store.db.prepare("UPDATE outbox SET text=?, kind=?, sticker_json=?, mentions_json=? WHERE id=? AND status='pending'").run(text, kind, stickerJson, mentionsJson, id);
		const out = this.get(id)!;
		this.audit.log(actor, "edited", { chatId: it.chat_id, detail: { id, kind } });
		if (it.origin === "scam_warn") this.log?.setScamAction({ outboxId: id }, "queued", "edited");
		else this.#event(out, "edited", actor, { text: out.text ?? (out.sticker_json ? `[貼圖] ${out.sticker_json}` : null) });
		return out;
	}

	reject(id: number, actor: Actor = "ui"): OutboxItem {
		const it = this.get(id);
		if (!it) throw new Error("outbox item not found");
		if (it.status !== "pending" && it.status !== "approved") throw new Error(`cannot reject item in status ${it.status}`);
		this.store.db.prepare("UPDATE outbox SET status='rejected', decided_at=? WHERE id=?").run(this.policy.clock.now(), id);
		this.audit.log(actor, "rejected", { chatId: it.chat_id, detail: { id } });
		const out = this.get(id)!;
		this.#event(out, "rejected", actor);
		return out;
	}

	/** kill switch：開啟時把所有待送（approved）退回 pending，關閉後也不會自動送出 */
	setKill(on: boolean, actor: Actor = "ui"): number {
		this.policy.setKillSwitch(on);
		let n = 0;
		if (on) {
			// 緊急停止：所有 auto 會話一律降回 review（AI 回覆與反詐提醒都是）
			this.policy.demoteAll("system", "kill_switch");
			// 反詐提醒是時效性訊息，不留到之後：直接取消
			this.store.db.prepare("UPDATE outbox SET status='rejected', error='kill_switch' WHERE status='approved' AND origin='scam_warn'").run();
			n = Number(this.store.db.prepare("UPDATE outbox SET status='pending', scheduled_at=NULL, error='kill_switch' WHERE status='approved'").run().changes);
		}
		this.audit.log(actor, on ? "kill_switch_on" : "kill_switch_off", { detail: { returned_to_pending: n } });
		return n;
	}

	/**
	 * 反詐即時提醒。信任狀態 review（預設）→ pending，等使用者在確認佇列編輯 / 核准；
	 * auto → 直接排程。都受 kill switch 與 MCP 白名單限制（warnCheck 另外檢查群組開關與每日上限）。
	 */
	enqueueWarning(chatId: string, text: string, replyTo: string, detail: string, mentions: { start: number; end: number; mid: string }[] = [], actor: Actor = "system"): OutboxItem {
		if (this.policy.killSwitch) throw denyError("kill_switch");
		const chat = this.store.getChat(chatId);
		if (!chat || chat.allowed !== 1) throw denyError("chat_not_allowed");
		const now = this.policy.clock.now();
		const auto = this.policy.trust(chatId, "scam") === "auto";
		if (!auto && this.#count("SELECT COUNT(*) AS n FROM outbox WHERE status='pending'") >= MAX_PENDING_TOTAL) throw new Error("pending queue full");
		const r = this.store.db
			.prepare(
				`INSERT INTO outbox(chat_id, kind, text, origin, origin_detail, reply_to, status, created_at, scheduled_at, decided_at, mentions_json)
				 VALUES (?, 'text', ?, 'scam_warn', ?, ?, ?, ?, ?, NULL, ?)`,
			)
			.run(chatId, text.slice(0, MAX_TEXT), detail.slice(0, 60), replyTo, auto ? "approved" : "pending", now, auto ? now : null, mentions.length ? JSON.stringify(mentions) : null);
		const item = this.get(Number(r.lastInsertRowid))!;
		this.audit.log(actor, auto ? "scam_warning_scheduled" : "scam_warning_queued", { chatId, detail: { id: item.id, reply_to: replyTo, kind: detail } });
		return item;
	}

	/** 訊息被隱藏 / 收回 / 刪除：取消所有針對它（引用 / 觸發）的待確認與已排程項目。回傳取消數。 */
	cancelForHidden(chatId: string, messageId: string): number {
		const items = this.store.db
			.prepare("SELECT * FROM outbox WHERE chat_id = ? AND status IN ('pending','approved') AND (reply_to = ? OR trigger_id = ?)")
			.all(chatId, messageId, messageId) as unknown as OutboxItem[];
		for (const it of items) this.#cancelHidden(it);
		return items.length;
	}
	#cancelHidden(it: OutboxItem): void {
		// 安靜取消：不寫稽核 / AI / 反詐紀錄
		this.store.db.prepare("UPDATE outbox SET status='expired', error='target_hidden' WHERE id=?").run(it.id);
	}

	/** 舊的 pending 過期；同會話新的建議取代舊的 */
	expireStale(): number {
		const cut = this.policy.clock.now() - PENDING_TTL_MS;
		return Number(this.store.db.prepare("UPDATE outbox SET status='expired' WHERE status='pending' AND created_at < ?").run(cut).changes);
	}
	supersede(chatId: string, origins: Origin[]): number {
		const ph = origins.map(() => "?").join(",");
		return Number(
			this.store.db.prepare(`UPDATE outbox SET status='expired', error='superseded' WHERE chat_id=? AND status='pending' AND origin IN (${ph})`).run(chatId, ...origins).changes,
		);
	}

	/** 送出所有到期的 approved。回傳送出筆數。 */
	async processDue(): Promise<number> {
		if (this.#busy) return 0;
		this.#busy = true;
		let sent = 0;
		try {
			const now = this.policy.clock.now();
			const due = this.store.db.prepare("SELECT * FROM outbox WHERE status='approved' AND scheduled_at <= ? ORDER BY scheduled_at, id").all(now) as unknown as OutboxItem[];
			for (const it of due) {
				const byUser = it.decided_at !== null;
				if ((it.reply_to && this.store.isHidden(it.chat_id, it.reply_to)) || (it.trigger_id && this.store.isHidden(it.chat_id, it.trigger_id))) {
					this.#cancelHidden(it);
					continue;
				}
				if (it.origin === "scam_warn") {
					const why = this.policy.killSwitch ? "kill_switch" : this.store.getChat(it.chat_id)?.allowed !== 1 ? "chat_not_allowed" : this.warnCheck(it);
					if (why) {
						this.store.db.prepare("UPDATE outbox SET status='rejected', error=? WHERE id=?").run(why, it.id);
						this.audit.log("system", "scam_warning_blocked", { chatId: it.chat_id, ok: false, detail: { id: it.id, reason: why } });
						this.#event(it, "blocked", "system", { detail: why });
						continue;
					}
				}
				const chk = it.origin === "scam_warn" ? ({ ok: true } as const) : this.policy.checkSend(it.chat_id, it.kind, { approvedByUser: byUser });
				if (!chk.ok) {
					this.#bounce(it, chk.reason);
					continue;
				}
				// 自動回覆：使用者已在手機上親自回覆（觸發訊息之後有自己的訊息）→ 取消
				if (!byUser && it.origin === "auto" && this.#userRepliedSince(it.chat_id, it.created_at)) {
					this.store.db.prepare("UPDATE outbox SET status='expired', error='superseded_by_user' WHERE id=?").run(it.id);
					this.#event(it, "expired", "system", { detail: "superseded_by_user" });
					this.audit.log("auto", "cancelled_user_replied", { chatId: it.chat_id, detail: { id: it.id } });
					continue;
				}
				try {
					const opts = { replyTo: it.reply_to };
					const mentions = it.mentions_json ? (JSON.parse(it.mentions_json) as { start: number; end: number; mid: string }[]) : [];
					if (it.kind === "text" && mentions.length) {
						try {
							await this.sender.sendText(it.chat_id, it.text!, { ...opts, mentions });
						} catch (e) {
							// @ 失敗（LINE 只准 @ 最近發過言的人）→ 拿掉 @ 段落重送一次
							this.audit.log("system", "mention_failed_retry", { chatId: it.chat_id, ok: false, detail: { id: it.id, error: redact((e as Error).message, 120) } });
							await this.sender.sendText(it.chat_id, stripMentions(it.text!, mentions), opts);
						}
					} else if (it.kind === "text") await this.sender.sendText(it.chat_id, it.text!, opts);
					else if (it.kind === "sticker") {
						const st = JSON.parse(it.sticker_json!) as StickerRef;
						if (!this.stickerSendable(st)) throw new Error("sticker_not_owned");
						// 文字（若有）先送並帶引用，貼圖接在後面
						if (it.text) {
							await this.sender.sendText(it.chat_id, it.text, opts);
							await this.sender.sendSticker(it.chat_id, st);
						} else await this.sender.sendSticker(it.chat_id, st, opts);
					} else {
						const bytes = new Uint8Array(readFileSync(it.image_path!));
						const mime = sniffMime(bytes);
						await this.sender.sendImage(it.chat_id, bytes, mime, `ai-${it.id}.${mime === "image/jpeg" ? "jpg" : mime === "image/webp" ? "webp" : "png"}`);
						if (it.text) await this.sender.sendText(it.chat_id, it.text, opts);
					}
					this.store.db.prepare("UPDATE outbox SET status='sent', sent_at=?, error=NULL WHERE id=?").run(this.policy.clock.now(), it.id);
					this.#event(it, "sent", "system", { text: it.text });
					this.audit.log(it.origin === "mcp" ? "mcp" : it.origin === "ui" ? "ui" : it.origin === "scam_warn" ? "system" : "auto", it.origin === "scam_warn" ? "scam_warning_sent" : "sent", {
						chatId: it.chat_id,
						detail: { id: it.id, kind: it.kind, approved_by_user: byUser },
					});
					sent++;
				} catch (e) {
					const msg = redact((e as Error).message, 200);
					this.store.db.prepare("UPDATE outbox SET status='failed', error=? WHERE id=?").run(msg, it.id);
					this.#event(it, "failed", "system", { detail: msg });
					this.audit.log("system", "send_failed", { chatId: it.chat_id, ok: false, detail: { id: it.id, error: msg } });
				}
			}
		} finally {
			this.#busy = false;
		}
		return sent;
	}

	#userRepliedSince(chatId: string, ts: number): boolean {
		const r = this.store.db.prepare("SELECT COUNT(*) AS n FROM message WHERE chat_id=? AND from_self=1 AND sent_at > ?").get(chatId, ts) as { n: number };
		// 排除我們自己送出的（sent_at 在 outbox 有紀錄的不算「使用者親自回覆」）
		const ours = this.store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE chat_id=? AND status='sent' AND sent_at > ?").get(chatId, ts) as { n: number };
		return Number(r.n) > Number(ours.n);
	}

	/** 到期但不能送：時段/間隔/每小時 → 延後重試；其他（kill、白名單、mode、每日上限）→ 退回 pending 讓使用者決定 */
	#bounce(it: OutboxItem, reason: DenyReason): void {
		const retry = reason === "outside_active_hours" || reason === "rate_interval" || reason === "hourly_cap";
		if (retry) {
			this.store.db.prepare("UPDATE outbox SET scheduled_at=?, error=? WHERE id=?").run(this.policy.clock.now() + 60_000, reason, it.id);
		} else {
			this.store.db.prepare("UPDATE outbox SET status='pending', scheduled_at=NULL, decided_at=NULL, error=? WHERE id=?").run(reason, it.id);
			this.audit.log("system", "send_blocked", { chatId: it.chat_id, ok: false, detail: { id: it.id, reason } });
		}
	}
}
