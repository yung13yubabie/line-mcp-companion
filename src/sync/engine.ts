import type { Store } from "../storage/db.ts";
import type { LineSource, SourceMessage } from "./types.ts";

export type SyncScope = "allowed" | "all";

export interface SyncStatus {
	state: "idle" | "syncing" | "error";
	lastFullSyncAt: number | null;
	lastPollAt: number | null;
	lastError: string | null;
	cursor: string | null;
	counts: { chats: number; allowed: number; messages: number };
}

/**
 * 同步引擎：
 * - fullSync：抓會話清單（全部，讓 UI 能勾選）＋每個「範圍內」會話的最近訊息。
 * - pollOnce：長輪詢增量事件（talk.sync），寫入新訊息與本帳號已讀位置。
 * 預設 scope = "allowed"：未勾選的會話只存名稱，不下載訊息內容（資料最小化）。
 * App 資料被系統清除後，DB 是空的 → 下一次 fullSync 會自動重建。
 */
export class SyncEngine {
	#store: Store;
	#src: LineSource;
	#state: SyncStatus["state"] = "idle";
	#lastError: string | null = null;
	#running: Promise<void> | null = null;
	/** 增量同步寫入新訊息後呼叫（AI 引擎、反詐偵測）；例外不影響同步 */
	onNewMessages: ((msgs: { chatId: string; id: string; fromSelf: boolean }[]) => void) | null = null;

	constructor(store: Store, src: LineSource) {
		this.#store = store;
		this.#src = src;
	}

	get scope(): SyncScope {
		return (this.#store.getSetting("sync_scope") as SyncScope) ?? "allowed";
	}

	/** 同一時間只跑一個 fullSync；重複呼叫共用同一個 promise。 */
	fullSync(opts: { perChat?: number } = {}): Promise<void> {
		if (!this.#running) {
			this.#running = this.#doFull(opts.perChat ?? 50).finally(() => {
				this.#running = null;
			});
		}
		return this.#running;
	}

	async #doFull(perChat: number): Promise<void> {
		this.#state = "syncing";
		try {
			const chats = await this.#src.listChats();
			this.#store.transaction(() => {
				for (const c of chats) {
					this.#store.upsertChat({ id: c.id, type: c.type, name: c.name, memberCount: c.memberCount ?? null });
					for (const m of c.members ?? []) this.#store.upsertParticipant(m.mid, m.displayName);
				}
			});
			const targets = this.scope === "all" ? chats.map((c) => c.id) : this.#store.listChats({ allowedOnly: true }).map((c) => c.id);
			for (const chatId of targets) {
				const msgs = await this.#src.recentMessages(chatId, perChat);
				this.#store.transaction(() => {
					for (const m of msgs) this.#write(m);
				});
			}
			this.#store.setSyncState("last_full_sync_at", String(Date.now()));
			this.#state = "idle";
			this.#lastError = null;
		} catch (e) {
			this.#state = "error";
			this.#lastError = (e as Error).message;
			throw e;
		}
	}

	/** 增量同步一次，回傳寫入的新訊息數。 */
	async pollOnce(): Promise<number> {
		const cursor = this.#store.getSyncState("talk_revision");
		const { ops, cursor: next } = await this.#src.pollOps(cursor);
		const inScope = (chatId: string) => this.scope === "all" || this.#store.getChat(chatId)?.allowed === 1;
		let added = 0;
		const fresh: { chatId: string; id: string; fromSelf: boolean }[] = [];
		this.#store.transaction(() => {
			for (const op of ops) {
				if (op.kind === "message" && op.message) {
					const m = op.message;
					if (!this.#store.getChat(m.chatId)) this.#store.upsertChat({ id: m.chatId, type: guessType(m.chatId), name: null });
					if (inScope(m.chatId) && this.#write(m)) {
						added++;
						fresh.push({ chatId: m.chatId, id: m.id, fromSelf: m.fromSelf });
					}
				} else if (op.kind === "read" && op.read) {
					// 這是「使用者在手機上讀了」的通知，只更新本機狀態，不會回寫 LINE。
					this.#store.setReadState(op.read.chatId, op.read.messageId, op.read.at);
				}
			}
			this.#store.setSyncState("talk_revision", next);
			this.#store.setSyncState("last_poll_at", String(Date.now()));
		});
		if (fresh.length && this.onNewMessages) {
			try {
				this.onNewMessages(fresh);
			} catch (e) {
				console.error("onNewMessages hook failed:", (e as Error).message);
			}
		}
		return added;
	}

	#write(m: SourceMessage): boolean {
		return this.#store.insertMessage({
			chatId: m.chatId,
			id: m.id,
			senderMid: m.senderMid,
			fromSelf: m.fromSelf,
			sentAt: m.sentAt,
			contentType: m.contentType,
			text: m.text,
			mediaName: m.mediaName,
			mediaSize: m.mediaSize,
			decryptState: m.decryptState,
			meta: m.meta,
		});
	}

	status(): SyncStatus {
		const s = this.#store.allSyncState();
		return {
			state: this.#running ? "syncing" : this.#state,
			lastFullSyncAt: s.last_full_sync_at ? Number(s.last_full_sync_at) : null,
			lastPollAt: s.last_poll_at ? Number(s.last_poll_at) : null,
			lastError: this.#lastError,
			cursor: s.talk_revision ?? null,
			counts: this.#store.counts(),
		};
	}
}

export function guessType(mid: string): "USER" | "GROUP" | "ROOM" | "SQUARE" {
	switch (mid[0]) {
		case "c":
			return "GROUP";
		case "r":
			return "ROOM";
		case "m":
			return "SQUARE";
		default:
			return "USER";
	}
}
