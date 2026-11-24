import type { Store, ChatRow } from "./storage/db.ts";

/** 會話白名單錯誤：不區分「不存在」與「未允許」，避免洩漏會話是否存在。 */
export class ChatNotAllowedError extends Error {
	readonly code = "chat_not_allowed";
	constructor() {
		super("chat not found or not allowed for MCP access");
	}
}

export class Whitelist {
	#store: Store;
	constructor(store: Store) {
		this.#store = store;
	}
	isAllowed(chatId: string): boolean {
		return this.#store.getChat(chatId)?.allowed === 1;
	}
	/** 不在白名單就丟 ChatNotAllowedError。 */
	assert(chatId: string): ChatRow {
		const c = this.#store.getChat(chatId);
		if (!c || c.allowed !== 1) throw new ChatNotAllowedError();
		return c;
	}
	allowedIds(): string[] {
		return this.#store.listChats({ allowedOnly: true }).map((c) => c.id);
	}
	set(chatId: string, allowed: boolean): boolean {
		return this.#store.setAllowed(chatId, allowed);
	}
}
