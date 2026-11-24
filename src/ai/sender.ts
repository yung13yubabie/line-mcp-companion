import type { StickerRef } from "./stickers.ts";

/** 真正把訊息送進 LINE 的介面。只有 Outbox.processDue() 會呼叫。 */
export interface MessageSender {
	/** replyTo：引用回覆的訊息 id（LINE relatedMessageId） */
	sendText(chatId: string, text: string, opts?: { replyTo?: string | null }): Promise<void>;
	sendImage(chatId: string, bytes: Uint8Array, mime: string, name: string): Promise<void>;
	sendSticker(chatId: string, sticker: StickerRef, opts?: { replyTo?: string | null }): Promise<void>;
}

const offline = async () => {
	throw new Error("not online: no LINE session");
};
/** 未登入時的 sender：一律失敗 */
export const offlineSender: MessageSender = { sendText: offline, sendImage: offline, sendSticker: offline };
