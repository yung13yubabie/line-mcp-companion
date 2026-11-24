/**
 * 真實 LINE 發送器（未對真帳號驗證）。只被 Outbox.processDue() 呼叫。
 * 透過 withSendPermit() 取得 upstream-guard 的發送許可；其他程式路徑呼叫 sendMessage 會被擋。
 * LINEJS：base.talk.sendMessage（base/service/talk/mod.ts:92；relatedMessageId = 引用回覆；遇到 E2EE 會自動改用加密重送）
 *         貼圖：contentType STICKER + contentMetadata { STKPKGID, STKID, STKVER }
 *         base.obs.uploadObjTalk（obs/mod.ts:156）/ uploadMediaByE2EE（obs/mod.ts:294）
 */
import type { BaseClient } from "@evex-dev/linejs/base";
import { withSendPermit } from "../guard/upstream-guard.ts";
import type { MessageSender } from "./sender.ts";
import type { StickerRef } from "./stickers.ts";

export class LinejsSender implements MessageSender {
	#base: BaseClient;
	constructor(base: BaseClient) {
		this.#base = base;
	}
	async sendText(chatId: string, text: string, opts: { replyTo?: string | null } = {}): Promise<void> {
		await withSendPermit(() => this.#base.talk.sendMessage({ to: chatId, text, relatedMessageId: opts.replyTo ?? undefined }));
	}
	async sendSticker(chatId: string, s: StickerRef, opts: { replyTo?: string | null } = {}): Promise<void> {
		await withSendPermit(() =>
			this.#base.talk.sendMessage({
				to: chatId,
				contentType: "STICKER" as never,
				contentMetadata: { STKPKGID: String(s.package_id), STKID: String(s.sticker_id), STKVER: String(s.version ?? "1") },
				relatedMessageId: opts.replyTo ?? undefined,
			}),
		);
	}
	async sendImage(chatId: string, bytes: Uint8Array, mime: string, name: string): Promise<void> {
		const blob = new Blob([bytes as unknown as ArrayBuffer], { type: mime });
		await withSendPermit(async () => {
			try {
				await this.#base.obs.uploadMediaByE2EE({ data: blob, oType: "image", to: chatId, filename: name });
			} catch {
				// 非 E2EE 會話（或對方沒有金鑰）→ 一般上傳
				await this.#base.obs.uploadObjTalk(chatId, "image", blob, undefined, name);
			}
		});
	}
}
