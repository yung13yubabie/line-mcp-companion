import type { ChatType } from "../storage/db.ts";

export interface SourceChat {
	id: string;
	type: ChatType;
	name: string | null;
	memberCount?: number | null;
	members?: { mid: string; displayName: string | null }[];
}

export interface SourceMessage {
	id: string;
	chatId: string;
	senderMid: string | null;
	fromSelf: boolean;
	sentAt: number;
	contentType: string; // NONE | IMAGE | VIDEO | AUDIO | FILE | STICKER ...
	text: string | null;
	mediaName?: string | null;
	mediaSize?: number | null;
	decryptState: "plain" | "decrypted" | "missing_key" | "invalid";
	meta?: Record<string, unknown> | null;
}

export interface SourceOp {
	revision: string;
	kind: "message" | "read" | "chat_update" | "other";
	message?: SourceMessage;
	/** kind=read：本帳號在其他裝置把此會話讀到哪（NOTIFIED_READ_MESSAGE 自己的部分） */
	read?: { chatId: string; messageId: string; at: number };
	chatId?: string;
}

/**
 * 同步來源介面。真實實作是 LinejsSource（src/sync/linejs-source.ts），
 * 測試用 FakeSource（test/fake-source.ts）。所有方法只讀，絕不送已讀。
 */
export interface LineSource {
	selfMid(): Promise<string>;
	listChats(): Promise<SourceChat[]>;
	recentMessages(chatId: string, limit: number): Promise<SourceMessage[]>;
	/** 長輪詢一次；cursor 為上次回傳的 revision（字串）。 */
	pollOps(cursor: string | undefined): Promise<{ ops: SourceOp[]; cursor: string }>;
	downloadMedia(msg: { chatId: string; id: string; contentType: string; meta: Record<string, unknown> | null }): Promise<{ bytes: Uint8Array; name: string; mime: string | null }>;
}
