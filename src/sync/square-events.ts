/**
 * LINE 社群（Square / OpenChat）事件 → 被隱藏訊息。
 * 依 LINEJS thrift 定義：
 *   SquareEventType 5 = NOTIFIED_DESTROY_MESSAGE（payload.notifiedDestroyMessage { squareChatMid, messageId }）
 *   SquareMessage.state：1 SENT、2 DELETED、3 FORBIDDEN（管理員隱藏 / 被檢舉）、4 UNSENT
 *   ContentsAttribute 2 = CONTENTS_HIDDEN
 *   顯示文字「此訊息已被隱藏。」
 * 注意：本版只有這個轉換函式（有單元測試）；社群聊天的同步本身尚未接上（見 SECURITY-REVIEW-BRIEF 已知限制）。
 */
import { isHiddenText } from "../storage/db.ts";
import type { HiddenReason } from "./types.ts";

type Raw = Record<string, any>;

const STATE: Record<string, HiddenReason | null> = { "1": null, SENT: null, "2": "deleted", DELETED: "deleted", "3": "forbidden", FORBIDDEN: "forbidden", "4": "unsent", UNSENT: "unsent" };

export function squareHidden(ev: Raw): { chatId: string; messageId: string; reason: HiddenReason } | null {
	const type = String(ev?.type ?? "");
	const p = ev?.payload ?? {};
	if (type === "5" || type === "NOTIFIED_DESTROY_MESSAGE") {
		const d = p.notifiedDestroyMessage ?? p;
		if (d?.squareChatMid && d?.messageId) return { chatId: String(d.squareChatMid), messageId: String(d.messageId), reason: "unsent" };
		return null;
	}
	if (type === "0" || type === "1" || type === "RECEIVE_MESSAGE" || type === "SEND_MESSAGE") {
		const sm = p.receiveMessage?.squareMessage ?? p.sendMessage?.squareMessage ?? p.squareMessage;
		const msg = sm?.message;
		if (!msg?.id || !(msg.to ?? sm?.squareChatMid)) return null;
		const chatId = String(msg.to ?? sm.squareChatMid);
		const st = sm.state == null ? null : STATE[String(sm.state)] ?? null;
		if (st) return { chatId, messageId: String(msg.id), reason: st };
		const attr = msg.contentMetadata?.CONTENTS_ATTRIBUTE ?? sm.contentsAttribute;
		if (attr === 2 || attr === "2" || attr === "CONTENTS_HIDDEN") return { chatId, messageId: String(msg.id), reason: "forbidden" };
		if (isHiddenText(msg.text)) return { chatId, messageId: String(msg.id), reason: "hidden_text" };
	}
	return null;
}
