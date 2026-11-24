import type { LineSource, SourceChat, SourceMessage, SourceOp } from "../src/sync/types.ts";

export const ME = "u_me_000000000000000000000000000000";
export const ALICE = "u_alice_0000000000000000000000000000";
export const BOB = "u_bob_000000000000000000000000000000";
export const GROUP = "c_family_000000000000000000000000000";
export const SECRET = "c_secret_000000000000000000000000000";

const t0 = Date.parse("2026-11-24T10:00:00+08:00");

function msg(id: string, chatId: string, from: string, min: number, text: string | null, contentType = "NONE", extra: Partial<SourceMessage> = {}): SourceMessage {
	return { id, chatId, senderMid: from, fromSelf: from === ME, sentAt: t0 + min * 60_000, contentType, text, decryptState: "plain", ...extra };
}

/** 假的 LINE：三個會話＋可注入增量事件。永遠不連網。 */
export class FakeSource implements LineSource {
	pending: SourceOp[] = [];
	rev = 100;
	downloads = 0;
	chats: SourceChat[] = [
		{ id: ALICE, type: "USER", name: "Alice", members: [{ mid: ALICE, displayName: "Alice" }] },
		{ id: GROUP, type: "GROUP", name: "家人群組", memberCount: 3, members: [{ mid: BOB, displayName: "Bob" }, { mid: ALICE, displayName: "Alice" }] },
		{ id: SECRET, type: "GROUP", name: "機密群組", memberCount: 2, members: [] },
	];
	messages: Record<string, SourceMessage[]> = {
		[ALICE]: [
			msg("1001", ALICE, ALICE, 0, "今天晚餐吃什麼？"),
			msg("1002", ALICE, ME, 1, "吃拉麵好了"),
			msg("1003", ALICE, ALICE, 2, null, "IMAGE", { mediaName: "ramen.jpg", mediaSize: 4, meta: { FILE_NAME: "ramen.jpg" } }),
		],
		[GROUP]: [msg("2001", GROUP, BOB, 5, "週末一起去爬山"), msg("2002", GROUP, ALICE, 6, "好啊 我帶便當")],
		[SECRET]: [msg("3001", SECRET, BOB, 7, "這是機密：晚餐密碼 1234")],
	};

	async selfMid() {
		return ME;
	}
	async listChats() {
		return this.chats;
	}
	async recentMessages(chatId: string, limit: number) {
		return (this.messages[chatId] ?? []).slice(-limit);
	}
	async pollOps(_cursor: string | undefined) {
		const ops = this.pending;
		this.pending = [];
		if (ops.length) this.rev = Number(ops[ops.length - 1]!.revision);
		return { ops, cursor: String(this.rev) };
	}
	push(m: SourceMessage) {
		this.rev++;
		this.pending.push({ revision: String(this.rev), kind: "message", message: m });
	}
	pushRead(chatId: string, messageId: string, at: number) {
		this.rev++;
		this.pending.push({ revision: String(this.rev), kind: "read", read: { chatId, messageId, at } });
	}
	async downloadMedia(m: { id: string }) {
		this.downloads++;
		return { bytes: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), name: "ramen.jpg", mime: "image/jpeg", id: m.id };
	}
}

export { msg, t0 };
