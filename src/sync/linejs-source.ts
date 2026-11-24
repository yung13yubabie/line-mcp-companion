/**
 * 真實 LINE 來源（尚未對真帳號驗證；第一次真登入後要逐一確認欄位）。
 * 使用的 LINEJS API（refs/linejs/packages/linejs/）：
 *   - talk.getAllChatMids / talk.getChats        base/service/talk/mod.ts:1534-1578
 *   - talk.getRecentMessagesV2                    base/service/talk/mod.ts:1600-1610
 *   - talk.sync（長輪詢 revision）                base/service/talk/mod.ts:42-60、base/polling/mod.ts:91-135
 *   - e2ee.decryptE2EEMessage                     base/e2ee/mod.ts:696
 *   - obs.downloadMessageData / obs.downloadMediaByE2EE  base/obs/mod.ts:98-127、:435
 * 不呼叫 sendChatChecked / markAsRead（且 upstream-guard 會擋）。
 */
import type { BaseClient } from "@evex-dev/linejs/base";
import type { LineSource, SourceChat, SourceMessage, SourceOp } from "./types.ts";
import { guessType } from "./engine.ts";

type Raw = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export class LinejsSource implements LineSource {
	#base: BaseClient;
	constructor(base: BaseClient) {
		this.#base = base;
	}

	async selfMid(): Promise<string> {
		return this.#base.profile!.mid;
	}

	async listChats(): Promise<SourceChat[]> {
		const mids = (await this.#base.talk.getAllChatMids({ request: { withMemberChats: true, withInvitedChats: false }, syncReason: "INTERNAL" })) as Raw;
		const groupIds: string[] = mids.memberChatMids ?? [];
		const out: SourceChat[] = [];
		for (let i = 0; i < groupIds.length; i += 50) {
			const res = (await this.#base.talk.getChats({ chatMids: groupIds.slice(i, i + 50), withMembers: true, withInvitees: false })) as Raw;
			for (const c of res.chats ?? []) {
				const members = Object.keys(c.extra?.groupExtra?.memberMids ?? {}).map((mid) => ({ mid, displayName: null }));
				out.push({ id: c.chatMid, type: guessType(c.chatMid), name: c.chatName ?? null, memberCount: members.length || null, members });
			}
		}
		// 1 對 1 聊天：從好友清單補（getAllContactIds + getContacts）
		const contactIds = ((await this.#base.talk.getAllContactIds({ syncReason: "INTERNAL" } as never)) as string[]) ?? [];
		for (let i = 0; i < contactIds.length; i += 100) {
			const contacts = (await this.#base.talk.getContacts({ mids: contactIds.slice(i, i + 100) })) as Raw[];
			for (const ct of contacts) out.push({ id: ct.mid, type: "USER", name: ct.displayName ?? null, members: [{ mid: ct.mid, displayName: ct.displayName ?? null }] });
		}
		return out;
	}

	async recentMessages(chatId: string, limit: number): Promise<SourceMessage[]> {
		const raw = (await this.#base.talk.getRecentMessagesV2({ messageBoxId: chatId, messagesCount: limit })) as Raw[];
		const me = await this.selfMid();
		const out: SourceMessage[] = [];
		for (const m of raw ?? []) out.push(await this.#normalize(m, me));
		return out;
	}

	async pollOps(cursor: string | undefined): Promise<{ ops: SourceOp[]; cursor: string }> {
		const me = await this.selfMid();
		const res = (await this.#base.talk.sync({ revision: cursor ? BigInt(cursor) : 0n, limit: 100 })) as Raw;
		let next = cursor ?? "0";
		const ops: SourceOp[] = [];
		if (res.fullSyncResponse?.nextRevision !== undefined) next = String(res.fullSyncResponse.nextRevision);
		for (const op of res.operationResponse?.operations ?? []) {
			next = String(op.revision);
			if ((op.type === "RECEIVE_MESSAGE" || op.type === "SEND_MESSAGE") && op.message) {
				ops.push({ revision: next, kind: "message", message: await this.#normalize(op.message, me) });
			} else if (op.type === "NOTIFIED_READ_MESSAGE" && op.param2 === me) {
				// param1 = chat, param2 = 讀者, param3 = messageId（自己在其他裝置讀了）
				ops.push({ revision: next, kind: "read", read: { chatId: op.param1, messageId: String(op.param3), at: Number(op.createdTime) } });
			} else {
				ops.push({ revision: next, kind: "other" });
			}
		}
		return { ops, cursor: next };
	}

	async downloadMedia(msg: { chatId: string; id: string; contentType: string; meta: Record<string, unknown> | null }) {
		const e2ee = msg.meta && (msg.meta as Raw).e2eeVersion;
		let file: File | null;
		if (e2ee) {
			const raw = (await this.#base.talk.getRecentMessagesV2({ messageBoxId: msg.chatId, messagesCount: 200 })) as Raw[];
			const found = raw.find((m) => String(m.id) === msg.id);
			if (!found) throw new Error("message not found upstream for E2EE media download");
			file = await this.#base.obs.downloadMediaByE2EE(found as never);
		} else {
			file = await this.#base.obs.downloadMessageData({ messageId: msg.id });
		}
		if (!file) throw new Error("media download returned nothing");
		return { bytes: new Uint8Array(await file.arrayBuffer()), name: file.name, mime: file.type || null };
	}

	async #normalize(m: Raw, me: string): Promise<SourceMessage> {
		let decryptState: SourceMessage["decryptState"] = "plain";
		let text: string | null = m.text ?? null;
		if (m.chunks?.length) {
			try {
				const d = (await this.#base.e2ee.decryptE2EEMessage(m as never)) as Raw;
				text = d.text ?? null;
				decryptState = "decrypted";
			} catch {
				decryptState = "missing_key";
			}
		}
		const toType = m.toType;
		const chatId = toType === "USER" || toType === 0 ? (m.from === me ? m.to : m.from) : m.to;
		const meta = m.contentMetadata ?? null;
		return {
			id: String(m.id),
			chatId,
			senderMid: m.from ?? null,
			fromSelf: m.from === me,
			sentAt: Number(m.createdTime),
			contentType: String(m.contentType ?? "NONE"),
			text,
			mediaName: meta?.FILE_NAME ?? null,
			mediaSize: meta?.FILE_SIZE ? Number(meta.FILE_SIZE) : null,
			decryptState,
			meta,
		};
	}
}
