/**
 * 上游 RPC 守門員。
 *
 * LINEJS 所有 Talk / Square RPC 都會經過 `base.request.request(value, methodName, ...)`
 * （refs/linejs/packages/linejs/base/service/talk/mod.ts:314-322 的 sendChatChecked、
 *  base/service/square/mod.ts:57-62 的 markAsRead 皆是），所以在這裡依 methodName 攔截，
 * 連 `message.read()`（client/features/message/talk.ts:115-129）也會被擋。
 *
 * 1. 已讀回條：預設封鎖 sendChatChecked / markAsRead / markChatsAsRead / markThreadsAsRead，
 *    只有 isReadReceiptEnabled() 回傳 true 才放行。
 * 2. E2EE 金鑰註冊：預設封鎖（與 line-mcp-server docs/architecture.md「E2EE key boundaries」相同理由），
 *    避免 QR 登入沒收到金鑰時 LINEJS 自動註冊新金鑰對（base/login/mod.ts:302-304）。
 */
import { AsyncLocalStorage } from "node:async_hooks";

export const READ_RECEIPT_METHODS = new Set(["sendChatChecked", "markAsRead", "markChatsAsRead", "markThreadsAsRead"]);
/** 會從使用者帳號送出 / 修改訊息的 RPC：只能在 withSendPermit() 內呼叫（也就是只有 Outbox 的 sender 能送） */
export const SEND_METHODS = new Set([
	"sendMessage", "sendMessageAwaitCommit", "unsendMessage", "sendPostback", "react", "sendChatRemoved",
	// secreview SR-12：LINEJS 3.6.9 裡實際存在、會以使用者身分對外產生可見動作或改動帳號 / 聊天室的 RPC（本 App 沒有任何正常路徑會呼叫）
	"reactToMessage", "sendSquareThreadMessage", "createChat", "createRoomV2", "inviteIntoChat", "inviteIntoRoom",
	"acceptChatInvitation", "acceptChatInvitationByTicket", "deleteSelfFromChat", "deleteOtherFromChat", "leaveRoom",
	"updateChat", "blockContact", "updateProfileAttributes", "updateExtendedProfileAttribute", "updatePassword",
	"inviteIntoSquareChat", "inviteToSquare", "leaveSquare", "leaveSquareChat", "deleteSquare", "deleteSquareChat",
	"reportAbuseEx", "reportProfile", "reportSquare", "reportSquareChat", "reportSquareMember", "reportSquareMessage",
]);
const sendPermit = new AsyncLocalStorage<boolean>();
/** 只有 LinejsSender 會用：在這個 callback 範圍內才允許 SEND_METHODS */
export function withSendPermit<T>(fn: () => Promise<T>): Promise<T> {
	return sendPermit.run(true, fn);
}
export function hasSendPermit(): boolean {
	return sendPermit.getStore() === true;
}
export const KEY_REGISTRATION_METHODS = new Set(["registerE2EEPublicKey", "registerE2EEPublicKeyV2", "registerE2EEGroupKey"]);

export class UpstreamBlockedError extends Error {
	readonly code: "read_receipt_blocked" | "key_registration_blocked" | "send_blocked";
	readonly method: string;
	constructor(code: "read_receipt_blocked" | "key_registration_blocked" | "send_blocked", method: string) {
		super(`${method} is blocked by line-mcp-app (${code})`);
		this.code = code;
		this.method = method;
	}
}

export interface GuardOptions {
	/** 回傳 true 時才允許送出已讀。預設永遠 false。 */
	isReadReceiptEnabled?: () => boolean;
	/** 回傳 true 時才允許註冊 E2EE 金鑰。預設永遠 false。 */
	isKeyRegistrationEnabled?: () => boolean;
	/** 每次被擋或放行時的紀錄（不含內容）。 */
	log?: (entry: { event: "blocked" | "call"; method: string }) => void;
}

/** 最小介面：只需要 request.request 與（可選的）e2ee.registerE2EEKeyPair。 */
export interface GuardableClient {
	request: { request: (value: unknown, methodName: string, ...rest: unknown[]) => Promise<unknown> };
	e2ee?: { registerE2EEKeyPair?: (...a: unknown[]) => Promise<unknown> };
	obs?: { uploadObjTalk?: (...a: unknown[]) => Promise<unknown>; uploadMediaByE2EE?: (...a: unknown[]) => Promise<unknown> };
}

export function installUpstreamGuards(base: GuardableClient, opts: GuardOptions = {}): void {
	const readOn = opts.isReadReceiptEnabled ?? (() => false);
	const keyOn = opts.isKeyRegistrationEnabled ?? (() => false);
	const log = opts.log ?? (() => {});
	const original = base.request.request.bind(base.request);

	base.request.request = async (value: unknown, methodName: string, ...rest: unknown[]) => {
		if (READ_RECEIPT_METHODS.has(methodName) && !readOn()) {
			log({ event: "blocked", method: methodName });
			throw new UpstreamBlockedError("read_receipt_blocked", methodName);
		}
		if (KEY_REGISTRATION_METHODS.has(methodName) && !keyOn()) {
			log({ event: "blocked", method: methodName });
			throw new UpstreamBlockedError("key_registration_blocked", methodName);
		}
		if (SEND_METHODS.has(methodName) && !hasSendPermit()) {
			log({ event: "blocked", method: methodName });
			throw new UpstreamBlockedError("send_blocked", methodName);
		}
		log({ event: "call", method: methodName });
		return await original(value, methodName, ...rest);
	};

	// LINEJS 的 registerE2EEKeyPair 會吞掉失敗（base/e2ee/mod.ts:1043-1070），
	// 所以要在函式層直接丟錯，讓「沒收到金鑰」的登入明確失敗。
	if (base.e2ee?.registerE2EEKeyPair) {
		const reg = base.e2ee.registerE2EEKeyPair.bind(base.e2ee);
		base.e2ee.registerE2EEKeyPair = async (...a: unknown[]) => {
			if (!keyOn()) {
				log({ event: "blocked", method: "registerE2EEKeyPair" });
				throw new UpstreamBlockedError("key_registration_blocked", "registerE2EEKeyPair");
			}
			return await reg(...a);
		};
	}

	// 上傳到聊天室（uploadObjTalk 帶 tomid 時會直接在聊天室出現圖片）也只允許在 sender 內
	for (const fn of ["uploadObjTalk", "uploadMediaByE2EE"] as const) {
		const orig = base.obs?.[fn];
		if (!orig) continue;
		const bound = orig.bind(base.obs);
		base.obs![fn] = async (...a: unknown[]) => {
			if (!hasSendPermit()) {
				log({ event: "blocked", method: fn });
				throw new UpstreamBlockedError("send_blocked", fn);
			}
			return await bound(...a);
		};
	}
}
