/**
 * Mock 模式資料來源（只給 UI 示範與 MCP 互通測試用）。
 * ⚠️ 只在 debug 建置存在：release bundle 以 LMA_INCLUDE_MOCK="0" 建置，這個檔案不會被打包
 * （scripts/purge-mock-check.sh 會檢查 APK 裡沒有 MOCK_MARKER）。
 * 資料存在獨立的 <home>/mock/line.db，與真實資料庫完全分開。
 */
import type { LineSource, SourceChat, SourceMessage, SourceOp } from "../sync/types.ts";

export const MOCK_MARKER = "LMA_MOCK_DATA_v1";
const ME = "u_mock_me";
const base = Date.parse("2026-11-24T09:00:00+08:00");
const min = (m: number) => base + m * 60_000;

function m(id: string, chatId: string, from: string, at: number, text: string | null, extra: Partial<SourceMessage> = {}): SourceMessage {
	return { id, chatId, senderMid: from, fromSelf: from === ME, sentAt: min(at), contentType: "NONE", text, decryptState: "plain", ...extra };
}

// 1x1 綠色 PNG
const PNG = Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAEBgIApD5fRAAAAABJRU5ErkJggg==", "base64"));

export class MockSource implements LineSource {
	readonly marker = MOCK_MARKER;
	chats: SourceChat[] = [
		{ id: "u_mock_mom", type: "USER", name: "媽媽", members: [{ mid: "u_mock_mom", displayName: "媽媽" }] },
		{ id: "c_mock_family", type: "GROUP", name: "家族群組", memberCount: 6, members: [{ mid: "u_mock_dad", displayName: "爸爸" }, { mid: "u_mock_mom", displayName: "媽媽" }, { mid: "u_mock_sis", displayName: "妹妹" }] },
		{ id: "c_mock_work", type: "GROUP", name: "專案 A 開發群", memberCount: 12, members: [{ mid: "u_mock_pm", displayName: "PM 小陳" }, { mid: "u_mock_dev", displayName: "工程師阿哲" }] },
		{ id: "u_mock_friend", type: "USER", name: "阿明", members: [{ mid: "u_mock_friend", displayName: "阿明" }] },
		{ id: "c_mock_private", type: "GROUP", name: "（私密）理財討論", memberCount: 3, members: [{ mid: "u_mock_bank", displayName: "理專" }] },
		{ id: "c_mock_hood", type: "GROUP", name: "社區住戶交流群", memberCount: 86, members: [{ mid: "u_mock_n1", displayName: "管委會小李" }, { mid: "u_mock_n2", displayName: "財富自由Amy" }, { mid: "u_mock_n3", displayName: "社區管理員(官方)" }, { mid: "u_mock_n4", displayName: "3F 陳太太" }] },
	];
	messages: Record<string, SourceMessage[]> = {
		u_mock_mom: [
			m("9001", "u_mock_mom", "u_mock_mom", 0, "今天晚餐要回來吃嗎？"),
			m("9002", "u_mock_mom", ME, 3, "會，大概七點到"),
			m("9003", "u_mock_mom", "u_mock_mom", 5, null, { contentType: "IMAGE", mediaName: "dinner.png", mediaSize: PNG.length, meta: { FILE_NAME: "dinner.png" } }),
			m("9004", "u_mock_mom", "u_mock_mom", 6, "煮了你愛吃的滷肉"),
			m("9005", "u_mock_mom", ME, 7, null, { contentType: "STICKER", meta: { STKPKGID: "11537", STKID: "52002734", STKVER: "1", STKTXT: "[開心]" } }),
			m("9006", "u_mock_mom", "u_mock_mom", 8, null, { contentType: "STICKER", meta: { STKPKGID: "11538", STKID: "51626501", STKVER: "1", STKTXT: "[愛心]" } }),
		],
		c_mock_family: [
			m("9101", "c_mock_family", "u_mock_dad", 10, "週六中午聚餐，餐廳我訂好了"),
			m("9102", "c_mock_family", "u_mock_sis", 12, "好耶！要帶什麼嗎？"),
			m("9103", "c_mock_family", "u_mock_mom", 13, "帶水果就好"),
			m("9104", "c_mock_family", ME, 14, null, { contentType: "STICKER", meta: { STKPKGID: "11537", STKID: "52002739", STKVER: "1", STKTXT: "[OK]" } }),
			m("9105", "c_mock_family", "u_mock_dad", 15, "週六 12:00 在老地方，記得帶水果喔", { meta: { relatedMessageId: "9103" } }),
		],
		c_mock_work: [
			m("9201", "c_mock_work", "u_mock_pm", 30, "明天 10:00 sprint review，記得更新進度"),
			m("9202", "c_mock_work", "u_mock_dev", 32, "MCP server 已經可以在手機上跑了"),
			m("9203", "c_mock_work", ME, 35, "收到，我會準備 demo", {}),
			m("9204", "c_mock_work", "u_mock_pm", 40, null, { contentType: "FILE", mediaName: "spec-v1.1.pdf", mediaSize: 2048, meta: { FILE_NAME: "spec-v1.1.pdf" } }),
		],
		u_mock_friend: [m("9301", "u_mock_friend", "u_mock_friend", 50, "晚點打球？"), m("9302", "u_mock_friend", ME, 51, "八點可以")],
		c_mock_private: [m("9401", "c_mock_private", "u_mock_bank", 60, "（這個會話預設未勾選，MCP 看不到）")],
		// 反詐示範：以下為依官方公告改寫的示意句，ID / 網址皆為虛構
		c_mock_hood: [
			m("9501", "c_mock_hood", "u_mock_n1", 70, "提醒大家這週六早上 9 點電梯保養，請改走樓梯"),
			m("9502", "c_mock_hood", "u_mock_n3", 72, "各位住戶好，本群廣告太多，明天將解散，請大家加入新群 👉 line.me/ti/g2/mockFAKE123"),
			m("9503", "c_mock_hood", "u_mock_n2", 74, "老師今天盤前精選一檔飆股，跟單學員已經翻倍，名額只剩 5 位，想跟的加我 LINE ID: mock_amy888"),
			m("9504", "c_mock_hood", "u_mock_n4", 76, "上面那個是詐騙嗎？大家不要亂加喔"),
			m("9505", "c_mock_hood", "u_mock_n2", 78, "您的包裹地址有誤，請於今日點擊 reurl.cc/mOcK1 完成實名驗證，逾期退回"),
		],
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
	/** 模擬「上線後才收到」的訊息（示範反詐即時提醒與 AI 建議） */
	live: SourceMessage[] = [
		{ id: "9506", chatId: "c_mock_hood", senderMid: "u_mock_n3", fromSelf: false, sentAt: 0, contentType: "NONE", text: "這個群要關了，請大家換群到新群組 👉 line.me/ti/g2/mockNEW456 ，明天前沒加入的會被移除", decryptState: "plain" },
	];
	liveDelayMs = 20_000;
	async pollOps(cursor: string | undefined): Promise<{ ops: SourceOp[]; cursor: string }> {
		if (this.live.length) {
			await new Promise((r) => setTimeout(r, this.liveDelayMs));
			const msgs = this.live.splice(0).map((x) => ({ ...x, sentAt: Date.now() }));
			for (const x of msgs) (this.messages[x.chatId] ??= []).push(x);
			return { ops: msgs.map((message) => ({ revision: "2", kind: "message" as const, message })), cursor: "2" };
		}
		await new Promise((r) => setTimeout(r, 30_000)); // 模擬長輪詢，沒有新事件
		return { ops: [], cursor: cursor ?? "1" };
	}
	async downloadMedia(msg: { id: string; contentType: string }) {
		if (msg.contentType === "FILE") return { bytes: new TextEncoder().encode("%PDF-1.4 mock\n"), name: "spec-v1.1.pdf", mime: "application/pdf" };
		return { bytes: PNG, name: "dinner.png", mime: "image/png" };
	}
}

/** 預設勾選（白名單）的 mock 會話；私密群組刻意不勾 */
export const MOCK_DEFAULT_ALLOWED = ["u_mock_mom", "c_mock_family", "c_mock_work", "c_mock_hood"];
/** AI 代聊白名單的 mock 預設（兩個白名單都要勾才生效） */
export const MOCK_AI_ALLOWED = ["u_mock_mom", "c_mock_work"];
