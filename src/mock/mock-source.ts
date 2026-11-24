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
		{ id: "c_mock_family", type: "GROUP", name: "林家家族群組", memberCount: 6, members: [{ mid: "u_mock_dad", displayName: "爸爸" }, { mid: "u_mock_mom", displayName: "媽媽" }, { mid: "u_mock_sis", displayName: "妹妹" }] },
		{ id: "c_mock_work", type: "GROUP", name: "專案 A 開發群", memberCount: 12, members: [{ mid: "u_mock_pm", displayName: "PM 小陳" }, { mid: "u_mock_dev", displayName: "工程師阿哲" }] },
		{ id: "u_mock_friend", type: "USER", name: "阿明", members: [{ mid: "u_mock_friend", displayName: "阿明" }] },
		{ id: "c_mock_private", type: "GROUP", name: "（私密）理財討論", memberCount: 3, members: [{ mid: "u_mock_bank", displayName: "理專" }] },
	];
	messages: Record<string, SourceMessage[]> = {
		u_mock_mom: [
			m("9001", "u_mock_mom", "u_mock_mom", 0, "今天晚餐要回來吃嗎？"),
			m("9002", "u_mock_mom", ME, 3, "會，大概七點到"),
			m("9003", "u_mock_mom", "u_mock_mom", 5, null, { contentType: "IMAGE", mediaName: "dinner.png", mediaSize: PNG.length, meta: { FILE_NAME: "dinner.png" } }),
			m("9004", "u_mock_mom", "u_mock_mom", 6, "煮了你愛吃的滷肉"),
		],
		c_mock_family: [
			m("9101", "c_mock_family", "u_mock_dad", 10, "週六中午聚餐，餐廳我訂好了"),
			m("9102", "c_mock_family", "u_mock_sis", 12, "好耶！要帶什麼嗎？"),
			m("9103", "c_mock_family", "u_mock_mom", 13, "帶水果就好"),
		],
		c_mock_work: [
			m("9201", "c_mock_work", "u_mock_pm", 30, "明天 10:00 sprint review，記得更新進度"),
			m("9202", "c_mock_work", "u_mock_dev", 32, "MCP server 已經可以在手機上跑了"),
			m("9203", "c_mock_work", ME, 35, "收到，我會準備 demo", {}),
			m("9204", "c_mock_work", "u_mock_pm", 40, null, { contentType: "FILE", mediaName: "spec-v1.1.pdf", mediaSize: 2048, meta: { FILE_NAME: "spec-v1.1.pdf" } }),
		],
		u_mock_friend: [m("9301", "u_mock_friend", "u_mock_friend", 50, "晚點打球？"), m("9302", "u_mock_friend", ME, 51, "八點可以")],
		c_mock_private: [m("9401", "c_mock_private", "u_mock_bank", 60, "（這個會話預設未勾選，MCP 看不到）")],
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
	async pollOps(cursor: string | undefined): Promise<{ ops: SourceOp[]; cursor: string }> {
		await new Promise((r) => setTimeout(r, 30_000)); // 模擬長輪詢，沒有新事件
		return { ops: [], cursor: cursor ?? "1" };
	}
	async downloadMedia(msg: { id: string; contentType: string }) {
		if (msg.contentType === "FILE") return { bytes: new TextEncoder().encode("%PDF-1.4 mock\n"), name: "spec-v1.1.pdf", mime: "application/pdf" };
		return { bytes: PNG, name: "dinner.png", mime: "image/png" };
	}
}

/** 預設勾選（白名單）的 mock 會話；私密群組刻意不勾 */
export const MOCK_DEFAULT_ALLOWED = ["u_mock_mom", "c_mock_family", "c_mock_work"];
