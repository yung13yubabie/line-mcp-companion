/**
 * Mock AI 供應商 + Mock 發送器（僅 debug 的 Mock 模式；release bundle 會換成 mock-ai-stub.ts）。
 * 完全不連網：回覆是固定模板，圖片是程式產生的 PNG，「送出」只寫進 mock 資料庫。
 */
import { deflateSync } from "node:zlib";
import type { AiProvider, AiCapabilities } from "../ai/provider.ts";
import type { ChatMsg } from "../ai/prompt.ts";
import type { MessageSender } from "../ai/sender.ts";
import type { StickerRef } from "../ai/stickers.ts";
import type { Store } from "../storage/db.ts";

export const MOCK_AI_MARKER = "LMA_MOCK_AI_v1";

export class MockAiProvider implements AiProvider {
	readonly kind = "mock" as const;
	readonly marker = MOCK_AI_MARKER;
	calls = 0;
	async chat(messages: ChatMsg[]): Promise<string> {
		this.calls++;
		const user = messages.find((m) => m.role === "user")?.content ?? "";
		if (/sprint|demo|進度/.test(user)) return "好的，我明天 10 點前會把進度更新好，demo 也準備中 👍";
		if (/晚餐|滷肉|回來吃/.test(user)) return "好啊，我七點左右到家，謝謝媽 ❤️";
		if (/聚餐|水果/.test(user)) return "收到！我會帶水果過去～";
		return "收到，我晚點再詳細回你喔！";
	}
	async generateImage(prompt: string): Promise<{ bytes: Uint8Array; mime: string }> {
		this.calls++;
		return { bytes: mockPng(prompt), mime: "image/png" };
	}
	async detect(): Promise<AiCapabilities> {
		return { text: true, vision: true, image_gen: true, voice: false, models: ["mock-chat", "mock-image"], checked_at: Date.now(), heuristic: false };
	}
}

/** 「送出」= 寫入本機 mock 資料庫（from_self），UI 會看到；不連網 */
export class MockSender implements MessageSender {
	#store: Store;
	#seq = 0;
	sent: { chatId: string; kind: string; text?: string }[] = [];
	constructor(store: Store) {
		this.#store = store;
	}
	async sendText(chatId: string, text: string, opts: { replyTo?: string | null } = {}): Promise<void> {
		this.sent.push({ chatId, kind: "text", text });
		this.#store.insertMessage({ chatId, id: `98${Date.now()}${this.#seq++}`, senderMid: "u_mock_me", fromSelf: true, sentAt: Date.now(), contentType: "NONE", text, meta: opts.replyTo ? { relatedMessageId: opts.replyTo } : null });
	}
	async sendSticker(chatId: string, s: StickerRef, opts: { replyTo?: string | null } = {}): Promise<void> {
		this.sent.push({ chatId, kind: "sticker" });
		this.#store.insertMessage({
			chatId,
			id: `98${Date.now()}${this.#seq++}`,
			senderMid: "u_mock_me",
			fromSelf: true,
			sentAt: Date.now(),
			contentType: "STICKER",
			text: null,
			meta: { STKPKGID: s.package_id, STKID: s.sticker_id, STKVER: s.version ?? "1", ...(opts.replyTo ? { relatedMessageId: opts.replyTo } : {}) },
		});
	}
	async sendImage(chatId: string, bytes: Uint8Array, _mime: string, name: string): Promise<void> {
		this.sent.push({ chatId, kind: "image" });
		this.#store.insertMessage({ chatId, id: `98${Date.now()}${this.#seq++}`, senderMid: "u_mock_me", fromSelf: true, sentAt: Date.now(), contentType: "IMAGE", text: null, mediaName: name, mediaSize: bytes.byteLength });
	}
}

/** 64x64 漸層 PNG（顏色由 prompt 雜湊決定） */
function mockPng(seed: string): Uint8Array {
	let h = 0;
	for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0;
	const W = 64;
	const raw = Buffer.alloc((W * 3 + 1) * W);
	for (let y = 0; y < W; y++) {
		raw[y * (W * 3 + 1)] = 0;
		for (let x = 0; x < W; x++) {
			const o = y * (W * 3 + 1) + 1 + x * 3;
			raw[o] = (h & 0xff) ^ (x * 4);
			raw[o + 1] = ((h >> 8) & 0xff) ^ (y * 4);
			raw[o + 2] = (h >> 16) & 0xff;
		}
	}
	const chunk = (type: string, data: Buffer) => {
		const len = Buffer.alloc(4);
		len.writeUInt32BE(data.length);
		const td = Buffer.concat([Buffer.from(type), data]);
		const crc = Buffer.alloc(4);
		crc.writeUInt32BE(crc32(td));
		return Buffer.concat([len, td, crc]);
	};
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(W, 0);
	ihdr.writeUInt32BE(W, 4);
	ihdr[8] = 8;
	ihdr[9] = 2;
	return new Uint8Array(Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]));
}

function crc32(b: Buffer): number {
	let c = ~0;
	for (const x of b) {
		c ^= x;
		for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
	}
	return ~c >>> 0;
}
