import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join, basename, relative, resolve, sep } from "node:path";
import type { Store } from "../storage/db.ts";
import type { LineSource } from "../sync/types.ts";

/** 檔案快取：<root>/media/<chatId>/<messageId>-<安全檔名> */
export class MediaCache {
	#root: string;
	#store: Store;
	#src: LineSource | null;
	constructor(root: string, store: Store, src: LineSource | null) {
		this.#root = root;
		this.#store = store;
		this.#src = src;
	}

	/** 相對於資料目錄的路徑（給 MCP 回傳，不洩漏絕對路徑） */
	relative(path: string): string {
		return relative(this.#root, path);
	}

	cached(chatId: string, messageId: string) {
		const m = this.#store.getMedia(chatId, messageId);
		return m && existsSync(m.path) ? m : undefined;
	}

	async ensure(chatId: string, messageId: string): Promise<{ path: string; mime: string | null; size: number | null; cached: boolean }> {
		const hit = this.cached(chatId, messageId);
		if (hit) return { ...hit, cached: true };
		if (!this.#src) throw new Error("not online: no LINE source attached");
		const msg = this.#store.getMessage(chatId, messageId);
		if (!msg) throw new Error("message not found");
		if (msg.content_type === "NONE") throw new Error("message has no media");
		const meta = msg.meta_json ? (JSON.parse(msg.meta_json) as Record<string, unknown>) : null;
		const dl = await this.#src.downloadMedia({ chatId, id: messageId, contentType: msg.content_type, meta });
		const dir = join(this.#root, "media", safe(chatId));
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		const path = join(dir, `${safe(messageId)}-${safe(basename(dl.name || "file"))}`);
		// 縱深防禦：最終路徑一定在 <root>/media/ 底下
		const mediaRoot = resolve(this.#root, "media") + sep;
		if (!resolve(dir).concat(sep).startsWith(mediaRoot) || !resolve(path).startsWith(mediaRoot)) throw new Error("unsafe media path");
		writeFileSync(path, dl.bytes, { mode: 0o600 });
		this.#store.putMedia(chatId, messageId, path, dl.mime, dl.bytes.byteLength);
		return { path, mime: dl.mime, size: dl.bytes.byteLength, cached: false };
	}
}

function safe(s: string): string {
	const t = s.replace(/[^\w.\-]/g, "_").slice(0, 120);
	// 只由點組成（"."、".."）或空字串 → 不可當路徑段
	return !t || /^\.+$/.test(t) ? "_" + t.replace(/\./g, "_") : t;
}
