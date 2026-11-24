/**
 * LINE 貼圖。個人帳號只能送「自己擁有」的貼圖，所以 AI 只能從「我曾經送過的貼圖」清單挑
 * （從已同步的訊息 metadata 學來：STKPKGID / STKID / STKVER / STKTXT）。
 * 使用者可以替貼圖加標籤（例如「開心」「OK」「謝謝」），AI 依標籤選。
 */
import type { Store } from "../storage/db.ts";

export interface StickerRef {
	package_id: string;
	sticker_id: string;
	version?: string;
}

export interface StickerEntry extends StickerRef {
	label: string | null;
	text: string | null; // LINE 的 STKTXT（例如 "[開心]"）
	uses: number;
	owned: boolean; // 我自己送過 → 可送
}

const ID = /^\d{1,12}$/;

export function validSticker(r: unknown): r is StickerRef {
	const x = r as StickerRef;
	return !!x && ID.test(String(x.package_id)) && ID.test(String(x.sticker_id)) && (x.version === undefined || /^\d{1,6}$/.test(String(x.version)));
}

export function stickerUrl(stickerId: string): string {
	if (!ID.test(stickerId)) throw new Error("bad sticker id");
	return `https://stickershop.line-scdn.net/stickershop/v1/sticker/${stickerId}/android/sticker.png`;
}

export class StickerCatalog {
	#store: Store;
	constructor(store: Store) {
		this.#store = store;
	}

	#labels(): Record<string, string> {
		try {
			return JSON.parse(this.#store.getSetting("sticker_labels") ?? "{}") as Record<string, string>;
		} catch {
			return {};
		}
	}

	setLabel(stickerId: string, label: string | null): void {
		if (!ID.test(stickerId)) throw new Error("bad sticker id");
		const l = this.#labels();
		if (label && label.trim()) l[stickerId] = label.trim().slice(0, 20);
		else delete l[stickerId];
		this.#store.setSetting("sticker_labels", JSON.stringify(l));
	}

	list(opts: { ownedOnly?: boolean; limit?: number } = {}): StickerEntry[] {
		const rows = this.#store.db
			.prepare(
				`SELECT json_extract(meta_json,'$.STKPKGID') AS pkg, json_extract(meta_json,'$.STKID') AS id,
				        MAX(json_extract(meta_json,'$.STKVER')) AS ver, MAX(json_extract(meta_json,'$.STKTXT')) AS txt,
				        COUNT(*) AS uses, MAX(from_self) AS owned
				 FROM message WHERE content_type='STICKER' AND meta_json IS NOT NULL AND json_valid(meta_json)
				 GROUP BY pkg, id ORDER BY owned DESC, uses DESC LIMIT ?`,
			)
			.all(Math.min(500, opts.limit ?? 200)) as { pkg: unknown; id: unknown; ver: unknown; txt: unknown; uses: number; owned: number }[];
		const labels = this.#labels();
		return rows
			.filter((r) => ID.test(String(r.pkg)) && ID.test(String(r.id)))
			.map((r) => ({
				package_id: String(r.pkg),
				sticker_id: String(r.id),
				version: r.ver == null ? undefined : String(r.ver),
				label: labels[String(r.id)] ?? null,
				text: r.txt == null ? null : String(r.txt).slice(0, 30),
				uses: Number(r.uses),
				owned: r.owned === 1,
			}))
			.filter((e) => !opts.ownedOnly || e.owned);
	}

	/** 只有「我送過」的貼圖可以送 */
	isSendable(ref: StickerRef): boolean {
		return this.list({ ownedOnly: true }).some((e) => e.package_id === String(ref.package_id) && e.sticker_id === String(ref.sticker_id));
	}

	find(stickerId: string): StickerEntry | undefined {
		return this.list().find((e) => e.sticker_id === stickerId);
	}

	/** 給模型看的精簡清單（只含可送的） */
	promptList(max = 24): { key: string; label: string }[] {
		return this.list({ ownedOnly: true })
			.slice(0, max)
			.map((e) => ({ key: e.sticker_id, label: e.label ?? e.text ?? "貼圖" }));
	}
}
