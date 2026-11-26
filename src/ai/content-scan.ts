/**
 * 內容正規化與聯絡方式偵測（M-1 / M-2 / M-3 / M-11）。
 *
 * 所有「這段文字有沒有網址／聯絡方式／注入句」的判斷都先走 normalizeForScan：
 *   NFKC（全形 → 半形）→ 去掉零寬／格式字元 → 還原常見 defang（[.]、(.)、hxxp、「點」）。
 * 之後才做網址、裸網域、IP、電話、LINE ID、Email 偵測。偵測寧可多報：多報只會多一次人工確認。
 */

// 零寬、雙向控制、軟連字號、變體選擇器、Mongolian vowel separator、BOM、tag 字元
const INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]|\uDB40[\uDC00-\uDC7F]/g;

export function normalizeForScan(s: string | null | undefined): string {
	if (!s) return "";
	let t = s.normalize("NFKC").replace(INVISIBLE, "");
	t = t
		// defang：[.] (.) {.} [dot] (dot) <.> 以及前後空白
		.replace(/\s*[[({<]\s*(?:\.|dot|點)\s*[\])}>]\s*/gi, ".")
		.replace(/(?<=[a-z0-9])\s+(?:dot|點)\s+(?=[a-z0-9])/gi, ".")
		// 中文句點、頓號夾在英數字中間 → .
		.replace(/(?<=[a-z0-9])\s*[。｡、]\s*(?=[a-z0-9])/gi, ".")
		// hxxp / hXXps / h**p
		.replace(/\bh(?:xx|\*\*|XX|tt)p(s?)\s*(?:\[:\]|:)\s*\/\s*\//gi, "http$1://")
		.replace(/\[:\]/g, ":")
		// "example . com" 這種點前後加空白（只在兩邊都是英數時）
		.replace(/(?<=[a-z0-9])\s+\.\s*(?=[a-z]{2,})|(?<=[a-z0-9])\s*\.\s+(?=[a-z]{2,}\b)/gi, ".");
	return t;
}

// 不當作網域的副檔名（降低「report.pdf」這類誤報）
// zip / mov / md 同時也是公開 TLD，不可無條件當檔名略過。
const FILE_EXT = new Set(["txt", "jpg", "jpeg", "png", "gif", "webp", "heic", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "rar", "mp3", "mp4", "js", "ts", "json", "html", "exe", "apk", "kt"]);

const RE = {
	url: /\b(?:[a-z][a-z0-9+.-]{1,15}):\/\/[^\s]+/gi,
	www: /\bwww\.[^\s]+/gi,
	email: /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
	ipv4: /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.]*\d)(?::\d{1,5})?(?:\/[^\s]*)?/g,
	ipv6: /\[[0-9a-f:.]{3,}\](?::\d{1,5})?(?:\/[^\s]*)?|(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi,
	domain: /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}|xn--[a-z0-9-]{2,30})(?![\w-])(?::\d{1,5})?(?:\/[^\s]*)?/gi,
	// LINE：line id / 賴 / 加line / line:xxx / @官方帳號 / line.me、lin.ee 由 domain 抓
	lineId: /(?:(?:\bline\s*id|line\s*帳號?|加\s*line|加?賴|\bid)\s*[:：=]?\s*|\bline\s*[:：=@]\s*)@?[a-z0-9._-]{3,30}/gi,
	atId: /(?<![\w@])@[a-z0-9._-]{4,20}(?![\w@])/gi,
	// 電話：台灣手機 / 市話 / 國際格式；分隔符號允許空白、-、.、()
	phone: /(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?!\d)/g,
};

export type ContactKind = "url" | "domain" | "ip" | "email" | "phone" | "line_id";

function phoneLike(m: string): boolean {
	const d = m.replace(/\D/g, "");
	if (d.length < 8 || d.length > 15) return false;
	// 純年份日期（2026-11-25）或時間不算
	if (/^\d{4}[-./]\d{1,2}[-./]\d{1,2}$/.test(m.trim())) return false;
	return true;
}

function domainLike(m: string, tld: string): boolean {
	return !FILE_EXT.has(tld.toLowerCase()) || /\//.test(m);
}

/** 偵測文字中的網址／聯絡方式種類 */
export function scanContacts(s: string | null | undefined): { kinds: ContactKind[]; normalized: string } {
	const n = normalizeForScan(s);
	const kinds = new Set<ContactKind>();
	if (!n) return { kinds: [], normalized: n };
	if (RE.url.test(n) || new RegExp(RE.www.source, "i").test(n)) kinds.add("url");
	RE.url.lastIndex = 0;
	const noEmail = n.replace(RE.email, (m) => (kinds.add("email"), " "));
	if (new RegExp(RE.ipv4.source).test(noEmail) || new RegExp(RE.ipv6.source, "i").test(noEmail)) kinds.add("ip");
	for (const m of noEmail.matchAll(new RegExp(RE.domain.source, "gi"))) if (domainLike(m[0], m[1]!)) kinds.add("domain");
	if (new RegExp(RE.lineId.source, "i").test(noEmail) || new RegExp(RE.atId.source, "i").test(noEmail)) kinds.add("line_id");
	for (const m of noEmail.matchAll(new RegExp(RE.phone.source, "g"))) if (phoneLike(m[0])) kinds.add("phone");
	return { kinds: [...kinds], normalized: n };
}

export const hasLink = (s: string | null | undefined) => scanContacts(s).kinds.some((k) => k === "url" || k === "domain" || k === "ip");

/**
 * 把網址／網域／IP／Email／電話／LINE ID 換成標記。沒偵測到就回原字串（不改動全形標點）；
 * 偵測到時回傳正規化後再遮蔽的版本。
 */
export function maskContacts(s: string, opts: { phone?: boolean } = {}): string {
	const { kinds, normalized } = scanContacts(s);
	if (!kinds.length) return s;
	let t = normalized
		.replace(new RegExp(RE.url.source, "gi"), "［連結］")
		.replace(new RegExp(RE.www.source, "gi"), "［連結］")
		.replace(new RegExp(RE.email.source, "gi"), "［Email］")
		.replace(new RegExp(RE.ipv6.source, "gi"), (m) => (m.includes(":") && /[0-9a-f]/i.test(m) && m.split(":").length > 2 ? "［連結］" : m))
		.replace(new RegExp(RE.ipv4.source, "g"), "［連結］")
		.replace(new RegExp(RE.domain.source, "gi"), (m, tld: string) => (domainLike(m, tld) ? "［連結］" : m))
		.replace(new RegExp(RE.lineId.source, "gi"), "［LINE ID］")
		.replace(new RegExp(RE.atId.source, "gi"), "［LINE ID］");
	if (opts.phone !== false) t = t.replace(new RegExp(RE.phone.source, "g"), (m) => (phoneLike(m) ? "［電話］" : m));
	return t;
}

/** 輸出中的每個網址／網域都要逐字出現在可信來源文字裡才算「引用」 */
export function linksNotIn(output: string, trusted: string[]): boolean {
	const out = normalizeForScan(output).toLowerCase();
	const pool = trusted.map((x) => normalizeForScan(x).toLowerCase()).join("\n");
	const found = [
		...out.matchAll(new RegExp(RE.url.source, "gi")),
		...out.matchAll(new RegExp(RE.www.source, "gi")),
		...out.matchAll(new RegExp(RE.ipv4.source, "g")),
		...out.matchAll(new RegExp(RE.ipv6.source, "gi")),
		...[...out.matchAll(new RegExp(RE.domain.source, "gi"))].filter((m) => domainLike(m[0], m[1]!)),
	].map((m) => m[0].replace(/[)\]}>.,!?;:'"」』）]+$/, ""));
	return found.some((f) => !pool.includes(f));
}

/** 送出內容的風險旗標（MCP send_message、圖片說明）。有旗標 → Outbox 一律進確認佇列 */
export function contentFlags(text: string | null | undefined, detectInjection: (s: string) => { suspected: boolean }): string[] {
	if (!text) return [];
	const { kinds, normalized } = scanContacts(text);
	const f: string[] = [];
	if (kinds.some((k) => k === "url" || k === "domain" || k === "ip")) f.push("url_in_output");
	if (kinds.some((k) => k === "phone" || k === "line_id" || k === "email")) f.push("contact_in_output");
	if (detectInjection(text).suspected || detectInjection(normalized).suspected) f.push("suspicious_output");
	return f;
}
