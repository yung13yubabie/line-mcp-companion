/**
 * 送到非本機 LLM 前去識別化。
 * 改作自 mars-tw/anti-scam-helper（Apache-2.0）guard/chat-training.mjs 的 deidentify()：
 * 人名 → 成員A/B…、email、網址（165 反詐專線網站除外）、身分證、手機、市話、帳號、LINE ID、@ID、地址。
 * 修改：TypeScript 移植；回傳人名對照表，讓模型回覆裡的「成員A」能換回原名（只換人名，不還原電話 / 網址等）。
 */
export interface DeidMap {
	/** 代號 → 原名 */
	names: Map<string, string>;
}

export function deidentify(text: string, names: string[] = [], map: DeidMap = { names: new Map() }): { text: string; map: DeidMap } {
	let out = String(text ?? "");
	const byName = new Map([...map.names].map(([code, n]) => [n, code]));
	for (const name of [...new Set(names)].filter((n) => n && n.length >= 2).sort((a, b) => b.length - a.length)) {
		if (!byName.has(name)) {
			const code = `成員${String.fromCharCode(65 + (byName.size % 26))}${byName.size >= 26 ? Math.floor(byName.size / 26) : ""}`;
			byName.set(name, code);
			map.names.set(code, name);
		}
		out = out.split(name).join(byName.get(name)!);
	}
	out = out
		.replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, "［email］")
		.replace(/https?:\/\/(?!165\.npa\.gov\.tw)[^\s，。）)]+/gi, "［網址］")
		.replace(/\b[A-Z][12]\d{8}\b/g, "［身分證］")
		.replace(/(\+?886[-\s]?|0)9\d{2}[-\s]?\d{3}[-\s]?\d{3}/g, "［手機］")
		.replace(/\(?0\d{1,2}\)?[-\s]?\d{3,4}[-\s]?\d{4}/g, "［電話］")
		.replace(/\b\d{10,16}\b/g, "［帳號］")
		.replace(/(?<![A-Za-z])(?:line\s*id\s*[:：]?\s*@?[\w.-]{3,}|id\s*[:：]\s*@?[\w.-]{3,}|id\s+@?(?=[\w.-]*\d)[\w.-]{3,})/gi, "［LINE ID］")
		.replace(/@[\w.-]{4,}/g, "［ID］")
		.replace(/[\u4e00-\u9fa5]{1,6}(縣|市)[\u4e00-\u9fa5]{1,6}(區|鄉|鎮|市)[\u4e00-\u9fa50-9０-９\-之]{1,20}(號|樓)/g, "［地址］")
		.replace(/[\u4e00-\u9fa5]{1,10}(路|街|大道)([\u4e00-\u9fa50-9０-９]{1,4}段)?([0-9０-９]{1,4}巷)?([0-9０-９]{1,4}弄)?[0-9０-９]{1,5}號([0-9０-９]{1,3}樓)?/g, "［地址］");
	return { text: out, map };
}

/** 把模型回覆裡的代號換回原名 */
export function reidentify(text: string, map: DeidMap): string {
	let out = String(text ?? "");
	for (const [code, name] of [...map.names].sort((a, b) => b[0].length - a[0].length)) out = out.split(code).join(name);
	return out;
}

export function isLocalUrl(u: string): boolean {
	try {
		const h = new URL(u).hostname;
		return h === "127.0.0.1" || h === "localhost" || h === "[::1]" || h === "::1";
	} catch {
		return false;
	}
}
