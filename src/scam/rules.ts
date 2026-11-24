/**
 * 群組詐騙規則計分。
 * 改作自 mars-tw/anti-scam-helper `guard/rules.mjs`（Apache-2.0，https://github.com/mars-tw/anti-scam-helper）。
 * 修改（Apache-2.0 §4(b)）：移植為 TypeScript；只保留文字/網址/LINE ID 類規則（去掉踢人、管理員名稱、
 * 交易所仿冒網域、檔案掃描等需要群組管理權限或外部清單的部分）；分數門檻改為「只產生警示」用途。
 *
 * 比對前先 NFKC 正規化，並另備一份去掉所有空白 / 零寬字元的版本，「本 群 明 天 要 刪 除」也會命中。
 */

export const SHORTENERS = [
	"bit.ly", "bit.do", "reurl.cc", "tinyurl.com", "tiny.cc", "pse.is",
	...["", 1, 2, 3, 4, 5, 6, 7, 8, 9].flatMap((n) => [`lihi${n}.cc`, `lihi${n}.com`, `lihi${n}.me`]),
	"ppt.cc", "myppt.cc", "is.gd", "v.gd", "t.ly", "shorturl.at", "shorturl.asia", "cutt.ly", "1url.cz", "ada.nz", "cutt.us", "tny.im", "u.nu",
	"n9.cl", "surl.li", "ouo.io", "shrtco.de", "9m.no", "t.cn", "kutt.it", "han.gl", "me2.do", "vo.la", "sor.bz", "rb.gy", "ow.ly", "buff.ly",
	"s.id", "goo.su", "gg.gg", "x.gd", "rebrand.ly", "short.gy", "shorturl.gg", "0rz.tw", "risu.io", "cli.re", "u.to", "clck.ru", "qrco.de",
	"tw.gg", "url.cn", "dwz.cn", "suo.im", "supr.link", "urlr.me",
];
const esc = (d: string) => d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** 詢問或提醒詐騙（「這是詐騙嗎」「不要亂加」）：扣分，避免把好心提醒的人標成詐騙 */
export const ASK_SCAM =
	/(這|那)(個|些|則|種)?(是|應該是|根本是|算)詐騙|是詐騙嗎|詐騙嗎|是不是(詐騙|詐團|騙人|騙局|假的)|是(真|假)的嗎|有(人|沒有人)(也)?收到(這|類似|一樣)|可信嗎|(不要|別|勿|千萬別)(亂)?(點|加入|加|相信|匯款|上當|理)|冒充|假冒|165\s*(查證|反詐|專線)?|小心(詐騙|被騙|上當)/;
export const ANTI_SCAM_WARNING =
	/(?:疑似|可能是?|小心|注意|提醒|警告|防範|謹防|慎防|當心|嚴防).{0,10}(?:詐騙|假群|假冒|冒充|冒用|被騙)|(?:不要|勿|別|切勿|請勿|千萬別|千萬不要)\s*(?:隨便|亂)?\s*(?:加入|點|加|相信|理會|上當|掃)/;

export interface ScamRule {
	name: string;
	score: number;
	pattern: RegExp;
}

export const RULES: ScamRule[] = [
	{ name: "LINE 邀請／加好友", score: 3, pattern: /line\.me\/(ti|R\/ti)|lin\.ee\/|加\s*(我\s*)?(賴|line|LINE|Line)|(line|LINE|賴)\s*(id|ID)\s*[:：]?|ID\s*[:：]\s*@?\w{3,}/ },
	{ name: "短網址", score: 3, pattern: new RegExp(`(?<![\\w.-])(${SHORTENERS.map(esc).join("|")})\\/[\\w-]`, "i") },
	{ name: "網址", score: 1, pattern: /https?:\/\/|www\.|(?<![\w.@-])(?:[a-z0-9-]+\.)+[a-z]{2,}\/[\w-]/i },
	{ name: "投資帶單", score: 2, pattern: /飆股|帶單|老師帶|投顧老師|穩賺|保證(獲利|賺)|勝率\s*\d|漲停板?.{0,6}(分享|帶|跟)|主力.{0,4}(進場|拉抬)|內線(消息)?|出金|入金|翻倍|獲利\s*\d+\s*%|報(明)?牌/ },
	{ name: "虛幣引流", score: 2, pattern: /(虛擬貨幣|加密貨幣|虛幣|USDT|泰達幣|新幣|幣圈).{0,12}(帶單|保證|穩賺|翻倍|收益|日收|月收|套利|搬磚|出金|入金|認購|錢包地址|分紅)|(搬磚|套利).{0,8}(USDT|泰達幣|虛幣)/i },
	{ name: "假冒名人報牌", score: 2, pattern: /(退休|離職|資深)(的)?(半導體|台積電|鴻海)?(工程師|經理|主管).{0,15}(報股|報牌|明牌|內幕|內線|飆股)|訂單(已經)?接到\s*20\d\d|(財經|股市)(名人|大師).{0,10}(帶|群|分享|免費)/ },
	{ name: "假投資平台", score: 2, pattern: /下載.{0,6}(app|APP|App).{0,10}(投資|交易|入金|註冊)|(投資|交易)平台.{0,8}(註冊|入金|邀請碼)|洗碼量|(繳|付).{0,4}保證金.{0,6}(出金|提領|解凍)|IP\s*異常|帳號.{0,4}凍結.{0,8}(出金|客服)/i },
	{ name: "兼職刷單", score: 2, pattern: /兼職.{0,10}(日領|日結|月入|輕鬆|在家|加)|日領|日結|刷單|在家(工作|賺)|輕鬆賺|躺賺|零經驗.{0,6}(月入|日入|日領)|月入\s*\d+萬|按讚.{0,6}(賺|領)|墊付.{0,6}返(佣|傭)|領任務/ },
	{ name: "私下聯繫", score: 2, pattern: /私我|私聊|私訊我|密我|加我好友|單獨聯繫|私下聯繫|找我拿|點我頭像|頭像加|加好友.{0,6}(領|拿|送|詳談)/ },
	{ name: "貸款博弈", score: 2, pattern: /免審|免照會|快速撥款|當日撥款|小額貸|借貸|代辦貸款|(信用|聯徵)(瑕疵|不良).{0,6}(可貸|也能貸)|博弈|娛樂城|百家樂|運彩.{0,6}(帶|老師|穩)|老虎機|首儲|儲值送/ },
	{ name: "假群組公告（換群）", score: 6, pattern: /(移|搬|轉|遷)(至|到|往|去)\s*(新|備用|另一?個)?\s*\d*\s*(號)?\s*(群|社群)|新\s*\d+\s*(號)?\s*(群|社群)|重新\s*(➕|＋|\+|加入|加一下|入群|進群)|統一\s*(核准|核準|審核|通過)|舊群.{0,6}(解散|關閉|停用)|(群組|社群)\s*(搬家|遷移)|備用群|(另外|重新)(成立|建立?|開)(了)?(新)?(群|社群)|(機器人|廣告)(太多|很多|洗版).{0,15}(新群|新社群)/ },
	{
		name: "假群組連結（換群）",
		score: 6,
		pattern:
			/(請|大家|各位|所有人|全體|麻煩).{0,6}(加入|進入|前往|移至|轉到)(到)?(我們的?)?新(的)?(群|社群|群組|社團)|(本|此|這個?|原|舊)(群|社群|群組|社團)(決定|宣布|將於|於|明天|明日|明早|今天|今晚|即將|馬上|稍後|近期|將|要|會|已經|已|準備)+.{0,3}(被)?(刪除|刪掉|解散|關閉|停用|作廢|不再使用)|新(的)?(群|社群|群組|社團)(連結|網址|入口|QR|qr)?(如下|在這|在此|點這|點此|請點|[:：👉⬇↓])|(廣告|騷擾|詐騙)(太多|過多|很多|嚴重).{0,24}(解散|關閉|刪除|新(群|社群|群組|社團))/,
	},
	{ name: "疑似換群", score: 3, pattern: /換(新)?(群|社群|群組)|(群|社群|群組)(搬|換|轉)(新)?(家|位置|地方)/ },
	{ name: "催促加入新群", score: 3, pattern: /(轉移|移轉|移動|遷移)(到|至)?(新|另一?個)(群|社群|群組)|新(群|社群|群組).{0,8}(重新)?審核(成員)?|(儘快|盡快|趕快|趕緊).{0,6}(申請)?(進群|入群|加入新(群|社群))|還沒(有)?加入的.{0,8}(請|儘快|盡快|趕快)/ },
	{ name: "群組邀請連結", score: 3, pattern: /line\.me\/(?:R\/)?ti\/g2?\/|openchat\.line\.me\//i },
	{ name: "假冒官方邀請入群", score: 2, pattern: /(官方|原廠|總公司|總部|品牌|公司|旅行社|銀行|航空|券商|客服中心|粉絲團).{0,12}(誠邀|邀請|邀您|歡迎|開放).{0,10}(加入|進入|入|免費加入).{0,8}(群|社群|群組|LINE\s*群|VIP|會員群|福利群)/i },
	{ name: "中獎／假客服", score: 2, pattern: /恭喜.{0,8}(中獎|抽中)|領取獎(金|品)|解除分期|誤設.{0,4}分期|重複扣款|客服通知|帳戶(異常|凍結)|驗證身分.{0,6}連結|實名驗證|開通金流|ATM.{0,6}(操作|解除)|無卡提款|遊戲點數/i },
	{ name: "愛情交友", score: 2, pattern: /(軍醫|戰地|聯合國|維和).{0,8}(醫生|軍官|官員|部隊)?.{0,15}(包裹|禮物|關稅|匯|投資)|(包裹|禮物).{0,8}(海關|關稅)|結婚基金/ },
	{ name: "盜帳號／收帳戶", score: 3, pattern: /(幫忙|幫我)投票.{0,15}(網址|連結|登入|https?:)|(傳|給|提供).{0,6}(簡訊)?(驗證碼|認證碼)|(驗證碼|認證碼).{0,10}(傳給我|給我|告訴我|截圖給我)|收購.{0,4}(帳戶|帳號|存摺)|(出租|租借|提供)(帳戶|存摺|提款卡)|出國.{0,4}(打工|工作).{0,6}高薪/ },
	{ name: "假紅包", score: 4, pattern: /(紅包|red\s*packet).{0,30}(加\s*(我\s*)?(賴|line)|私(訊|聊|我)|密我|頭像|先(付|儲值|入金)|手續費|保證金|解凍|驗證碼|授權錢包)/i },
	{ name: "免費子網域", score: 2, pattern: /(?<![\w.@-])(?:https?:\/\/)?[a-z0-9-]+\.(?:eu\.cc|us\.kg|eu\.org|pp\.ua|dpdns\.org|qzz\.io|ccwu\.cc)(?![a-z0-9-])/i },
	{ name: "LINE 官方帳號連結", score: -1, pattern: /line\.me\/(?:R\/)?ti\/p\/@|line\.me\/R\/ti\/p\/%40/i },
];

export function normalize(text: string): { norm: string; stripped: string } {
	const norm = text.normalize("NFKC");
	return { norm, stripped: norm.replace(/[\s\u200b-\u200f\u2060\ufeff]+/g, "") };
}

export interface RuleScore {
	score: number;
	hits: { name: string; score: number }[];
	warningTone: boolean;
}

export function scoreText(text: string): RuleScore {
	const { norm, stripped } = normalize(text);
	const hits: { name: string; score: number }[] = [];
	for (const r of RULES) if (r.pattern.test(norm) || r.pattern.test(stripped)) hits.push({ name: r.name, score: r.score });
	let score = hits.reduce((n, h) => n + h.score, 0);
	const warningTone = ASK_SCAM.test(norm) || ANTI_SCAM_WARNING.test(norm);
	const hasLink = hits.some((h) => /網址|LINE 邀請|群組邀請/.test(h.name));
	if (warningTone) score -= hasLink ? 2 : 4; // 好心提醒 / 詢問
	return { score, hits, warningTone };
}

/** 字元 bigram Jaccard 相似度（範例比對） */
export function similarity(a: string, b: string): number {
	const grams = (s: string) => {
		const t = normalize(s).stripped.toLowerCase();
		const g = new Set<string>();
		for (let i = 0; i < t.length - 1; i++) g.add(t.slice(i, i + 2));
		return g;
	};
	const A = grams(a);
	const B = grams(b);
	if (!A.size || !B.size) return 0;
	let inter = 0;
	for (const x of A) if (B.has(x)) inter++;
	return inter / (A.size + B.size - inter);
}
