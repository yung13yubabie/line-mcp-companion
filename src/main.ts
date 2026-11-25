/**
 * 常駐程序進入點（Android Foreground Service 用 libnode 執行它；桌面也可直接 `node src/main.ts`）。
 * 環境變數：
 *   LINE_MCP_HOME        資料目錄（Android：context.filesDir），內含 line.db 與 media/
 *   LINE_MCP_PORT        MCP 埠（預設 47823）
 *   LINE_MCP_TOKEN       MCP Bearer token（沒設 → 自動產生並只印一次；執行中可由 UI 輪換）
 *   LINE_CONTROL_PORT    控制 API 埠（預設 47824）
 *   LINE_CONTROL_TOKEN   控制 API token（沒設 → 自動產生並只印一次）
 *   LMA_DATA_KEY         Android：Keystore 解開的資料金鑰（base64 32 bytes），用來加密 SQLite 裡的 LINE token / E2EE 金鑰
 *   LMA_PASSPHRASE       桌面 / 開發：沒有 LMA_DATA_KEY 時必設（≥12 字），否則拒絕啟動（mock 模式除外）
 *   LMA_AI_KEY           （選用）AI API key；讀入記憶體後立即從環境變數移除。也可由 UI 經控制 API 設定。
 */
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { openDatabase } from "./storage/db.ts";
import { resolveDataKey } from "./storage/data-key.ts";
import { Whitelist } from "./whitelist.ts";
import { Session } from "./auth/session.ts";
import { SyncEngine } from "./sync/engine.ts";
import { LinejsSource } from "./sync/linejs-source.ts";
import { backoffMs, isAuthError } from "./sync/backoff.ts";
import { MediaCache } from "./media/cache.ts";
import { startMcpHttp } from "./mcp/server.ts";
import { startControlHttp, type LoginState } from "./control/server.ts";
import type { ToolContext } from "./mcp/tools.ts";
import { EventLog } from "./storage/event-log.ts";
import { AiPolicy } from "./ai/policy.ts";
import { Audit } from "./ai/audit.ts";
import { Outbox } from "./ai/outbox.ts";
import { AiService } from "./ai/service.ts";
import { OpenAICompatProvider } from "./ai/provider.ts";
import { offlineSender } from "./ai/sender.ts";
import { LinejsSender } from "./ai/linejs-sender.ts";
import { stickerUrl } from "./ai/stickers.ts";
import { ScamDetector } from "./scam/detector.ts";
import { ScamWarner } from "./scam/warner.ts";
import { OAuthServer } from "./mcp/oauth.ts";
import { DigestStore } from "./storage/digests.ts";
import { DigestPoster } from "./ai/digest-post.ts";
import { LinkReader } from "./links/reader.ts";
import { startGateway, normalizePublicUrl } from "./mcp/gateway.ts";
import { QuickTunnel } from "./mcp/tunnel.ts";

const rootHome = process.env.LINE_MCP_HOME ?? ".state";
// Mock 模式：只在 debug 建置可用（release bundle 以 LMA_INCLUDE_MOCK="0" 建置，整段被移除），資料放在獨立的 mock/ 目錄
const MOCK = process.env.LMA_INCLUDE_MOCK !== "0" && process.env.LINE_MCP_MOCK === "1";
const home = MOCK ? join(rootHome, "mock") : rootHome;
const store = openDatabase(join(home, "line.db"));
const whitelist = new Whitelist(store);
let dataKey: ReturnType<typeof resolveDataKey>;
try {
	dataKey = resolveDataKey(store, process.env, { mock: MOCK });
} catch (e) {
	console.error((e as Error).message);
	process.exit(78); // EX_CONFIG
}
if (dataKey.migrated) console.error(JSON.stringify({ event: "secrets_migrated", rows: dataKey.migrated }));
const session = new Session(store, dataKey.box);
let state: LoginState = { phase: "logged_out" };

// ---- 秘密只放記憶體 ----
let aiKey: string | undefined = process.env.LMA_AI_KEY || undefined;
delete process.env.LMA_AI_KEY;
// 沒設 token 就自動產生隨機 token 並只印一次（stderr）；絕不提供未驗證的服務
const genToken = () => randomBytes(24).toString("base64url");
let mcpToken: string = process.env.LINE_MCP_TOKEN || "";
const controlToken: string = process.env.LINE_CONTROL_TOKEN || genToken();
if (!process.env.LINE_CONTROL_TOKEN) console.error(JSON.stringify({ event: "generated_token", which: "control", token: controlToken, note: "shown once" }));
if (!mcpToken) {
	mcpToken = genToken();
	console.error(JSON.stringify({ event: "generated_token", which: "mcp", token: mcpToken, note: "shown once" }));
}
if (controlToken.length < 16 || mcpToken.length < 16) {
	console.error("refusing to start: tokens must be at least 16 characters");
	process.exit(78);
}
delete process.env.LINE_MCP_TOKEN;
delete process.env.LINE_CONTROL_TOKEN;

// ---- AI / 反詐 ----
const audit = new Audit(store);
const policy = new AiPolicy(store);
const outbox = new Outbox(store, policy, audit, offlineSender);
const mockAi = MOCK ? await import("./mock/mock-ai.ts") : null;
const ai = new AiService(store, policy, outbox, audit, {
	home,
	getKey: () => aiKey,
	allowMock: MOCK,
	providerFactory: (cfg, getKey) => (cfg.provider === "mock" && mockAi ? new mockAi.MockAiProvider() : new OpenAICompatProvider(cfg, getKey)),
	secrets: () => [mcpToken, controlToken],
});
const scam = new ScamDetector(store);
scam.seedBuiltin();
// AI 判讀（選用）：只有使用者開啟 scam_ai 且 App 內有 key 時
scam.judge = (msgs) => ai.provider().chat(ai.deidMessages(msgs), { maxTokens: 120 });
const warner = new ScamWarner(store, outbox, audit, scam);
// 反詐紀錄 / AI 代聊紀錄（人名與內容用資料金鑰加密）
const events = new EventLog(store, dataKey.box);
outbox.log = events;
scam.log = events;
warner.events = events;
const digests = new DigestStore(store, dataKey.box, whitelist);
ai.digests = digests;
const links = new LinkReader({ getSafeBrowsingKey: () => process.env.LMA_SAFE_BROWSING_KEY || undefined, getBlocklist: () => (store.getSetting("link_blocklist") ?? "").split(/[\s,]+/).filter(Boolean) });
ai.links = links;
const poster = new DigestPoster(store, digests, outbox, ai);
events.prune();

const ctx: ToolContext = { store, whitelist, sync: null, media: new MediaCache(home, store, null), ai, scam, warner, events, digests, poster, links };

function attachSync(sync: SyncEngine): void {
	sync.onNewMessages = (msgs) => {
		const alerts = scam.onNewMessages(msgs);
		warner.handle(alerts);
		ai.onNewMessages(msgs);
		void outbox.processDue();
	};
	// 被隱藏 / 收回 / 刪除：安靜取消針對它的待送回覆與提醒（不寫紀錄）
	sync.onHidden = (items) => {
		for (const h of items) outbox.cancelForHidden(h.chatId, h.id);
	};
}

async function goOnline(): Promise<void> {
	const p = session.profile!;
	state = { phase: "online", profile: { displayName: p.displayName, mid: p.mid } };
	const src = new LinejsSource(session.base);
	ctx.sync = new SyncEngine(store, src);
	ctx.media = new MediaCache(home, store, src);
	outbox.sender = new LinejsSender(session.base);
	attachSync(ctx.sync);
	await ctx.sync.fullSync().catch((e) => console.error("fullSync failed:", (e as Error).message));
	void pollLoop();
}

/** 增量同步：失敗時指數退避（1s → 5 分鐘上限，含抖動）；登入失效時停下並請使用者重新登入 */
async function pollLoop(): Promise<void> {
	let attempt = 0;
	for (;;) {
		try {
			await ctx.sync!.pollOnce();
			attempt = 0;
		} catch (e) {
			if (isAuthError(e)) {
				state = { phase: "error", error: "LINE 登入已失效，請重新登入" };
				outbox.sender = offlineSender;
				audit.log("system", "session_expired", { ok: false });
				return;
			}
			const wait = backoffMs(attempt++);
			console.error(`poll failed (retry in ${Math.round(wait / 1000)}s):`, (e as Error).message);
			await new Promise((r) => setTimeout(r, wait));
		}
	}
}

async function goMockOnline(): Promise<void> {
	if (process.env.LMA_INCLUDE_MOCK === "0" || !mockAi) return;
	const { MockSource, MOCK_DEFAULT_ALLOWED, MOCK_AI_ALLOWED, seedMockDigests, MOCK_LINK_PAGES } = await import("./mock/mock-source.ts");
	// mock：連結讀取不連網
	links.useOffline(MOCK_LINK_PAGES);
	const src = new MockSource();
	state = { phase: "online", profile: { displayName: "Mock 使用者", mid: "u_mock_me" } };
	ctx.sync = new SyncEngine(store, src);
	ctx.media = new MediaCache(home, store, src);
	outbox.sender = new mockAi.MockSender(store);
	await ctx.sync.fullSync();
	if (!store.getSetting("mock_seeded")) {
		for (const id of MOCK_DEFAULT_ALLOWED) whitelist.set(id, true);
		await ctx.sync.fullSync();
		// 示範用設定：內建 AI（mock，不連網）＋兩個代聊會話＋確認佇列裡有幾則建議
		ai.setConfig({ provider: "mock" });
		ai.setDriver("builtin");
		policy.setAiEnabled(true);
		for (const id of MOCK_AI_ALLOWED) policy.set(id, { ai_allowed: true, mode: id === "c_mock_work" ? "auto" : "suggest" });
		// 示範信任狀態：工作群 AI 回覆升到「自動」（其餘維持審核）
		policy.setTrust("c_mock_work", "ai", "auto", "ui", "mock 示範");
		policy.set("c_mock_family", { ai_allowed: false });
		await ai.suggestToQueue("u_mock_mom", "auto", "suggest", null, "9004").catch((e) => console.error("mock seed:", (e as Error).message));
		await ai.suggestToQueue("c_mock_work", "auto", "suggest", null, "9201").catch((e) => console.error("mock seed:", (e as Error).message));
		// 反詐：重掃社區群、開啟即時提醒（@ 管委會小李）
		scam.setAdmin("c_mock_hood", "u_mock_n1", { name: "管委會小李", mention: true });
		scam.rescanChat("c_mock_hood");
		warner.set("c_mock_hood", { enabled: true, mention_admins: true });
		// 日報示範（只在 mock）
		try {
			seedMockDigests(store, digests);
			store.setSetting("link_read:c_mock_work", "on");
			store.setSetting("link_read:c_mock_hood", "on");
			poster.saveSchedule({ target_chat: "c_mock_work", source_chats: ["c_mock_work", "c_mock_hood"], time_hhmm: "21:00", generate: true }, "system");
		} catch (e) {
			console.error("mock digests:", (e as Error).message);
		}
		store.setSetting("mock_seeded", "1");
	} else src.live = []; // 已示範過即時提醒
	attachSync(ctx.sync);
	void pollLoop();
}

function startQrLogin(): void {
	if (MOCK) return;
	if (state.phase === "waiting_qr_scan" || state.phase === "waiting_pin" || state.phase === "online") return;
	state = { phase: "waiting_qr_scan" };
	session
		.loginWithQr({
			onQrUrl: (url) => void (state = { phase: "waiting_qr_scan", qrUrl: url }),
			onPincode: (pin) => void (state = { phase: "waiting_pin", pin }),
		})
		.then(goOnline)
		.catch((e) => (state = { phase: "error", error: (e as Error).message }));
}

/** 貼圖圖片：mock 用程式產生；真實模式從 LINE 貼圖 CDN 取一次後快取（只接受數字 id，大小上限 512KB） */
async function stickerImage(id: string): Promise<{ bytes: Uint8Array; mime: string }> {
	if (MOCK && mockAi) return { bytes: mockAi.mockStickerPng(id), mime: "image/png" };
	const dir = join(home, "stickers");
	const file = join(dir, `${id}.png`);
	if (existsSync(file)) return { bytes: readFileSync(file), mime: "image/png" };
	const r = await fetch(stickerUrl(id), { signal: AbortSignal.timeout(10_000), redirect: "error" });
	if (!r.ok) throw new Error(`sticker fetch ${r.status}`);
	const buf = new Uint8Array(await r.arrayBuffer());
	if (buf.byteLength > 512 * 1024) throw new Error("sticker too large");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	writeFileSync(file, buf, { mode: 0o600 });
	return { bytes: buf, mime: "image/png" };
}

const mcpPort = Number(process.env.LINE_MCP_PORT ?? 47823);
// 雲端連接器閘道（預設關；App 設定或 LMA_CONNECTOR=1 開啟）
const oauth = new OAuthServer(store, audit);
const tunnel = new QuickTunnel();
const connectorPort = Number(process.env.LINE_CONNECTOR_PORT ?? 47825);
if (process.env.LMA_CONNECTOR === "1") store.setSetting("connector_enabled", "on");
if (process.env.LMA_CONNECTOR_PUBLIC_URL) store.setSetting("connector_public_url", normalizePublicUrl(process.env.LMA_CONNECTOR_PUBLIC_URL));
// quick tunnel 網址每次都會變 → 自動更新公開網址
tunnel.onUrl = (u) => {
	if (u) store.setSetting("connector_public_url", u);
	console.log(JSON.stringify({ event: "tunnel", url: u }));
};
let mcpStats: (() => import("./mcp/server.ts").McpStats) | null = null;
const control = await startControlHttp(
	{
		store,
		whitelist,
		login: () => state,
		startQrLogin,
		ai,
		scam,
		warner,
		events,
		digests,
		poster,
		links,
		setAiKey: (k) => void (aiKey = k ?? undefined),
		mcpStats: () => mcpStats?.() ?? null,
		rotateMcpToken: () => (mcpToken = genToken()),
		stickerImage,
		connector: { oauth, gatewayPort: connectorPort, tunnel },
		syncStatus: () => (ctx.sync ? (ctx.sync.status() as unknown as Record<string, unknown>) : null),
		info: () => ({
			mock: MOCK,
			mcp_url: `http://127.0.0.1:${mcpPort}/mcp`,
			mcp_auth: "bearer",
			data_key: dataKey.source,
			transport: "streamable-http",
			read_receipts: store.getSetting("read_receipts") === "on" ? "enabled" : "blocked",
			counts: store.counts(),
		}),
	},
	{ port: Number(process.env.LINE_CONTROL_PORT ?? 47824), token: controlToken },
);
const mcp = await startMcpHttp(ctx, { port: mcpPort, getToken: () => mcpToken, audit });
mcpStats = mcp.stats;
const gateway = await startGateway(ctx, { port: connectorPort, store, oauth, audit, getStaticToken: () => mcpToken });
if (process.env.LMA_CONNECTOR === "1") {
	// 桌面模式：配對碼印在 stderr（Android 上只在 App 畫面顯示）
	console.error(JSON.stringify({ event: "connector", gateway: gateway.url, pairing_code: oauth.pairingCode().code, note: "pairing code valid 10 min; GET /control/connector for a new one" }));
	if (process.env.LMA_TUNNEL === "cloudflare") void tunnel.start(connectorPort).then((st) => console.error(JSON.stringify({ event: "tunnel_status", ...st })));
}
console.log(JSON.stringify({ event: "ready", control: control.url, mcp: mcp.url, connector: gateway.url, mock: MOCK }));

// 排程送出 / 過期清理
setInterval(() => {
	outbox.expireStale();
	void outbox.processDue().catch((e) => console.error("processDue:", (e as Error).message));
}, 5_000).unref?.();
// 日報定時貼文（台北時間，每分鐘檢查）
setInterval(() => void poster.tick().catch((e) => console.error("digest tick:", (e as Error).message)), 60_000).unref?.();
setInterval(() => events.prune(), 3_600_000).unref?.();

for (const sig of ["SIGTERM", "SIGINT"] as const)
	process.on(sig, () => {
		tunnel.stop();
		process.exit(0);
	});
process.on("unhandledRejection", (e) => console.error("unhandledRejection:", (e as Error)?.message ?? e));

if (MOCK) await goMockOnline();

// 已有 token → 直接上線；清除資料後沒有 token → 等 UI 觸發 QR 登入，登入後自動完整同步
if (!MOCK && session.savedToken()) {
	session
		.loginWithToken()
		.then(goOnline)
		.catch((e) => (state = { phase: "error", error: isAuthError(e) ? "LINE 登入已失效，請重新登入" : `token login failed: ${(e as Error).message}` }));
}
