/**
 * 常駐程序進入點（Android Foreground Service 用 libnode 執行它；桌面也可直接 `node src/main.ts`）。
 * 環境變數：
 *   LINE_MCP_HOME        資料目錄（Android：context.filesDir），內含 line.db 與 media/
 *   LINE_MCP_PORT        MCP 埠（預設 47823）
 *   LINE_MCP_TOKEN       MCP Bearer token（建議必設；執行中可由 UI 輪換）
 *   LINE_CONTROL_PORT    控制 API 埠（預設 47824）
 *   LINE_CONTROL_TOKEN   控制 API token（必設）
 *   LMA_AI_KEY           （選用）AI API key；讀入記憶體後立即從環境變數移除。也可由 UI 經控制 API 設定。
 */
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { openDatabase } from "./storage/db.ts";
import { Whitelist } from "./whitelist.ts";
import { Session } from "./auth/session.ts";
import { SyncEngine } from "./sync/engine.ts";
import { LinejsSource } from "./sync/linejs-source.ts";
import { backoffMs, isAuthError } from "./sync/backoff.ts";
import { MediaCache } from "./media/cache.ts";
import { startMcpHttp } from "./mcp/server.ts";
import { startControlHttp, type LoginState } from "./control/server.ts";
import type { ToolContext } from "./mcp/tools.ts";
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

const rootHome = process.env.LINE_MCP_HOME ?? ".state";
// Mock 模式：只在 debug 建置可用（release bundle 以 LMA_INCLUDE_MOCK="0" 建置，整段被移除），資料放在獨立的 mock/ 目錄
const MOCK = process.env.LMA_INCLUDE_MOCK !== "0" && process.env.LINE_MCP_MOCK === "1";
const home = MOCK ? join(rootHome, "mock") : rootHome;
const store = openDatabase(join(home, "line.db"));
const whitelist = new Whitelist(store);
const session = new Session(store);
let state: LoginState = { phase: "logged_out" };

// ---- 秘密只放記憶體 ----
let aiKey: string | undefined = process.env.LMA_AI_KEY || undefined;
delete process.env.LMA_AI_KEY;
let mcpToken: string | undefined = process.env.LINE_MCP_TOKEN || undefined;
delete process.env.LINE_MCP_TOKEN;
const controlToken = process.env.LINE_CONTROL_TOKEN;
delete process.env.LINE_CONTROL_TOKEN;
if (!controlToken) throw new Error("LINE_CONTROL_TOKEN is required");

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
	secrets: () => [mcpToken, controlToken].filter((x): x is string => !!x),
});
const scam = new ScamDetector(store);
scam.seedBuiltin();
// AI 判讀（選用）：只有使用者開啟 scam_ai 且 App 內有 key 時
scam.judge = (msgs) => ai.provider().chat(msgs, { maxTokens: 120 });
const warner = new ScamWarner(store, outbox, audit, scam);

const ctx: ToolContext = { store, whitelist, sync: null, media: new MediaCache(home, store, null), ai, scam };

function attachSync(sync: SyncEngine): void {
	sync.onNewMessages = (msgs) => {
		const alerts = scam.onNewMessages(msgs);
		warner.handle(alerts);
		ai.onNewMessages(msgs);
		void outbox.processDue();
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
	const { MockSource, MOCK_DEFAULT_ALLOWED, MOCK_AI_ALLOWED } = await import("./mock/mock-source.ts");
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
		for (const id of MOCK_AI_ALLOWED) policy.set(id, { ai_allowed: true, mode: id === "c_mock_work" ? "auto" : "suggest", confirm_send: true });
		policy.set("c_mock_family", { ai_allowed: false });
		await ai.suggestToQueue("u_mock_mom", "auto", "suggest", null, "9004").catch((e) => console.error("mock seed:", (e as Error).message));
		await ai.suggestToQueue("c_mock_work", "auto", "suggest", null, "9201").catch((e) => console.error("mock seed:", (e as Error).message));
		// 反詐：重掃社區群、開啟即時提醒（@ 管委會小李）
		scam.setAdmin("c_mock_hood", "u_mock_n1", { name: "管委會小李", mention: true });
		scam.rescanChat("c_mock_hood");
		warner.set("c_mock_hood", { enabled: true, mention_admins: true });
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
		setAiKey: (k) => void (aiKey = k ?? undefined),
		mcpStats: () => mcpStats?.() ?? null,
		rotateMcpToken: () => (mcpToken = randomBytes(24).toString("base64url")),
		stickerImage,
		syncStatus: () => (ctx.sync ? (ctx.sync.status() as unknown as Record<string, unknown>) : null),
		info: () => ({
			mock: MOCK,
			mcp_url: `http://127.0.0.1:${mcpPort}/mcp`,
			mcp_auth: mcpToken ? "bearer" : "none",
			transport: "streamable-http",
			read_receipts: store.getSetting("read_receipts") === "on" ? "enabled" : "blocked",
			counts: store.counts(),
		}),
	},
	{ port: Number(process.env.LINE_CONTROL_PORT ?? 47824), token: controlToken },
);
const mcp = await startMcpHttp(ctx, { port: mcpPort, getToken: () => mcpToken, audit });
mcpStats = mcp.stats;
console.log(JSON.stringify({ event: "ready", control: control.url, mcp: mcp.url, mock: MOCK }));

// 排程送出 / 過期清理
setInterval(() => {
	outbox.expireStale();
	void outbox.processDue().catch((e) => console.error("processDue:", (e as Error).message));
}, 5_000).unref?.();

process.on("unhandledRejection", (e) => console.error("unhandledRejection:", (e as Error)?.message ?? e));

if (MOCK) await goMockOnline();

// 已有 token → 直接上線；清除資料後沒有 token → 等 UI 觸發 QR 登入，登入後自動完整同步
if (!MOCK && session.savedToken()) {
	session
		.loginWithToken()
		.then(goOnline)
		.catch((e) => (state = { phase: "error", error: isAuthError(e) ? "LINE 登入已失效，請重新登入" : `token login failed: ${(e as Error).message}` }));
}
