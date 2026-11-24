/**
 * 常駐程序進入點（Android Foreground Service 用 libnode 執行它；桌面也可直接 `node src/main.ts`）。
 * 環境變數：
 *   LINE_MCP_HOME        資料目錄（Android：context.filesDir），內含 line.db 與 media/
 *   LINE_MCP_PORT        MCP 埠（預設 47823）
 *   LINE_MCP_TOKEN       MCP Bearer token（建議必設）
 *   LINE_CONTROL_PORT    控制 API 埠（預設 47824）
 *   LINE_CONTROL_TOKEN   控制 API token（必設）
 */
import { join } from "node:path";
import { openDatabase } from "./storage/db.ts";
import { Whitelist } from "./whitelist.ts";
import { Session } from "./auth/session.ts";
import { SyncEngine } from "./sync/engine.ts";
import { LinejsSource } from "./sync/linejs-source.ts";
import { MediaCache } from "./media/cache.ts";
import { startMcpHttp } from "./mcp/server.ts";
import { startControlHttp, type LoginState } from "./control/server.ts";
import type { ToolContext } from "./mcp/tools.ts";

const rootHome = process.env.LINE_MCP_HOME ?? ".state";
// Mock 模式：只在 debug 建置可用（release bundle 以 LMA_INCLUDE_MOCK="0" 建置，整段被移除），資料放在獨立的 mock/ 目錄
const MOCK = process.env.LMA_INCLUDE_MOCK !== "0" && process.env.LINE_MCP_MOCK === "1";
const home = MOCK ? join(rootHome, "mock") : rootHome;
const store = openDatabase(join(home, "line.db"));
const whitelist = new Whitelist(store);
const session = new Session(store);
let state: LoginState = { phase: "logged_out" };
const ctx: ToolContext = { store, whitelist, sync: null, media: new MediaCache(home, store, null) };

async function goOnline(): Promise<void> {
	const p = session.profile!;
	state = { phase: "online", profile: { displayName: p.displayName, mid: p.mid } };
	const src = new LinejsSource(session.base);
	ctx.sync = new SyncEngine(store, src);
	ctx.media = new MediaCache(home, store, src);
	await ctx.sync.fullSync().catch((e) => console.error("fullSync failed:", (e as Error).message));
	void pollLoop();
}

async function pollLoop(): Promise<void> {
	for (;;) {
		try {
			await ctx.sync!.pollOnce();
		} catch (e) {
			console.error("poll failed:", (e as Error).message);
			await new Promise((r) => setTimeout(r, 10_000));
		}
	}
}

async function goMockOnline(): Promise<void> {
	if (process.env.LMA_INCLUDE_MOCK === "0") return;
	const { MockSource, MOCK_DEFAULT_ALLOWED } = await import("./mock/mock-source.ts");
	const src = new MockSource();
	state = { phase: "online", profile: { displayName: "Mock 使用者", mid: "u_mock_me" } };
	ctx.sync = new SyncEngine(store, src);
	ctx.media = new MediaCache(home, store, src);
	await ctx.sync.fullSync();
	if (!store.getSetting("mock_seeded")) {
		for (const id of MOCK_DEFAULT_ALLOWED) whitelist.set(id, true);
		store.setSetting("mock_seeded", "1");
		await ctx.sync.fullSync();
	}
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

const controlToken = process.env.LINE_CONTROL_TOKEN;
if (!controlToken) throw new Error("LINE_CONTROL_TOKEN is required");
const mcpPort = Number(process.env.LINE_MCP_PORT ?? 47823);
const control = await startControlHttp({ store, whitelist, login: () => state, startQrLogin, info: () => ({ mock: MOCK, mcp_url: `http://127.0.0.1:${mcpPort}/mcp`, transport: "streamable-http", read_receipts: store.getSetting("read_receipts") === "on" ? "enabled" : "blocked", counts: store.counts() }) }, { port: Number(process.env.LINE_CONTROL_PORT ?? 47824), token: controlToken });
const mcp = await startMcpHttp(ctx, { port: mcpPort, token: process.env.LINE_MCP_TOKEN });
console.log(JSON.stringify({ event: "ready", control: control.url, mcp: mcp.url, mock: MOCK }));
if (MOCK) await goMockOnline();

// 已有 token → 直接上線；清除資料後沒有 token → 等 UI 觸發 QR 登入，登入後自動完整同步
if (!MOCK && session.savedToken()) {
	session
		.loginWithToken()
		.then(goOnline)
		.catch((e) => (state = { phase: "error", error: `token login failed: ${(e as Error).message}` }));
}
