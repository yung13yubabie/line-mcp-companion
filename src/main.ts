/**
 * 常駐程序進入點（Android Foreground Service 用 libnode 執行它；桌面也可直接 `node src/main.ts`）。
 * 環境變數：
 *   LINE_MCP_HOME        資料目錄（Android：context.filesDir），內含 line.db 與 media/
 *   LINE_MCP_PORT        MCP 埠（預設 47823）
 *   LINE_MCP_TOKEN       MCP 專用通道 key（沒設 → 自動產生並寫入 0600 檔案；執行中可由 UI 輪換）
 *   LINE_CONTROL_PORT    控制 API 埠（預設 47824）
 *   LINE_CONTROL_TOKEN   控制 API token（沒設 → 自動產生並寫入 0600 檔案）
 *   LMA_DATA_KEY         Android：Keystore 解開的資料金鑰（base64 32 bytes），用來加密 SQLite 裡的 LINE token / E2EE 金鑰
 *   LMA_PASSPHRASE       桌面 / 開發：沒有 LMA_DATA_KEY 時必設（≥12 字），否則拒絕啟動（mock 模式除外）
 *   LMA_AI_KEY           （選用）AI API key；讀入記憶體後立即從環境變數移除。也可由 UI 經控制 API 設定。
 *   LMA_SECRETS_STDIN=1  （建議，secreview SR-07）改從 stdin 第一行讀 JSON：{mcp_token, control_token, data_key, passphrase, ai_key}。
 *                        環境變數即使 delete 也仍留在 /proc/<pid>/environ；stdin 不會。
 */
import { join } from "node:path";
import { createRuntimeMode } from "./runtime-mode.ts";
import { installSafeConsole } from "./control/safe-console.ts";
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
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
import { GatewayToken } from "./mcp/gateway-token.ts";
import { OAuthServer } from "./mcp/oauth.ts";
import { DigestStore } from "./storage/digests.ts";
import { DigestPoster } from "./ai/digest-post.ts";
import { LinkReader } from "./links/reader.ts";
import { startGateway, normalizePublicUrl } from "./mcp/gateway.ts";
import { QuickTunnel } from "./mcp/tunnel.ts";

/** secreview SR-07：從 stdin 讀秘密（一行 JSON，上限 16KB，5 秒逾時） */
async function readStdinSecrets(): Promise<Record<string, string>> {
	return await new Promise((resolve, reject) => {
		let buf = "";
		const t = setTimeout(() => reject(new Error("timeout reading secrets from stdin")), 5000);
		const finish = () => {
			clearTimeout(t);
			process.stdin.pause();
			process.stdin.removeAllListeners("data");
			try {
				const v = JSON.parse(buf.split("\n")[0] || "{}") as Record<string, unknown>;
				resolve(Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x === "string")) as Record<string, string>);
			} catch {
				reject(new Error("invalid secrets JSON on stdin"));
			}
		};
		process.stdin.setEncoding("utf8");
		process.stdin.on("data", (d: string) => {
			buf += d;
			if (buf.length > 16 * 1024) return reject(new Error("secrets on stdin too large"));
			if (buf.includes("\n")) finish();
		});
		process.stdin.on("end", finish);
	});
}
let stdinSecrets: Record<string, string> = {};
if (process.env.LMA_SECRETS_STDIN === "1") {
	delete process.env.LMA_SECRETS_STDIN;
	try {
		stdinSecrets = await readStdinSecrets();
	} catch (e) {
		console.error((e as Error).message);
		process.exit(78);
	}
}

const rootHome = process.env.LINE_MCP_HOME ?? ".state";
// Build-selected runtime policy. Production implementation has no QA environment switches.
const mode = createRuntimeMode(process.env);
const home = mode.dataDirectory(rootHome);
const store = openDatabase(join(home, "line.db"));
const whitelist = new Whitelist(store);
let dataKey: ReturnType<typeof resolveDataKey>;
try {
	const keyEnv: NodeJS.ProcessEnv = { LMA_DATA_KEY: stdinSecrets.data_key ?? process.env.LMA_DATA_KEY, LMA_PASSPHRASE: stdinSecrets.passphrase ?? process.env.LMA_PASSPHRASE };
	delete process.env.LMA_DATA_KEY;
	delete process.env.LMA_PASSPHRASE;
	dataKey = (mode.dataKeyResolver ?? resolveDataKey)(store, keyEnv);
} catch (e) {
	console.error((e as Error).message);
	process.exit(78); // EX_CONFIG
}
if (dataKey.migrated) console.error(JSON.stringify({ event: "secrets_migrated", rows: dataKey.migrated }));
const session = new Session(store, dataKey.box);
let state: LoginState = { phase: "logged_out" };

// ---- 秘密只放記憶體 ----
let aiKey: string | undefined = stdinSecrets.ai_key || process.env.LMA_AI_KEY || undefined;
delete process.env.LMA_AI_KEY;
// 沒設 token 就自動產生隨機 token；secreview SR-08：token 值不寫進 log（logcat / node.log / 終端紀錄），
// 改寫到資料目錄下權限 0600 的 generated-tokens.json，log 只記檔名。絕不提供未驗證的服務。
const genToken = () => randomBytes(24).toString("base64url");
let mcpToken: string = stdinSecrets.mcp_token || process.env.LINE_MCP_TOKEN || "";
const providedControl = stdinSecrets.control_token || process.env.LINE_CONTROL_TOKEN || "";
const controlToken: string = providedControl || genToken();
const generated: Record<string, string> = {};
if (!providedControl) generated.control = controlToken;
if (!mcpToken) {
	mcpToken = genToken();
	generated.mcp = mcpToken;
}
if (Object.keys(generated).length) {
	mkdirSync(home, { recursive: true, mode: 0o700 });
	const tokFile = join(home, "generated-tokens.json");
	writeFileSync(tokFile, JSON.stringify(generated) + "\n", { mode: 0o600 });
	chmodSync(tokFile, 0o600);
	for (const which of Object.keys(generated)) console.error(JSON.stringify({ event: "generated_token", which, file: tokFile, note: "token value written to file (0600), not logged" }));
}

// secreview SR-08：所有 console 輸出（Android 上會進 logcat 與 node.log）遮蔽已知秘密
const logSecrets = (): string[] => [mcpToken, controlToken, aiKey, (session as { base?: { authToken?: string } } | undefined)?.base?.authToken].filter((x): x is string => !!x && x.length >= 8);
installSafeConsole(console, logSecrets);
// The startup envelope is no longer needed after the consumers copied its values.
stdinSecrets = {};
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
const ai = new AiService(store, policy, outbox, audit, {
	home,
	getKey: () => aiKey,
	...mode.aiOptions,
	providerFactory: (cfg, getKey) => new OpenAICompatProvider(cfg, getKey),
	secrets: () => [mcpToken, controlToken],
});
const scam = new ScamDetector(store);
scam.seedBuiltin();
// AI 判讀（選用）：只有使用者開啟 scam_ai 且 App 內有 key 時
scam.judge = (msgs, options) => ai.provider().chat(ai.deidMessages(msgs), { maxTokens: 120, assertAuthorized: options?.assertAuthorized });
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


function startQrLogin(): void {
	if (mode.isolated) return;
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
	if (mode.stickerImage) return mode.stickerImage(id);
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
const mcpLegacyHttp = process.env.LMA_MCP_LEGACY_HTTP === "1";
let mcpUrl = `http://127.0.0.1:${mcpPort}/mcp`;
let mcpStatus: "starting" | "ready" | "unavailable" = "starting";
// 雲端連接器閘道（預設關；App 設定或 LMA_CONNECTOR=1 開啟）
const oauth = new OAuthServer(store, audit);
const tunnel = new QuickTunnel();
const gatewayToken = new GatewayToken(store, audit);
const connectorPort = Number(process.env.LINE_CONNECTOR_PORT ?? 47825);
if (process.env.LMA_CONNECTOR === "1") store.setSetting("connector_enabled", "on");
if (process.env.LMA_CONNECTOR_PUBLIC_URL) store.setSetting("connector_public_url", normalizePublicUrl(process.env.LMA_CONNECTOR_PUBLIC_URL));
// quick tunnel 網址每次都會變 → 自動更新公開網址
tunnel.onUrl = (u) => {
	if (u) store.setSetting("connector_public_url", u);
	console.log(JSON.stringify({ event: "tunnel", url: u }));
};
let mcpStats: (() => import("./mcp/server.ts").McpStats) | null = null;
let mcpError: string | null = null;
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
		connector: { oauth, gatewayPort: connectorPort, tunnel, gatewayToken },
		syncStatus: () => (ctx.sync ? (ctx.sync.status() as unknown as Record<string, unknown>) : null),
		info: () => ({
			mock: mode.isolated,
			mcp_url: mcpUrl, // Historical compatibility field; not the primary connection setting.
			mcp_status: mcpStatus,
			mcp_error: mcpError,
			mcp_secure_url: mcpStatus === "ready" ? `${mcpUrl}/secure` : null,
			mcp_legacy_http: mcpLegacyHttp, // Configured opt-in, retained for old consumers.
			mcp_legacy_http_enabled: mcpStatus === "ready" && mcpLegacyHttp,
			mcp_auth: "mcp-psk-aead-v1",
			data_key: dataKey.source,
			transport: "stdio-adapter",
			read_receipts: store.getSetting("read_receipts") === "on" ? "enabled" : "blocked",
			counts: store.counts(),
		}),
	},
	{ port: Number(process.env.LINE_CONTROL_PORT ?? 47824), token: controlToken, hmacOnly: process.env.LMA_CONTROL_HMAC_ONLY === "1" },
).catch((e: NodeJS.ErrnoException) => {
	// secreview SR-01：控制埠被佔用 → 可能有其他 App 冒充本服務；不啟動，交給 UI 的身分驗證顯示警告
	console.error(JSON.stringify({ event: "control_start_failed", reason: e.code === "EADDRINUSE" ? "port_in_use" : "start_failed" }));
	process.exit(75);
});
// secreview SR-02：MCP 埠被其他程式佔用時不崩潰，記錄並讓 UI 顯示警告，之後每 30 秒重試
async function startMcp(): Promise<boolean> {
	try {
		const mcp = await startMcpHttp(ctx, { port: mcpPort, getToken: () => mcpToken, allowLegacyBearer: mcpLegacyHttp, audit });
		mcpStats = mcp.stats;
		mcpUrl = mcp.url;
		mcpStatus = "ready";
		mcpError = null;
		return true;
	} catch (e) {
		mcpStatus = "unavailable";
		mcpError = (e as NodeJS.ErrnoException).code === "EADDRINUSE" ? "port_in_use" : "start_failed";
		audit.log("system", "mcp_start_failed", { ok: false, detail: { reason: mcpError } });
		console.error(JSON.stringify({ event: "mcp_start_failed", reason: mcpError, port: mcpPort }));
		return false;
	}
}
if (!(await startMcp())) {
	const retry = setInterval(() => void startMcp().then((ok) => ok && clearInterval(retry)), 30_000);
}
const gateway = await startGateway(ctx, { port: connectorPort, store, oauth, audit, gatewayToken });
if (process.env.LMA_CONNECTOR === "1") {
	// 桌面模式：配對碼印在 stderr（Android 上只在 App 畫面顯示）
	console.error(JSON.stringify({ event: "connector", gateway: gateway.url, note: "retrieve pairing code through authenticated /control/connector" }));
	if (process.env.LMA_TUNNEL === "cloudflare") void tunnel.start(connectorPort).then((st) => console.error(JSON.stringify({ event: "tunnel_status", ...st })));
}
console.log(JSON.stringify({ event: "ready", control: control.url, mcp: mcpUrl, mcp_error: mcpError, connector: gateway.url, mock: mode.isolated }));

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

if (mode.initialize) await mode.initialize({ store, home, whitelist, ctx, outbox, ai, policy, scam, warner,
    digests, links, poster, attachSync, pollLoop, setLoginState: value => { state = value; } });

// 已有 token → 直接上線；清除資料後沒有 token → 等 UI 觸發 QR 登入，登入後自動完整同步
if (!mode.isolated && session.savedToken()) {
	session
		.loginWithToken()
		.then(goOnline)
		.catch((e) => (state = { phase: "error", error: isAuthError(e) ? "LINE 登入已失效，請重新登入" : `token login failed: ${(e as Error).message}` }));
}
