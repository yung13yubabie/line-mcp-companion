/**
 * 端到端 OAuth 煙霧測試：用官方 MCP SDK 的 OAuth 用戶端（與 Claude Code / Inspector 等同一套邏輯）
 * 自動發現 → DCR → PKCE → 授權頁輸入配對碼 → 換 token → 連線列工具 → 呼叫 search/fetch。
 *
 *   node scripts/oauth-smoke.ts <server_base> <control_url> <control_token> [--send]
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";

const [base, controlUrl, controlToken] = process.argv.slice(2);
const allowSend = process.argv.includes("--send");
if (!base || !controlUrl || !controlToken) throw new Error("usage: oauth-smoke.ts <server_base> <control_url> <control_token>");
const REDIRECT = "http://127.0.0.1:33418/callback";

let clientInfo: unknown;
let tokens: unknown;
let verifier = "";
let gotCode: string | null = null;

const provider: OAuthClientProvider = {
	get redirectUrl() {
		return REDIRECT;
	},
	get clientMetadata() {
		return { client_name: "oauth-smoke (MCP SDK)", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
	},
	clientInformation: () => clientInfo as never,
	saveClientInformation: (i) => void (clientInfo = i),
	tokens: () => tokens as never,
	saveTokens: (t) => void (tokens = t),
	saveCodeVerifier: (v) => void (verifier = v),
	codeVerifier: () => verifier,
	// 模擬使用者：打開授權頁、輸入 App 顯示的配對碼
	redirectToAuthorization: async (url) => {
		console.log("authorize:", url.origin + url.pathname, "params:", [...url.searchParams.keys()].join(","));
		const page = await (await fetch(url)).text();
		const nonce = /name="nonce" value="([^"]+)"/.exec(page)?.[1];
		if (!nonce) throw new Error("no consent form: " + page.slice(0, 200));
		const conn = (await (await fetch(`${controlUrl}/connector`, { headers: { authorization: `Bearer ${controlToken}` } })).json()) as { pairing: { code: string } };
		const form = new URLSearchParams({ nonce, pairing_code: conn.pairing.code, action: "allow", ...(allowSend ? { allow_send: "on" } : {}) });
		const r = await fetch(new URL("/oauth/authorize", url), { method: "POST", body: form, redirect: "manual" });
		const loc = new URL(r.headers.get("location") ?? "about:blank");
		console.log("consent →", r.status, loc.origin + loc.pathname, "iss=" + loc.searchParams.get("iss"));
		gotCode = loc.searchParams.get("code");
	},
};

const mcpUrl = new URL("/mcp", base);
let transport = new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider });
let client = new Client({ name: "oauth-smoke", version: "1" });
try {
	await client.connect(transport);
} catch (e) {
	if (!(e instanceof UnauthorizedError) || !gotCode) throw e;
	await transport.finishAuth(gotCode);
	transport = new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider });
	client = new Client({ name: "oauth-smoke", version: "1" });
	await client.connect(transport);
}
const t = tokens as { scope?: string; access_token: string };
console.log("token scope:", t.scope, "access_token prefix:", t.access_token.slice(0, 7));
const tools = (await client.listTools()).tools.map((x) => x.name);
console.log("tools:", tools.length, tools.includes("send_message") ? "(incl. send tools)" : "(read-only)");
const s = (await client.callTool({ name: "search", arguments: { query: "換群" } })) as { content: { text: string }[] };
const res = JSON.parse(s.content[0]!.text) as { results: { id: string }[] };
console.log("search results:", res.results.length);
if (res.results[0]) {
	const f = (await client.callTool({ name: "fetch", arguments: { id: res.results[0].id } })) as { content: { text: string }[] };
	console.log("fetch ok:", JSON.parse(f.content[0]!.text).id);
}
await client.close();
console.log("OK");
