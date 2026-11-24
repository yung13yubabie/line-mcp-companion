/**
 * 本機 MCP Server（Streamable HTTP，stateless，JSON 回應）。
 * - 預設只綁 127.0.0.1；不設 CORS（瀏覽器網頁無法呼叫）。
 * - 可選 Bearer token（Android 上建議一律開，因為同機其他 App 也能連 loopback）。
 */
import { createServer, type Server, type IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { callTool, type ToolContext } from "./tools.ts";
import { ChatNotAllowedError } from "../whitelist.ts";

const timeArg = z.union([z.number(), z.string()]).optional().describe("epoch ms 或 ISO 8601");

const TOOL_DEFS: Record<string, { description: string; schema: Record<string, z.ZodType> }> = {
	list_allowed_chats: { description: "列出使用者勾選「允許 AI / MCP 存取」的會話。", schema: {} },
	get_messages: {
		description: "讀取指定會話訊息（新到舊分頁）。用回傳的 next_before 取下一頁。不會標已讀。",
		schema: { chat_id: z.string(), limit: z.number().int().min(1).max(500).optional(), before: timeArg, after: timeArg },
	},
	search_messages: {
		description: "全文搜尋允許會話中的訊息（中文可用；3 字以上走 FTS5 trigram）。",
		schema: { query: z.string().min(1), chat_id: z.string().optional(), limit: z.number().int().min(1).max(200).optional() },
	},
	get_attachment: { description: "取得一則訊息的附件資訊與本機快取路徑。", schema: { chat_id: z.string(), message_id: z.string() } },
	download_media: {
		description: "下載訊息中的圖片/影片/檔案到 App 私有快取；inline=true 時同時回傳 base64（有大小上限）。",
		schema: { chat_id: z.string(), message_id: z.string(), inline: z.boolean().optional() },
	},
	get_unread_summary: { description: "允許會話的未讀摘要（本機計算，不呼叫 LINE 已讀 API）。", schema: { per_chat: z.number().int().min(0).max(50).optional() } },
	get_sync_status: { description: "同步狀態、筆數、已讀回條是否封鎖。", schema: {} },
	trigger_sync: { description: "手動觸發一次增量同步；full=true 先做完整同步。", schema: { full: z.boolean().optional() } },
};

export function buildMcpServer(ctx: ToolContext): McpServer {
	const server = new McpServer({ name: "line-mcp-app", version: "0.1.0" });
	for (const [name, def] of Object.entries(TOOL_DEFS)) {
		server.registerTool(name, { description: def.description, inputSchema: def.schema }, async (args: Record<string, unknown>) => {
			try {
				const result = await callTool(ctx, name, args);
				return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
			} catch (e) {
				const code = e instanceof ChatNotAllowedError ? e.code : "error";
				return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code, message: (e as Error).message }) }] };
			}
		});
	}
	return server;
}

export interface HttpOptions {
	host?: string;
	port?: number;
	token?: string;
}

function authorized(req: IncomingMessage, token?: string): boolean {
	if (!token) return true;
	const h = req.headers.authorization ?? "";
	const want = Buffer.from(`Bearer ${token}`);
	const got = Buffer.from(h);
	return got.length === want.length && timingSafeEqual(got, want);
}

export async function startMcpHttp(ctx: ToolContext, opts: HttpOptions = {}): Promise<{ server: Server; url: string }> {
	const host = opts.host ?? "127.0.0.1";
	const http = createServer(async (req, res) => {
		if (!req.url?.startsWith("/mcp")) {
			res.writeHead(404).end();
			return;
		}
		if (!authorized(req, opts.token)) {
			res.writeHead(401, { "content-type": "application/json" }).end('{"error":"unauthorized"}');
			return;
		}
		if (req.method !== "POST") {
			res.writeHead(405, { allow: "POST" }).end();
			return;
		}
		// stateless：每個請求一組 server+transport
		const mcp = buildMcpServer(ctx);
		const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
		res.on("close", () => {
			void transport.close();
			void mcp.close();
		});
		try {
			await mcp.connect(transport);
			await transport.handleRequest(req, res);
		} catch (e) {
			if (!res.headersSent) res.writeHead(500).end(JSON.stringify({ error: (e as Error).message }));
		}
	});
	await new Promise<void>((resolve) => http.listen(opts.port ?? 47823, host, resolve));
	const addr = http.address();
	const port = typeof addr === "object" && addr ? addr.port : opts.port;
	return { server: http, url: `http://${host}:${port}/mcp` };
}
