/** One authenticated JSON-RPC exchange per request; no streaming or server-initiated RPC. */
import type { IncomingMessage, ServerResponse } from "node:http";
import { JSONRPCMessageSchema, type JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ControlReplayWindow } from "../control/security.ts";
import { channelNonce, helloProof, validNonce, openMcp, sealMcp, MCP_REQUEST_LIMIT, MCP_SECURE_PATH, MCP_HELLO_PATH } from "./secure-channel.ts";
import type { buildMcpServer } from "./server.ts";
import type { ToolContext } from "./tools.ts";

export function secureMcpHandler(ctx: ToolContext, getToken: () => string | undefined, build: typeof buildMcpServer, hooks: { takeHello: () => boolean; takeRequest: () => boolean; takeSend: (message: JSONRPCMessage) => boolean; onCall?: (name: string, ok: boolean, ms: number, code?: string) => void; reject: () => boolean }) {
 const epoch = channelNonce(), replay = new ControlReplayWindow();
 return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
  const reject = (status: number) => { if ((status === 401 || status === 400 || status === 413) && !hooks.reject()) status = 429; res.writeHead(status, { "cache-control": "no-store" }).end(); };
  const token = getToken();
  if (!token || token.length < 16 || token.length > 512) return reject(503);
  if (req.url === MCP_HELLO_PATH) {
   if (!hooks.takeHello()) return reject(429);
   const challenge = req.headers["x-lma-mcp-challenge"];
   if (req.method !== "GET" || !validNonce(challenge)) return reject(400);
   res.writeHead(204, { "cache-control": "no-store", "x-lma-mcp-epoch": epoch, "x-lma-mcp-proof": helloProof(token, challenge, epoch) }).end();
   return;
  }
  if (req.url !== MCP_SECURE_PATH) return reject(404);
  if (req.method !== "POST") return reject(405);
  const nonce = req.headers["x-lma-mcp-nonce"], stamp = req.headers["x-lma-mcp-time"];
  if (!validNonce(nonce) || req.headers["x-lma-mcp-epoch"] !== epoch || typeof stamp !== "string" || !/^\d{13}$/.test(stamp)) return reject(401);
  const ts = Number(stamp);
  if (!replay.validTimestamp(ts)) return reject(401);
  let plain: Buffer;
  try {
   if (req.headers["content-type"] !== "application/octet-stream" || Number(req.headers["content-length"] ?? 0) > MCP_REQUEST_LIMIT + 28) return reject(413);
   const chunks: Buffer[] = []; let length = 0;
   for await (const part of req) {
    length += part.length;
    if (length > MCP_REQUEST_LIMIT + 28) return reject(413);
    chunks.push(Buffer.from(part));
   }
   plain = openMcp(token, "request", epoch, nonce, ts, 0, Buffer.concat(chunks));
   if (getToken() !== token || !replay.consume(nonce, ts)) return reject(401);
  } catch { return reject(401); }
  const send = (status: number, message: unknown) => {
   if (res.writableEnded || res.destroyed) return;
   if (getToken() !== token) { status = 401; message = null; }
   try {
    const bytes = sealMcp(token, "response", epoch, nonce, ts, status, Buffer.from(JSON.stringify(message)));
    res.writeHead(status, { "content-type": "application/octet-stream", "cache-control": "no-store" }).end(bytes);
   } catch { reject(500); }
  };
  let message: JSONRPCMessage;
  try { message = JSONRPCMessageSchema.parse(JSON.parse(plain.toString("utf8"))); }
  catch { return send(400, null); }
  if (!("method" in message)) return send(400, null);
  if (!hooks.takeRequest() || !hooks.takeSend(message)) return send(429, null);
  const server = build(ctx, { client: "secure-stdio", onCall: hooks.onCall, allowWrite: ctx.store.getSetting("mcp_allow_write") === "on" });
  let closed = false;
  const transport: Transport = {
   async start() {},
   async send(reply) { send(200, reply); },
   async close() { if (!closed) { closed = true; transport.onclose?.(); } },
  };
  const deadline = setTimeout(() => { send(504, null); void server.close(); }, 60_000);
  res.once("close", () => { clearTimeout(deadline); void server.close(); });
  try {
   await server.connect(transport);
   transport.onmessage?.(message);
   if (!("id" in message)) send(202, null);
  } catch { send(500, null); }
 };
}
