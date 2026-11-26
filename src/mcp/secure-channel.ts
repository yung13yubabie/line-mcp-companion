/** MCP-only PSK channel. Direction and startup epoch are authenticated, never sent as credentials. */
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { request } from "node:http";
import { JSONRPCMessageSchema, type JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

export const MCP_REQUEST_LIMIT = 256 * 1024;
export const MCP_RESPONSE_LIMIT = 24 * 1024 * 1024;
export const MCP_SECURE_PATH = "/mcp/secure";
export const MCP_HELLO_PATH = "/mcp/secure/hello";
export const channelNonce = () => randomBytes(16).toString("hex");
export const validNonce = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
function key(token: string, purpose: string): Buffer {
 if (token.length < 16 || token.length > 512) throw new Error("invalid_mcp_key");
 return createHmac("sha256", token).update(`lma:mcp:channel:v1:${purpose}`).digest();
}
export function helloProof(token: string, challenge: string, epoch: string): string {
 return createHmac("sha256", key(token, "hello")).update(`mcp1:hello:${challenge}:${epoch}`).digest("hex");
}
export function sameProof(a: string, b: string): boolean {
 return /^[a-f0-9]{64}$/.test(a) && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
export function sealMcp(token: string, direction: "request" | "response", epoch: string, nonce: string, ts: number, status: number, plain: Uint8Array): Buffer {
 if (!validNonce(epoch) || !validNonce(nonce) || !Number.isSafeInteger(ts)) throw new Error("invalid_channel_context");
 const limit = direction === "request" ? MCP_REQUEST_LIMIT : MCP_RESPONSE_LIMIT;
 if (plain.byteLength > limit) throw new Error("mcp_body_too_large");
 const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key(token, direction), iv, { authTagLength: 16 });
 cipher.setAAD(Buffer.from(`mcp1:${direction}:${epoch}:${nonce}:${ts}:POST:${MCP_SECURE_PATH}:${status}`));
 const body = Buffer.concat([cipher.update(plain), cipher.final()]);
 return Buffer.concat([iv, body, cipher.getAuthTag()]);
}
export function openMcp(token: string, direction: "request" | "response", epoch: string, nonce: string, ts: number, status: number, raw: Buffer): Buffer {
 if (!validNonce(epoch) || !validNonce(nonce) || !Number.isSafeInteger(ts)) throw new Error("invalid_channel_context");
 const limit = direction === "request" ? MCP_REQUEST_LIMIT : MCP_RESPONSE_LIMIT;
 if (raw.length < 28 || raw.length > limit + 28) throw new Error("invalid_channel_body");
 const cipher = createDecipheriv("aes-256-gcm", key(token, direction), raw.subarray(0, 12), { authTagLength: 16 });
 cipher.setAAD(Buffer.from(`mcp1:${direction}:${epoch}:${nonce}:${ts}:POST:${MCP_SECURE_PATH}:${status}`));
 cipher.setAuthTag(raw.subarray(-16));
 return Buffer.concat([cipher.update(raw.subarray(12, -16)), cipher.final()]);
}
export function secureMcpUrl(value: string): URL {
 const url = new URL(value);
 if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password || url.pathname !== MCP_SECURE_PATH || url.search || url.hash) throw new Error("invalid_mcp_url");
 return url;
}
// node:http is direct loopback, ignores environment proxies and never follows redirects.
async function exchange(url: URL, method: "GET" | "POST", headers: Record<string, string>, body: Buffer, limit: number, deadline: number): Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; bytes: Buffer }> {
 return await new Promise((resolve, reject) => {
  const req = request(url, { method, headers, agent: false }, res => {
   const chunks: Buffer[] = []; let count = 0;
   res.on("data", (chunk: Buffer) => {
    count += chunk.length;
    if (count > limit) { req.destroy(new Error("mcp_response_too_large")); res.destroy(); return; }
    chunks.push(chunk);
   });
   res.on("error", reject);
   res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, bytes: Buffer.concat(chunks) }));
  });
  const timer = setTimeout(() => req.destroy(new Error("mcp_channel_timeout")), Math.max(1, deadline - Date.now()));
  req.on("close", () => clearTimeout(timer));
  req.on("error", reject);
  req.end(body);
 });
}
export async function secureMcpRequest(value: string, token: string, message: JSONRPCMessage): Promise<JSONRPCMessage | null> {
 const url = secureMcpUrl(value), deadline = Date.now() + 60_000;
 const challenge = channelNonce();
 const helloUrl = new URL(MCP_HELLO_PATH, url);
 const hello = await exchange(helloUrl, "GET", { "x-lma-mcp-challenge": challenge }, Buffer.alloc(0), 256, deadline);
 const epoch = hello.headers["x-lma-mcp-epoch"], proof = hello.headers["x-lma-mcp-proof"];
 if (hello.status !== 204 || !validNonce(epoch) || typeof proof !== "string" || !sameProof(proof, helloProof(token, challenge, epoch))) throw new Error("mcp_server_untrusted");
 const nonce = channelNonce(), ts = Date.now();
 const sealed = sealMcp(token, "request", epoch, nonce, ts, 0, Buffer.from(JSON.stringify(message)));
 const response = await exchange(url, "POST", { "content-type": "application/octet-stream", "x-lma-mcp-epoch": epoch, "x-lma-mcp-nonce": nonce, "x-lma-mcp-time": String(ts) }, sealed, MCP_RESPONSE_LIMIT + 28, deadline);
 const plain = openMcp(token, "response", epoch, nonce, ts, response.status, response.bytes);
 if (response.status !== 200 && response.status !== 202) throw new Error("mcp_channel_rejected");
 const decoded: unknown = JSON.parse(plain.toString("utf8"));
 if (!("id" in message)) {
  if (decoded !== null) throw new Error("invalid_notification_response");
  return null;
 }
 const reply = JSONRPCMessageSchema.parse(decoded);
 if (!("id" in reply) || reply.id !== message.id || "method" in reply) throw new Error("mcp_response_mismatch");
 return reply;
}
