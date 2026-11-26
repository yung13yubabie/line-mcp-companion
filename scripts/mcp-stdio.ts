/** Standard MCP stdio adapter to the application's MCP-only authenticated channel. */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { secureMcpRequest, secureMcpUrl, MCP_REQUEST_LIMIT } from "../src/mcp/secure-channel.ts";
import { openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { pathToFileURL } from "node:url";

export async function runMcpStdio(url: string, token: string): Promise<void> {
 secureMcpUrl(url);
 if (token.length < 16 || token.length > 512) throw new Error("invalid_mcp_key");
 const stdio = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: MCP_REQUEST_LIMIT });
 let active = 0, stopped = false;
 const stop = () => {
  if (stopped) return;
  stopped = true;
  process.stderr.write("MCP secure channel failed; no plaintext fallback.\n");
  process.exitCode = 1;
  void stdio.close();
 };
 stdio.onerror = stop;
 stdio.onmessage = message => {
  if (stopped) return;
  if (++active > 8) { active--; stop(); return; }
  void secureMcpRequest(url, token, message).then(async reply => {
   if (!stopped && reply) await stdio.send(reply);
  }).catch(stop).finally(() => { active--; });
 };
 process.stdin.once("end", () => { void stdio.close(); });
 await stdio.start();
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
 let token = process.env.LMA_MCP_CHANNEL_KEY ?? "";
 const keyFile = process.env.LMA_MCP_CHANNEL_KEY_FILE;
 delete process.env.LMA_MCP_CHANNEL_KEY;
 delete process.env.LMA_MCP_CHANNEL_KEY_FILE;
 try {
  if (keyFile) {
   const fd = openSync(keyFile, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
   try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 512 || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new Error("invalid_key_file");
    const buffer = Buffer.alloc(513);
    const count = readSync(fd, buffer, 0, buffer.length, 0);
    if (count > 512) throw new Error("invalid_key_file");
    token = buffer.subarray(0, count).toString("utf8").trim();
   } finally { closeSync(fd); }
  }
 } catch { token = ""; }
 runMcpStdio(process.argv[2] ?? "", token).catch(() => {
  process.stderr.write("Invalid MCP adapter configuration.\n");
  process.exitCode = 78;
 });
}
