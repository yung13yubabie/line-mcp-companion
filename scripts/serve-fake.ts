/** 用假資料啟動本機 MCP（不連 LINE），方便用 Claude Code / MCP Inspector 試工具。 */
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { SyncEngine } from "../src/sync/engine.ts";
import { MediaCache } from "../src/media/cache.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { FakeSource, ALICE, GROUP } from "../test/fake-source.ts";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "lma-fake-"));
const store = openDatabase(join(dir, "line.db"));
const src = new FakeSource();
const sync = new SyncEngine(store, src);
await sync.fullSync();
const whitelist = new Whitelist(store);
whitelist.set(ALICE, true);
whitelist.set(GROUP, true);
await sync.fullSync();
const token = process.env.LINE_MCP_TOKEN ?? randomBytes(16).toString("hex");
const { url } = await startMcpHttp({ store, whitelist, sync, media: new MediaCache(dir, store, src) }, { port: Number(process.env.LINE_MCP_PORT ?? 47823), token });
console.log(`MCP (fake data) at ${url}\nAuthorization: Bearer ${token}`);
