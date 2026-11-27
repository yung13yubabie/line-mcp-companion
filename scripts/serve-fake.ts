/** 用假資料啟動本機 MCP（不連 LINE），方便用 Claude Code / MCP Inspector 試工具。 */
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { SyncEngine } from "../src/sync/engine.ts";
import { MediaCache } from "../src/media/cache.ts";
import { startMcpHttp } from "../src/mcp/server.ts";
import { FakeSource, ALICE, GROUP } from "../test/fake-source.ts";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
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
// Never reuse an ambient application credential or print a key value.
const token = randomBytes(32).toString("hex");
const keyFile = join(dir, "mcp-channel.key");
writeFileSync(keyFile, token + "\n", { mode: 0o600 });
const { server, url } = await startMcpHttp({ store, whitelist, sync, media: new MediaCache(dir, store, src) }, {
 port: Number(process.env.LINE_MCP_PORT ?? 0), token, allowLegacyBearer: false,
});
console.log(JSON.stringify({ event: "ready", scope: "synthetic-host-fixture", mcp_secure_url: url + "/secure",
 mcp_legacy_http_enabled: false, key_file: keyFile, note: "Not Android acceptance; status smoke uses --url and --key-file." }));
let stopping = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => {
 if (stopping) return;
 stopping = true;
 server.close(() => { store.close(); rmSync(dir, { recursive: true, force: true }); });
 server.closeIdleConnections();
});
