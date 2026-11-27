import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createRuntimeMode } from "../src/runtime-mode.production.ts";
import { openDatabase } from "../src/storage/db.ts";
import { AiPolicy } from "../src/ai/policy.ts";
import { Audit } from "../src/ai/audit.ts";
import { Outbox } from "../src/ai/outbox.ts";
import { offlineSender } from "../src/ai/sender.ts";
import { AiService } from "../src/ai/service.ts";
import { Whitelist } from "../src/whitelist.ts";
import { startControlHttp } from "../src/control/server.ts";

test("production scanner synthetic structures and refusal cases", () => {
 const result = spawnSync("python3", [resolve("test/production-artifact.test.py")], { encoding: "utf8" });
 assert.equal(result.status, 0, result.stdout + result.stderr);
 assert.match(result.stderr, /Ran 10 tests/);
 assert.match(result.stdout, /Executed 10; skipped 0; failures 0; errors 0/);
});

test("production gate fails closed for missing/empty/malformed/missing-receipt artifacts", () => {
 const dir = mkdtempSync(join(tmpdir(), "release-gate-"));
 try {
  writeFileSync(join(dir, "empty.mjs"), "");
  writeFileSync(join(dir, "arbitrary.mjs"), "console.log('synthetic fixture');");
  writeFileSync(join(dir, "invalid.apk"), "not a zip");
  for (const name of ["empty.mjs", "missing.mjs", "arbitrary.mjs", "invalid.apk"]) {
   const result = spawnSync("bash", [resolve("scripts/purge-mock-check.sh"), join(dir, name)], { encoding: "utf8" });
   assert.notEqual(result.status, 0, name);
   assert.doesNotMatch(result.stdout, /static_packaging_pass/);
  }
 } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("production policy ignores old QA environment and never redirects home or enables QA provider", () => {
 const policy = createRuntimeMode({ LINE_MCP_MOCK: "1", LMA_INCLUDE_MOCK: "1", mock_mode: "true" });
 assert.equal(policy.isolated, false);
 assert.equal(policy.dataDirectory("synthetic-home"), "synthetic-home");
 assert.equal(policy.dataKeyResolver, undefined);
 assert.equal(policy.aiOptions.providerExtensions, undefined);
 assert.equal(policy.initialize, undefined);
 assert.equal(policy.stickerImage, undefined);
});

test("stored QA AI preference is refused without constructing or calling any provider", () => {
 const store = openDatabase(":memory:");
 try {
  const policy = new AiPolicy(store), audit = new Audit(store), outbox = new Outbox(store, policy, audit, offlineSender);
  let factoryCalls = 0;
  const ai = new AiService(store, policy, outbox, audit, { home: ".unused-synthetic", getKey: () => undefined,
   providerFactory: () => { factoryCalls++; throw new Error("must not be constructed"); } });
  store.setSetting("ai_provider", "mock");
  assert.equal(ai.config().unavailable, true);
  assert.equal(ai.hasKey(), false);
  assert.throws(() => ai.provider(), /stored AI provider/);
  assert.equal(factoryCalls, 0);
 } finally { store.db.close(); }
});


test("real synthetic Control API can retire unsupported state and explicitly recover without provider calls or old queue dispatch", async () => {
 const store = openDatabase(":memory:");
 store.setSetting("ai_provider", "mock"); store.setSetting("ai_enabled", "on");
 store.setSetting("ai_base_url", "mock://local"); store.setSetting("ai_model", "mock-chat");
 for (const status of ["pending", "approved"]) store.db.prepare("INSERT INTO outbox(chat_id,kind,text,origin,status,created_at,scheduled_at) VALUES ('synthetic-chat','text','synthetic queued draft','auto',?,0,0)").run(status);
 let factories = 0, sends = 0;
 const policy = new AiPolicy(store), audit = new Audit(store);
 const outbox = new Outbox(store, policy, audit, { ...offlineSender, sendText: async () => { sends++; } });
 const ai = new AiService(store, policy, outbox, audit, { home: ".unused-synthetic", getKey: () => "synthetic-not-used-key",
  providerFactory: () => { factories++; throw new Error("no provider should be constructed"); } });
 const { server, url } = await startControlHttp({ store, whitelist: new Whitelist(store), login: () => ({ phase: "logged_out" }), startQrLogin: () => { throw new Error("no LINE login"); }, ai }, { port: 0, token: "synthetic-control-token-12345" });
 const headers = { authorization: "Bearer synthetic-control-token-12345", "content-type": "application/json" };
 try {
  const response = await fetch(`${url}/ai`, { headers }); assert.equal(response.status, 200);
  const view = await response.json();
  assert.equal(view.config.unavailable, true); assert.equal(view.enabled, false); assert.equal(view.has_key, false);
  assert.deepEqual([view.config.base_url, view.config.model, view.config.fallback], ["", "", []]);
  assert.ok(!view.presets.mock);
  assert.equal((await fetch(`${url}/dashboard`, { headers })).status, 200);
  assert.deepEqual(store.db.prepare("SELECT status,error FROM outbox ORDER BY id").all().map(item => [item.status, item.error]), [["pending", null], ["expired", "unsupported_ai_provider"]]);
  const invalid = await fetch(`${url}/ai`, { method: "POST", headers, body: JSON.stringify({ provider: "mock", enabled: false }) });
  assert.notEqual(invalid.status, 200);
  const recovered = await fetch(`${url}/ai`, { method: "POST", headers, body: JSON.stringify({ provider: "openai", enabled: false }) });
  assert.equal(recovered.status, 200); const normal = await recovered.json();
  assert.equal(normal.config.provider, "openai"); assert.equal(normal.config.unavailable, undefined); assert.equal(normal.enabled, false);
  assert.notEqual(normal.config.base_url, "mock://local"); assert.notEqual(normal.config.model, "mock-chat");
  policy.setAiEnabled(true); assert.equal(await outbox.processDue(), 0);
  assert.equal(factories, 0); assert.equal(sends, 0);
 } finally { await new Promise(resolve => server.close(resolve)); store.close(); }
});
