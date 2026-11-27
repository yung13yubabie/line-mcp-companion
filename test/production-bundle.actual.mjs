// Actual compiler/static artifact checks; never executes bundled application or contacts LINE.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
const bun = process.env.BUN_BINARY || "bun";
const build = release => spawnSync(bun, ["scripts/bundle.ts", ...(release ? ["--release"] : [])], { encoding: "utf8", env: { ...process.env, LINE_MCP_MOCK: "1", LMA_INCLUDE_MOCK: "1" } });
const gate = () => spawnSync("bash", ["scripts/purge-mock-check.sh", "android/app/src/main/assets/nodeapp/main.mjs"], { encoding: "utf8" });
const output = "android/app/src/main/assets/nodeapp";

test("real debug build retains QA while real production build excludes its entire source closure", () => {
 try {
  let result = build(false); assert.equal(result.status, 0, result.stderr);
  let js = readFileSync(`${output}/main.mjs`, "utf8");
  assert.match(js, /LMA_MOCK_DATA_v1/); assert.match(js, /LINE_MCP_MOCK/);
  assert.notEqual(gate().status, 0, "debug artifact cannot pass production gate");
  result = build(true); assert.equal(result.status, 0, result.stderr);
  js = readFileSync(`${output}/main.mjs`, "utf8");
  assert.doesNotMatch(js, /MockSource|MockAiProvider|MockSender|goMockOnline|LINE_MCP_MOCK|LMA_INCLUDE_MOCK|mock_seeded|[cu]_mock_|mock:\/\/local|mock-chat|mock-image/);
  const receipt = JSON.parse(readFileSync(`${output}/build-boundary.json`, "utf8"));
  assert.equal(receipt.mode, "production");
  assert.ok(receipt.inputs["src/runtime-mode.production.ts"]);
  assert.ok(!Object.keys(receipt.inputs).some(name => name.startsWith("src/mock/") || name === "src/runtime-mode.ts"));
  const inspected = gate(); assert.equal(inspected.status, 0, inspected.stdout + inspected.stderr);
 } finally { const restored = build(true); assert.equal(restored.status, 0, restored.stderr); }
});

test("actual bundler refuses QA imports in production policy and removes stale successful output", () => {
 const root = mkdtempSync(join(tmpdir(), "synthetic-bundle-closure-"));
 try {
  mkdirSync(join(root, "scripts")); mkdirSync(join(root, "src/mock"), { recursive: true });
  copyFileSync("scripts/bundle.ts", join(root, "scripts/bundle.ts"));
  writeFileSync(join(root, "src/main.ts"), 'import { mode } from "./runtime-mode.ts"; console.log(mode);');
  writeFileSync(join(root, "src/runtime-mode.ts"), 'export const mode = "debug";');
  writeFileSync(join(root, "src/runtime-mode.production.ts"), 'export const mode = "production";');
  writeFileSync(join(root, "src/mock/fixture.ts"), 'export const synthetic = "not data from a person";');
  let result = spawnSync(bun, ["scripts/bundle.ts", "--release"], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  writeFileSync(join(root, "src/runtime-mode.production.ts"), 'import "./mock/fixture.ts"; export const mode = "production";');
  result = spawnSync(bun, ["scripts/bundle.ts", "--release"], { cwd: root, encoding: "utf8" });
  assert.notEqual(result.status, 0, "QA source must fail the real compiler plugin");
  assert.match(result.stderr, /QA module in production closure/);
  assert.equal(existsSync(join(root, output, "main.mjs")), false, "previous successful JS removed on failure");
  assert.equal(existsSync(join(root, output, "build-boundary.json")), false, "previous successful receipt removed on failure");
 } finally { rmSync(root, { recursive: true, force: true }); }
});
