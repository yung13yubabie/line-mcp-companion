// bun scripts/bundle.ts [--release]. Production substitutes a whole policy module; no QA stubs.
import { resolve, relative, dirname } from "node:path";
import { readFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
const release = process.argv.includes("--release");
const out = "android/app/src/main/assets/nodeapp";
const source = resolve("src/runtime-mode.ts"), production = resolve("src/runtime-mode.production.ts");
const inputs = new Map<string, string>();
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
// A failed build cannot leave a previous successful bundle or stale extra runtime assets.
rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true });
const r = await Bun.build({
 entrypoints: ["src/main.ts"], target: "node", format: "esm", outdir: out, naming: "main.mjs",
 minify: release ? { syntax: true, whitespace: false, identifiers: false } : false,
 plugins: [{ name: "runtime-boundary", setup(b) {
  if (release) b.onResolve({ filter: /runtime-mode(\.ts)?$/ }, args => {
   if (resolve(dirname(args.importer), args.path) === source) return { path: production };
  });
  b.onLoad({ filter: /.*/ }, args => {
   const dep = args.path.lastIndexOf("/node_modules/");
   const name = dep >= 0 ? args.path.slice(dep + 1) : relative(resolve("."), args.path).replaceAll("\\", "/");
   if (release && (name.startsWith("src/mock/") || args.path === source)) throw new Error(`QA module in production closure: ${name}`);
   inputs.set(name, hash(readFileSync(args.path)));
   return undefined;
  });
 } }],
});
if (!r.success) { rmSync(out, { recursive: true, force: true }); console.error(r.logs); process.exit(1); }
const bundle = readFileSync(`${out}/main.mjs`);
writeFileSync(`${out}/build-boundary.json`, JSON.stringify({ schema: 1, mode: release ? "production" : "debug", bundle_sha256: hash(bundle),
 recipe_sha256: hash(readFileSync("scripts/bundle.ts")), inputs: Object.fromEntries([...inputs].sort()) }, null, 2) + "\n");
console.log(`bundled ${release ? "production policy" : "debug policy"} → ${out}/main.mjs`);
