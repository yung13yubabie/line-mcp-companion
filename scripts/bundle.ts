// 用法：bun scripts/bundle.ts [--release]
// --release：把 src/mock/mock-source.ts 換成 mock-stub.ts，並定義 LMA_INCLUDE_MOCK="0"
import { resolve } from "node:path";
const release = process.argv.includes("--release");
const out = "android/app/src/main/assets/nodeapp";
const r = await Bun.build({
	entrypoints: ["src/main.ts"],
	target: "node",
	format: "esm",
	outdir: out,
	naming: "main.mjs",
	minify: release ? { syntax: true, whitespace: false, identifiers: false } : false,
	define: release ? { "process.env.LMA_INCLUDE_MOCK": '"0"' } : {},
	plugins: release
		? [{ name: "strip-mock", setup(b) { b.onResolve({ filter: /mock-source(\.ts)?$/ }, () => ({ path: resolve("src/mock/mock-stub.ts") })); b.onResolve({ filter: /mock-ai(\.ts)?$/ }, () => ({ path: resolve("src/mock/mock-ai-stub.ts") })); } }]
		: [],
});
if (!r.success) { console.error(r.logs); process.exit(1); }
console.log(`bundled ${release ? "RELEASE (no mock)" : "DEBUG (mock available)"} → ${out}/main.mjs`);
