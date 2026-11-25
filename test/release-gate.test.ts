import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

test("release mock gate fails closed for missing, empty, and malformed artifacts", () => {
	const dir = mkdtempSync(join(tmpdir(), "release-gate-test-"));
	const script = resolve("scripts/purge-mock-check.sh");
	const scratch = join(dir, "scratch");
	mkdirSync(scratch);
	const run = (name: string) => spawnSync("bash", [script, join(dir, name)], {
		encoding: "utf8", env: { ...process.env, TMPDIR: scratch },
	});
	try {
		writeFileSync(join(dir, "clean.mjs"), 'console.log("production fixture");\n');
		writeFileSync(join(dir, "mock.mjs"), 'console.log("LMA_MOCK_DATA_v1");\n');
		writeFileSync(join(dir, "empty.mjs"), "");
		writeFileSync(join(dir, "invalid.apk"), "not a zip archive");
		assert.equal(run("clean.mjs").status, 0);
		for (const name of ["mock.mjs", "missing.mjs", "empty.mjs", "invalid.apk"]) {
			const result = run(name);
			assert.notEqual(result.status, 0, `${name} must fail: ${result.stdout}`);
			assert.doesNotMatch(result.stdout, /OK: no mock data/);
		}
		assert.deepEqual(readdirSync(scratch), [], "temporary extraction directory must be removed");
	} finally { rmSync(dir, { recursive: true, force: true }); }
});

test("release mock gate rejects an APK without its required main bundle", () => {
	const dir = mkdtempSync(join(tmpdir(), "release-apk-test-"));
	try {
		// Minimal valid ZIP with one stored file: assets/nodeapp/metadata.json.
		// Its lack of main.mjs reproduced a false successful gate in the reviewed version.
		const apk = Buffer.from("UEsDBBQAAAAAAI6TeV1Dv6ajAgAAAAIAAAAcAAAAYXNzZXRzL25vZGVhcHAvbWV0YWRhdGEuanNvbnt9UEsBAhQDFAAAAAAAjpN5XUO/pqMCAAAAAgAAABwAAAAAAAAAAAAAAIABAAAAAGFzc2V0cy9ub2RlYXBwL21ldGFkYXRhLmpzb25QSwUGAAAAAAEAAQBKAAAAPAAAAAAA", "base64");
		const filename = join(dir, "missing-main.apk");
		writeFileSync(filename, apk);
		const listing = spawnSync("unzip", ["-l", filename], { encoding: "utf8" });
		assert.equal(listing.status, 0, "fixture must be a valid ZIP");
		assert.match(listing.stdout, /assets\/nodeapp\/metadata\.json/);
		const result = spawnSync("bash", [resolve("scripts/purge-mock-check.sh"), filename], { encoding: "utf8" });
		assert.notEqual(result.status, 0);
		assert.doesNotMatch(result.stdout, /OK: no mock data/);
	} finally { rmSync(dir, { recursive: true, force: true }); }
});
