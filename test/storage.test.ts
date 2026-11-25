import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDatabase } from "../src/storage/db.ts";
import { SqliteKvStorage } from "../src/storage/kv-storage.ts";
import { SecretBox } from "../src/storage/secret-box.ts";
import { randomBytes } from "node:crypto";
import { SyncEngine } from "../src/sync/engine.ts";
import { FakeSource, ALICE, GROUP, SECRET, ME, msg } from "./fake-source.ts";

test("schema: FTS5 trigram 中文搜尋 + 短查詢 fallback", () => {
	const s = openDatabase(":memory:");
	s.upsertChat({ id: ALICE, type: "USER", name: "Alice" });
	s.insertMessage({ chatId: ALICE, id: "1", sentAt: 1, text: "今天晚餐吃什麼？" });
	s.insertMessage({ chatId: ALICE, id: "2", sentAt: 2, text: "明天早餐" });
	assert.equal(s.searchMessages("晚餐吃", [ALICE]).length, 1, "3+ 字走 FTS");
	assert.equal(s.searchMessages("餐", [ALICE]).length, 2, "1 字走 instr");
	assert.equal(s.searchMessages("晚餐", [ALICE]).length, 1, "2 字走 instr");
	assert.equal(s.searchMessages("晚餐吃", []).length, 0, "空範圍不回傳");
});

test("insertMessage 冪等，message id 保持字串", () => {
	const s = openDatabase(":memory:");
	s.upsertChat({ id: ALICE, type: "USER", name: "Alice" });
	const big = "612345678901234567890";
	assert.equal(s.insertMessage({ chatId: ALICE, id: big, sentAt: 5, text: "x" }), true);
	assert.equal(s.insertMessage({ chatId: ALICE, id: big, sentAt: 5, text: "x" }), false);
	assert.equal(s.getMessage(ALICE, big)!.id, big);
	assert.equal(s.counts().messages, 1);
});

test("SqliteKvStorage 實作 LINEJS BaseStorage（含 bigint）", async () => {
	const s = openDatabase(":memory:");
	const kv = new SqliteKvStorage(s, new SecretBox(randomBytes(32)));
	await kv.set("refreshToken", "rt");
	await kv.set("obj", { a: 1, b: 2n } as never);
	assert.equal(await kv.get("refreshToken"), "rt");
	assert.deepEqual(await kv.get("obj"), { a: 1, b: 2n });
	await kv.delete("refreshToken");
	assert.equal(await kv.get("refreshToken"), undefined);
});

test("同步：scope=allowed 只下載勾選會話的訊息；清除資料後可重建", async () => {
	const dir = mkdtempSync(join(tmpdir(), "lma-"));
	try {
		const path = join(dir, "line.db");
		let s = openDatabase(path);
		const src = new FakeSource();
		let eng = new SyncEngine(s, src);
		await eng.fullSync();
		assert.equal(s.counts().chats, 3);
		assert.equal(s.counts().messages, 0, "沒有勾選 → 不抓內容");
		s.setAllowed(ALICE, true);
		await eng.fullSync();
		assert.equal(s.counts().messages, 3);

		// 增量：允許會話收新訊息；未允許會話的訊息不落地
		src.push(msg("1004", ALICE, ALICE, 10, "到了嗎"));
		src.push(msg("3002", SECRET, ME, 11, "不該被存"));
		src.pushRead(ALICE, "1002", Date.parse("2026-11-24T10:01:00+08:00"));
		assert.equal(await eng.pollOnce(), 1);
		assert.equal(s.getMessage(SECRET, "3002"), undefined);
		assert.equal(eng.status().cursor, String(src.rev));

		// 模擬 Android「清除資料」：刪掉 DB 後重開 → fullSync 自動重建
		s.close();
		rmSync(dir, { recursive: true, force: true });
		s = openDatabase(path);
		assert.equal(s.counts().chats, 0);
		eng = new SyncEngine(s, src);
		await eng.fullSync();
		assert.equal(s.counts().chats, 3);
		s.setSetting("sync_scope", "all");
		await eng.fullSync();
		assert.equal(s.counts().messages, 3 + 2 + 1, "scope=all 抓全部");
		assert.ok(s.getChat(GROUP));
		s.close();
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
