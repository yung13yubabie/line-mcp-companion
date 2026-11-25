import { test } from "node:test";
import assert from "node:assert/strict";
import { openDatabase } from "../src/storage/db.ts";
import { Whitelist } from "../src/whitelist.ts";
import { startControlHttp, type LoginState } from "../src/control/server.ts";
import { ALICE } from "./fake-source.ts";

test("控制 API：需 token、可勾選會話與改設定", async () => {
	const store = openDatabase(":memory:");
	store.upsertChat({ id: ALICE, type: "USER", name: "Alice" });
	const whitelist = new Whitelist(store);
	let st: LoginState = { phase: "logged_out" };
	const { server, url } = await startControlHttp(
		{ store, whitelist, login: () => st, startQrLogin: () => void (st = { phase: "waiting_qr_scan", qrUrl: "https://line.me/R/au/lgn/sq/TEST" }) },
		{ port: 0, token: "ct-0123456789abcdef" },
	);
	const h = { authorization: "Bearer ct-0123456789abcdef", "content-type": "application/json" };
	try {
		assert.equal((await fetch(`${url}/state`)).status, 401);
		const q = await (await fetch(`${url}/login/qr`, { method: "POST", headers: h })).json();
		assert.equal(q.phase, "waiting_qr_scan");
		let chats = await (await fetch(`${url}/chats`, { headers: h })).json();
		assert.equal(chats[0].allowed, false);
		await fetch(`${url}/chats/allow`, { method: "POST", headers: h, body: JSON.stringify({ chat_id: ALICE, allowed: true }) });
		chats = await (await fetch(`${url}/chats`, { headers: h })).json();
		assert.equal(chats[0].allowed, true);
		assert.equal((await fetch(`${url}/settings`, { method: "POST", headers: h, body: JSON.stringify({ evil: 1 }) })).status, 400);
		await fetch(`${url}/settings`, { method: "POST", headers: h, body: JSON.stringify({ read_receipts: "off" }) });
		assert.equal(store.getSetting("read_receipts"), "off");
	} finally {
		server.close();
		store.close();
	}
});
