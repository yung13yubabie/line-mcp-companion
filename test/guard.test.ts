import { test } from "node:test";
import assert from "node:assert/strict";
import { BaseClient } from "@evex-dev/linejs/base";
import { MemoryStorage } from "@evex-dev/linejs/storage";
import { installUpstreamGuards, UpstreamBlockedError } from "../src/guard/upstream-guard.ts";

function fakeClient() {
	const calls: string[] = [];
	const c = {
		request: { request: async (_v: unknown, m: string) => (calls.push(m), "ok") },
		e2ee: { registerE2EEKeyPair: async () => (calls.push("registerE2EEKeyPair"), "reg") },
	};
	return { c, calls };
}

test("預設封鎖 sendChatChecked / markAsRead 等已讀 RPC", async () => {
	const { c, calls } = fakeClient();
	installUpstreamGuards(c);
	for (const m of ["sendChatChecked", "markAsRead", "markChatsAsRead", "markThreadsAsRead"]) {
		await assert.rejects(c.request.request([], m), (e: unknown) => e instanceof UpstreamBlockedError && e.code === "read_receipt_blocked");
	}
	assert.equal(await c.request.request([], "getRecentMessagesV2"), "ok");
	assert.deepEqual(calls, ["getRecentMessagesV2"], "被擋的 RPC 完全沒送出");
});

test("明確開啟 read_receipts 才放行", async () => {
	const { c, calls } = fakeClient();
	let on = false;
	installUpstreamGuards(c, { isReadReceiptEnabled: () => on });
	await assert.rejects(c.request.request([], "sendChatChecked"));
	on = true;
	assert.equal(await c.request.request([], "sendChatChecked"), "ok");
	assert.deepEqual(calls, ["sendChatChecked"]);
});

test("E2EE 金鑰註冊預設封鎖（含 registerE2EEKeyPair 函式層）", async () => {
	const { c, calls } = fakeClient();
	installUpstreamGuards(c);
	await assert.rejects(c.request.request([], "registerE2EEPublicKey"), /key_registration_blocked/);
	await assert.rejects(c.e2ee.registerE2EEKeyPair(), /key_registration_blocked/);
	assert.deepEqual(calls, []);
});

test("真的 LINEJS BaseClient：talk.sendChatChecked 在送出前就被擋（不連網）", async () => {
	const base = new BaseClient({ device: "ANDROIDSECONDARY", storage: new MemoryStorage(), fetch: async () => { throw new Error("network must not be touched"); } });
	installUpstreamGuards(base as never);
	await assert.rejects(base.talk.sendChatChecked({ chatMid: "c1", lastMessageId: "1", seq: 0 }), (e: unknown) => e instanceof UpstreamBlockedError);
	await assert.rejects(base.square.markAsRead({ request: { squareChatMid: "m1", messageId: "1" } } as never), (e: unknown) => e instanceof UpstreamBlockedError);
	assert.equal(base.device, "ANDROIDSECONDARY");
});
