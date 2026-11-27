import type { RuntimeContext } from "../runtime-contract.ts";
import { SyncEngine } from "../sync/engine.ts";
import { MediaCache } from "../media/cache.ts";
import * as mockAi from "./mock-ai.ts";

export async function initialize(deps: RuntimeContext): Promise<void> {
	const { store, home, whitelist, ctx, outbox, ai, policy, scam, warner, digests, links, poster, attachSync, pollLoop, setLoginState } = deps;
	const { MockSource, MOCK_DEFAULT_ALLOWED, MOCK_AI_ALLOWED, seedMockDigests, MOCK_LINK_PAGES } = await import("./mock-source.ts");
	// mock：連結讀取不連網
	links.useOffline(MOCK_LINK_PAGES);
	const src = new MockSource();
	setLoginState({ phase: "online", profile: { displayName: "Mock 使用者", mid: "u_mock_me" } });
	ctx.sync = new SyncEngine(store, src);
	ctx.media = new MediaCache(home, store, src);
	outbox.sender = new mockAi.MockSender(store);
	await ctx.sync.fullSync();
	if (!store.getSetting("mock_seeded")) {
		for (const id of MOCK_DEFAULT_ALLOWED) whitelist.set(id, true);
		await ctx.sync.fullSync();
		// 示範用設定：內建 AI（mock，不連網）＋兩個代聊會話＋確認佇列裡有幾則建議
		ai.setConfig({ provider: "mock" });
		ai.setDriver("builtin");
		policy.setAiEnabled(true);
		for (const id of MOCK_AI_ALLOWED) policy.set(id, { ai_allowed: true, mode: id === "c_mock_work" ? "auto" : "suggest" });
		// 示範信任狀態：工作群 AI 回覆升到「自動」（其餘維持審核）
		policy.setTrust("c_mock_work", "ai", "auto", "ui", "mock 示範");
		policy.set("c_mock_family", { ai_allowed: false });
		await ai.suggestToQueue("u_mock_mom", "auto", "suggest", null, "9004").catch((e) => console.error("mock seed:", (e as Error).message));
		await ai.suggestToQueue("c_mock_work", "auto", "suggest", null, "9201").catch((e) => console.error("mock seed:", (e as Error).message));
		// 反詐：重掃社區群、開啟即時提醒（@ 管委會小李）
		scam.setAdmin("c_mock_hood", "u_mock_n1", { name: "管委會小李", mention: true });
		scam.rescanChat("c_mock_hood");
		warner.set("c_mock_hood", { enabled: true, mention_admins: true });
		// 日報示範（只在 mock）
		try {
			seedMockDigests(store, digests);
			store.setSetting("link_read:c_mock_work", "on");
			store.setSetting("link_read:c_mock_hood", "on");
			poster.saveSchedule({ target_chat: "c_mock_work", source_chats: ["c_mock_work", "c_mock_hood"], time_hhmm: "21:00", generate: true }, "system");
		} catch (e) {
			console.error("mock digests:", (e as Error).message);
		}
		store.setSetting("mock_seeded", "1");
	} else src.live = []; // 已示範過即時提醒
	attachSync(ctx.sync);
	void pollLoop();
}

