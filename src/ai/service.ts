/**
 * AI 服務：供應商設定、能力偵測、建議回覆、自動回覆引擎、圖片生成。
 * 對外只透過 Outbox 送訊息；本身不直接呼叫 LINE。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Store, MessageRow } from "../storage/db.ts";
import { AiPolicy, inActiveHours, denyError } from "./policy.ts";
import { Outbox, type OutboxItem } from "./outbox.ts";
import { Audit, redact, type Actor } from "./audit.ts";
import { OpenAICompatProvider, PRESETS, validateBaseUrl, type AiConfig, type AiProvider, type AiCapabilities, type ProviderKind } from "./provider.ts";
import { buildReplyPrompt, buildImagePrompt, detectInjection, sanitizeReply, historyHasUrl, type HistoryItem } from "./prompt.ts";

export interface AiServiceOptions {
	home: string;
	/** 讀取 API key（只在記憶體） */
	getKey: () => string | undefined;
	/** 測試 / mock 用：自訂 provider 工廠 */
	providerFactory?: (cfg: AiConfig, getKey: () => string | undefined) => AiProvider;
	/** 是否允許 mock provider（release 為 false） */
	allowMock?: boolean;
	/** 自動回覆的 debounce（ms） */
	debounceMs?: number;
	secrets?: () => string[];
}

const PROVIDERS: ProviderKind[] = ["openai", "xai", "anthropic", "custom", "mock"];

export class AiService {
	readonly store: Store;
	readonly policy: AiPolicy;
	readonly outbox: Outbox;
	readonly audit: Audit;
	#opts: AiServiceOptions;
	#provider: AiProvider | null = null;
	#timers = new Map<string, ReturnType<typeof setTimeout>>();
	#inflight = new Set<string>();

	constructor(store: Store, policy: AiPolicy, outbox: Outbox, audit: Audit, opts: AiServiceOptions) {
		this.store = store;
		this.policy = policy;
		this.outbox = outbox;
		this.audit = audit;
		this.#opts = opts;
	}

	// ---- 設定 -------------------------------------------------------------
	config(): AiConfig {
		const g = (k: string) => this.store.getSetting(k);
		const provider = (PROVIDERS.includes(g("ai_provider") as ProviderKind) ? g("ai_provider") : "openai") as ProviderKind;
		const preset = provider === "mock" ? { base_url: "mock://local", model: "mock-chat", image_model: "mock-image" } : PRESETS[provider];
		return {
			provider,
			base_url: g("ai_base_url") ?? preset.base_url,
			model: g("ai_model") ?? preset.model,
			image_model: g("ai_image_model") ?? preset.image_model,
		};
	}

	setConfig(patch: Partial<AiConfig>): AiConfig {
		const cur = this.config();
		const provider = patch.provider ?? cur.provider;
		if (!PROVIDERS.includes(provider)) throw new Error("unknown provider");
		if (provider === "mock" && !this.#opts.allowMock) throw new Error("mock provider is only available in debug mock mode");
		const switching = patch.provider !== undefined && patch.provider !== cur.provider;
		const preset = provider === "mock" ? { base_url: "mock://local", model: "mock-chat", image_model: "mock-image" } : PRESETS[provider];
		const next: AiConfig = {
			provider,
			base_url: (patch.base_url ?? (switching ? preset.base_url : cur.base_url)).trim(),
			model: (patch.model ?? (switching ? preset.model : cur.model)).trim().slice(0, 100),
			image_model: (patch.image_model ?? (switching ? preset.image_model : cur.image_model)).trim().slice(0, 100),
		};
		if (provider !== "mock" && next.base_url) validateBaseUrl(next.base_url);
		this.store.setSetting("ai_provider", next.provider);
		this.store.setSetting("ai_base_url", next.base_url);
		this.store.setSetting("ai_model", next.model);
		this.store.setSetting("ai_image_model", next.image_model);
		this.store.setSetting("ai_capabilities", "");
		this.#provider = null;
		this.audit.log("ui", "ai_config_changed", { detail: { provider: next.provider, base_url: next.base_url, model: next.model, image_model: next.image_model } });
		return next;
	}

	hasKey(): boolean {
		return this.config().provider === "mock" || !!this.#opts.getKey();
	}

	/** 只回傳 key 的末 4 碼，給 UI 顯示 */
	keyHint(): string | null {
		const k = this.#opts.getKey();
		return k ? `••••${k.slice(-4)}` : null;
	}

	provider(): AiProvider {
		if (this.#provider) return this.#provider;
		const cfg = this.config();
		if (!this.hasKey()) throw new Error("尚未設定 API key");
		const f = this.#opts.providerFactory ?? ((c, k) => new OpenAICompatProvider(c, k));
		this.#provider = f(cfg, this.#opts.getKey);
		return this.#provider;
	}

	/** 換了 key 之後呼叫 */
	resetProvider(): void {
		this.#provider = null;
		this.store.setSetting("ai_capabilities", "");
	}

	capabilities(): AiCapabilities | null {
		const raw = this.store.getSetting("ai_capabilities");
		if (!raw) return null;
		try {
			return JSON.parse(raw) as AiCapabilities;
		} catch {
			return null;
		}
	}

	async detect(): Promise<AiCapabilities> {
		const caps = await this.provider().detect();
		this.store.setSetting("ai_capabilities", JSON.stringify(caps));
		this.audit.log("ui", "ai_detect", { ok: !caps.error, detail: { text: caps.text, vision: caps.vision, image_gen: caps.image_gen, voice: caps.voice, error: caps.error } });
		return caps;
	}

	// ---- 產生 -------------------------------------------------------------
	#history(chatId: string, n = 20): HistoryItem[] {
		return this.store
			.getMessages(chatId, { limit: n })
			.reverse()
			.map((m: MessageRow) => ({ sender: m.sender_name ?? m.sender_mid ?? "?", fromSelf: m.from_self === 1, text: m.text, type: m.content_type, at: m.sent_at }));
	}

	/**
	 * 產生建議回覆（不送出）。checks：kill switch、全域開關、白名單、mode != off。
	 * flags 含 injection_suspected / url_in_output 等。
	 */
	async suggest(chatId: string, actor: Actor, instruction?: string | null): Promise<{ text: string; flags: string[]; injection_hits: string[] }> {
		const b = this.policy.checkBasic(chatId, "text");
		if (!b.ok) {
			this.audit.log(actor, "suggest_denied", { chatId, ok: false, detail: { reason: b.reason } });
			throw denyError(b.reason);
		}
		const history = this.#history(chatId);
		// 只檢查「我最後一次發言之後」的對方訊息
		let lastSelf = -1;
		history.forEach((h, i) => h.fromSelf && (lastSelf = i));
		const incoming = history.slice(lastSelf + 1).filter((h) => !h.fromSelf);
		const hits = [...new Set(incoming.flatMap((h) => detectInjection(h.text).hits))];
		const chat = this.store.getChat(chatId)!;
		const msgs = buildReplyPrompt({ chatName: chat.name, history, instruction });
		let raw: string;
		try {
			raw = await this.provider().chat(msgs);
		} catch (e) {
			this.audit.log(actor, "ai_error", { chatId, ok: false, detail: { error: redact((e as Error).message, 200) } });
			throw e;
		}
		const k = this.#opts.getKey();
		const out = sanitizeReply(raw, { secrets: [...(k ? [k] : []), ...(this.#opts.secrets?.() ?? [])], historyHasUrl: historyHasUrl(history) });
		const flags = [...out.flags, ...(hits.length ? ["injection_suspected"] : [])];
		this.audit.log(actor, "suggestion_generated", { chatId, detail: { flags, hits, text: redact(out.text) } });
		return { text: out.text, flags, injection_hits: hits };
	}

	/** 產生建議並放進確認佇列（UI「取得建議」與 suggest 模式使用） */
	async suggestToQueue(chatId: string, actor: Actor, origin: "suggest" | "ui", instruction?: string | null, replyTo?: string | null): Promise<OutboxItem> {
		const s = await this.suggest(chatId, actor, instruction);
		this.outbox.supersede(chatId, ["suggest", "auto"]);
		return this.outbox.enqueue({ chatId, kind: "text", text: s.text, origin, replyTo, flags: s.flags, forcePending: true }, actor).item;
	}

	/** 生成圖片並排入佇列。先檢查圖片權限才呼叫供應商（避免浪費額度）。 */
	async imageToQueue(chatId: string, prompt: string, caption: string | null, actor: Actor, origin: "mcp" | "ui", originDetail?: string | null): Promise<{ item: OutboxItem; route: "pending" | "scheduled" }> {
		const b = this.policy.checkBasic(chatId, "image");
		if (!b.ok) {
			this.audit.log(actor, "image_denied", { chatId, ok: false, detail: { reason: b.reason } });
			throw denyError(b.reason);
		}
		if (!prompt.trim()) throw new Error("prompt is required");
		const p = buildImagePrompt(prompt);
		const flags = detectInjection(prompt).suspected ? ["injection_suspected"] : [];
		const img = await this.provider().generateImage(p);
		const dir = join(this.#opts.home, "ai-images");
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		const path = join(dir, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${img.mime === "image/jpeg" ? "jpg" : "png"}`);
		writeFileSync(path, img.bytes, { mode: 0o600 });
		this.audit.log(actor, "image_generated", { chatId, detail: { prompt: redact(p), bytes: img.bytes.byteLength } });
		return this.outbox.enqueue({ chatId, kind: "image", text: caption, prompt: p, imagePath: path, origin, originDetail, flags }, actor);
	}

	// ---- 自動回覆引擎 -------------------------------------------------------
	/** SyncEngine 寫入新訊息後呼叫。只處理白名單 + mode suggest/auto 的會話。 */
	onNewMessages(msgs: { chatId: string; id: string; fromSelf: boolean }[]): void {
		const byChat = new Map<string, string>();
		for (const m of msgs) if (!m.fromSelf) byChat.set(m.chatId, m.id);
		for (const [chatId, lastId] of byChat) {
			const b = this.policy.checkBasic(chatId, "text");
			if (!b.ok) continue;
			const prev = this.#timers.get(chatId);
			if (prev) clearTimeout(prev);
			this.#timers.set(
				chatId,
				setTimeout(() => {
					this.#timers.delete(chatId);
					void this.autoReply(chatId, lastId).catch(() => {});
				}, this.#opts.debounceMs ?? 5_000),
			);
		}
	}

	/** 對單一會話產生自動回覆 / 建議。回傳排入的項目或 null（被略過）。 */
	async autoReply(chatId: string, triggerId: string | null): Promise<OutboxItem | null> {
		if (this.#inflight.has(chatId)) return null;
		this.#inflight.add(chatId);
		try {
			const b = this.policy.checkBasic(chatId, "text");
			if (!b.ok) return null;
			const cfg = b.cfg;
			if (!this.hasKey()) return null;
			if (!inActiveHours(this.policy.clock.minuteOfDay(this.policy.clock.now()), cfg.active_start, cfg.active_end)) {
				this.audit.log("auto", "skipped_outside_active_hours", { chatId });
				return null;
			}
			const last = this.store.getMessages(chatId, { limit: 1 })[0];
			if (!last || last.from_self === 1) return null; // 使用者已經回了
			const s = await this.suggest(chatId, "auto");
			const origin = cfg.mode === "auto" ? "auto" : "suggest";
			this.outbox.supersede(chatId, ["suggest", "auto"]);
			try {
				return this.outbox.enqueue({ chatId, kind: "text", text: s.text, origin, replyTo: triggerId, flags: s.flags, forcePending: cfg.mode !== "auto" }, "auto").item;
			} catch (e) {
				// 自動路徑被上限 / 間隔擋下 → 改放確認佇列讓使用者決定，並記錄原因
				const reason = (e as { reason?: string }).reason;
				if (reason === "rate_interval" || reason === "hourly_cap" || reason === "chat_daily_cap" || reason === "daily_cap") {
					return this.outbox.enqueue({ chatId, kind: "text", text: s.text, origin, replyTo: triggerId, flags: [...s.flags, `limited:${reason}`], forcePending: true }, "auto").item;
				}
				throw e;
			}
		} finally {
			this.#inflight.delete(chatId);
		}
	}

	stop(): void {
		for (const t of this.#timers.values()) clearTimeout(t);
		this.#timers.clear();
	}
}
