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
import { buildReplyPrompt, buildImagePrompt, detectInjection, sanitizeReply, historyHasUrl, extractSticker, type HistoryItem } from "./prompt.ts";
import { StickerCatalog, type StickerRef } from "./stickers.ts";
import { lieflat } from "../style/lieflat/index.ts";
import { socialPost, DEFAULT_VOICE, type Platform, type VoiceCard } from "../style/social-post/index.ts";
import type { FilterResult } from "../style/types.ts";

export type AiDriver = "connector" | "builtin";

export interface Suggestion {
	text: string;
	sticker: StickerRef | null;
	flags: string[];
	injection_hits: string[];
	style: Pick<FilterResult, "method" | "changed"> & { before: number; after: number };
}

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
	readonly stickers: StickerCatalog;
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
		this.stickers = new StickerCatalog(store);
		outbox.stickerSendable = (st) => this.stickers.isSendable(st);
	}

	/** 「由連接器代聊」（外部 AI 經 MCP 送訊息，不需要 App 內 API key）或「App 內建 AI」 */
	get driver(): AiDriver {
		return this.store.getSetting("ai_driver") === "builtin" ? "builtin" : "connector";
	}
	setDriver(d: AiDriver): void {
		this.store.setSetting("ai_driver", d === "builtin" ? "builtin" : "connector");
		this.audit.log("ui", "ai_driver_changed", { detail: { driver: d } });
	}
	get persona(): string {
		return this.store.getSetting("ai_persona") ?? "";
	}
	setPersona(p: string): void {
		this.store.setSetting("ai_persona", String(p ?? "").slice(0, 300));
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
		return this.store.getMessages(chatId, { limit: n }).reverse().map(toItem);
	}

	/**
	 * 產生建議回覆（不送出）。checks：kill switch、全域開關、白名單、mode != off。
	 * flags 含 injection_suspected / url_in_output 等。
	 */
	async suggest(chatId: string, actor: Actor, instruction?: string | null, targetId?: string | null): Promise<Suggestion> {
		const b = this.policy.checkBasic(chatId, "text");
		if (!b.ok) {
			this.audit.log(actor, "suggest_denied", { chatId, ok: false, detail: { reason: b.reason } });
			throw denyError(b.reason);
		}
		const history = this.#history(chatId);
		let target: HistoryItem | null = null;
		if (targetId) {
			const t = this.store.getMessage(chatId, targetId);
			if (!t) throw new Error("target message not found in this chat");
			target = toItem(t);
		}
		// 檢查「我最後一次發言之後」的對方訊息＋指定要回覆的那則
		let lastSelf = -1;
		history.forEach((h, i) => h.fromSelf && (lastSelf = i));
		const incoming = [...history.slice(lastSelf + 1).filter((h) => !h.fromSelf), ...(target && !target.fromSelf ? [target] : [])];
		const hits = [...new Set(incoming.flatMap((h) => detectInjection(h.text).hits))];
		const chat = this.store.getChat(chatId)!;
		const stickerList = this.stickers.promptList();
		const msgs = buildReplyPrompt({ chatName: chat.name, history, instruction, persona: this.persona, stickers: stickerList, target });
		let raw: string;
		try {
			raw = await this.provider().chat(msgs);
		} catch (e) {
			this.audit.log(actor, "ai_error", { chatId, ok: false, detail: { error: redact((e as Error).message, 200) } });
			throw e;
		}
		const { text: body, stickerKey } = extractSticker(raw);
		const entry = stickerKey ? this.stickers.list({ ownedOnly: true }).find((e) => e.sticker_id === stickerKey) : undefined;
		const sticker: StickerRef | null = entry ? { package_id: entry.package_id, sticker_id: entry.sticker_id, version: entry.version } : null;
		const k = this.#opts.getKey();
		const secrets = [...(k ? [k] : []), ...(this.#opts.secrets?.() ?? [])];
		let text = "";
		let flags: string[] = [];
		let style: Suggestion["style"] = { method: "none", changed: false, before: 0, after: 0 };
		if (body || !sticker) {
			const out = sanitizeReply(body, { secrets, historyHasUrl: historyHasUrl(history) });
			text = out.text;
			flags = out.flags;
			if (b.cfg.style_lieflat) {
				const r = await lieflat.apply(text, { llm: (m) => this.provider().chat(m, { maxTokens: 400 }) });
				// 改寫後再過一次輸出檢查；不通過就保留原句
				try {
					const re = sanitizeReply(r.text, { secrets, historyHasUrl: historyHasUrl(history) });
					text = re.text;
					flags = [...new Set([...flags, ...re.flags])];
					style = { method: r.method, changed: r.changed, before: r.before.length, after: r.after.length };
				} catch {
					style = { method: "llm_rejected", changed: false, before: r.before.length, after: r.before.length };
				}
			}
		}
		if (stickerKey && !sticker) flags.push("unknown_sticker_dropped");
		if (hits.length) flags.push("injection_suspected");
		this.audit.log(actor, "suggestion_generated", { chatId, detail: { flags, hits, text: redact(text), sticker: sticker?.sticker_id, style: style.method } });
		return { text, sticker, flags, injection_hits: hits, style };
	}

	/** 產生建議並放進確認佇列（UI「取得建議」與 suggest 模式使用） */
	async suggestToQueue(chatId: string, actor: Actor, origin: "suggest" | "ui", instruction?: string | null, replyTo?: string | null): Promise<OutboxItem> {
		const s = await this.suggest(chatId, actor, instruction, replyTo);
		this.outbox.supersede(chatId, ["suggest", "auto"]);
		return this.outbox.enqueue({ chatId, ...suggestionPayload(s), origin, replyTo, flags: s.flags, forcePending: true }, actor).item;
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
		if (this.driver !== "builtin") return;
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
			if (this.driver !== "builtin" || !this.hasKey()) return null;
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
				return this.outbox.enqueue({ chatId, ...suggestionPayload(s), origin, triggerId, flags: s.flags, forcePending: cfg.mode !== "auto" }, "auto").item;
			} catch (e) {
				// 自動路徑被上限 / 間隔擋下 → 改放確認佇列讓使用者決定，並記錄原因
				const reason = (e as { reason?: string }).reason;
				if (reason === "rate_interval" || reason === "hourly_cap" || reason === "chat_daily_cap" || reason === "daily_cap") {
					return this.outbox.enqueue({ chatId, ...suggestionPayload(s), origin, triggerId, flags: [...s.flags, `limited:${reason}`], forcePending: true }, "auto").item;
				}
				throw e;
			}
		} finally {
			this.#inflight.delete(chatId);
		}
	}

	// ---- 社群貼文草稿（只草稿，不發布）--------------------------------------
	voice(): VoiceCard {
		try {
			return { ...DEFAULT_VOICE, ...(JSON.parse(this.store.getSetting("social_voice") ?? "{}") as Partial<VoiceCard>) };
		} catch {
			return DEFAULT_VOICE;
		}
	}
	setVoice(v: Partial<VoiceCard>): VoiceCard {
		const cur = this.voice();
		const clip = (x: unknown, n: number) => String(x ?? "").slice(0, n);
		const next: VoiceCard = {
			tone: clip(v.tone ?? cur.tone, 100),
			length: clip(v.length ?? cur.length, 100),
			opening: clip(v.opening ?? cur.opening, 100),
			ending: clip(v.ending ?? cur.ending, 100),
			banned: clip(v.banned ?? cur.banned, 200),
			samples: (v.samples ?? cur.samples ?? []).slice(0, 3).map((x) => clip(x, 800)),
		};
		this.store.setSetting("social_voice", JSON.stringify(next));
		return next;
	}

	/** 需要：AI 總開關 + 會話同時在 MCP 白名單與 AI 白名單。kill switch 不影響（不會發送任何東西）。 */
	async draftSocialPost(input: { chatId: string; platform: Platform; mode: "A" | "B" | "C"; note?: string | null; limit?: number }, actor: Actor): Promise<{ id: number; text: string; warnings: string[] }> {
		if (!this.policy.aiEnabled) throw denyError("ai_disabled");
		const chat = this.store.getChat(input.chatId);
		if (!chat || chat.allowed !== 1) throw denyError("chat_not_allowed");
		if (!this.policy.get(input.chatId).ai_allowed) throw denyError("ai_not_allowed");
		if (!["facebook", "instagram", "threads", "x"].includes(input.platform)) throw new Error("unknown platform");
		const messages = this.#history(input.chatId, Math.min(80, input.limit ?? 40));
		const participantNames = [...new Set(messages.filter((m) => !m.fromSelf).map((m) => m.sender))];
		const pin = { platform: input.platform, mode: input.mode, chatName: chat.name, messages, participantNames, voice: this.voice(), note: input.note };
		const raw = await this.provider().chat(socialPost.buildPrompt(pin), { maxTokens: 900 });
		const pp = socialPost.postProcess(raw, pin);
		const lf = await lieflat.apply(pp.text, { llm: (m) => this.provider().chat(m, { maxTokens: 1200 }) });
		const r = this.store.db
			.prepare("INSERT INTO social_draft(chat_id, platform, mode, text, warnings, created_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(input.chatId, input.platform, input.mode, lf.text, JSON.stringify(pp.warnings), Date.now());
		this.audit.log(actor, "social_draft_created", { chatId: input.chatId, detail: { platform: input.platform, mode: input.mode, warnings: pp.warnings.length } });
		return { id: Number(r.lastInsertRowid), text: lf.text, warnings: pp.warnings };
	}

	socialDrafts(limit = 20): { id: number; chat_id: string | null; platform: string; mode: string; text: string; warnings: string[]; created_at: number }[] {
		return (this.store.db.prepare("SELECT * FROM social_draft ORDER BY id DESC LIMIT ?").all(limit) as Record<string, unknown>[]).map((r) => ({
			...(r as unknown as { id: number; chat_id: string | null; platform: string; mode: string; text: string; created_at: number }),
			warnings: JSON.parse(String(r.warnings ?? "[]")) as string[],
		}));
	}

	stop(): void {
		for (const t of this.#timers.values()) clearTimeout(t);
		this.#timers.clear();
	}
}

function toItem(m: MessageRow): HistoryItem {
	return { id: m.id, sender: m.sender_name ?? m.sender_mid ?? "?", fromSelf: m.from_self === 1, text: m.text, type: m.content_type, at: m.sent_at };
}

function suggestionPayload(s: Suggestion): { kind: "text" | "sticker"; text: string | null; sticker: StickerRef | null } {
	if (s.sticker) return { kind: "sticker", text: s.text || null, sticker: s.sticker };
	return { kind: "text", text: s.text, sticker: null };
}
