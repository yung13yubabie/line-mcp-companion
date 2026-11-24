/**
 * AI 供應商（OpenAI 相容 API）。支援 OpenAI、xAI (Grok)、Anthropic (Claude，走其 OpenAI 相容端點)、自訂端點。
 *
 * 安全：
 *   - API key 不寫進 SQLite：由 Android 端以 Keystore 加密保存，啟動時經環境變數 / 控制 API 傳進記憶體。
 *   - 只允許 https；http 只允許 127.0.0.1 / localhost（本機 LLM）。
 *   - 每個請求都有逾時與回應大小上限；錯誤訊息會去掉 key。
 */
import { redact } from "./audit.ts";
import type { ChatMsg } from "./prompt.ts";

export type ProviderKind = "openai" | "xai" | "anthropic" | "custom" | "mock";

export interface AiConfig {
	provider: ProviderKind;
	base_url: string;
	model: string;
	image_model: string;
}

export interface AiCapabilities {
	text: boolean;
	vision: boolean;
	image_gen: boolean;
	voice: boolean;
	models: string[];
	checked_at: number;
	error?: string;
	/** vision / voice 是依模型名稱推測 */
	heuristic: boolean;
}

export const PRESETS: Record<Exclude<ProviderKind, "mock">, { base_url: string; model: string; image_model: string; label: string }> = {
	openai: { label: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4o-mini", image_model: "gpt-image-1" },
	xai: { label: "xAI Grok", base_url: "https://api.x.ai/v1", model: "grok-3-mini", image_model: "grok-2-image" },
	anthropic: { label: "Anthropic Claude", base_url: "https://api.anthropic.com/v1", model: "claude-sonnet-4-5", image_model: "" },
	custom: { label: "自訂（OpenAI 相容）", base_url: "", model: "", image_model: "" },
};

export interface AiProvider {
	readonly kind: ProviderKind;
	chat(messages: ChatMsg[], opts?: { maxTokens?: number }): Promise<string>;
	generateImage(prompt: string): Promise<{ bytes: Uint8Array; mime: string }>;
	detect(): Promise<AiCapabilities>;
}

export class AiError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

export function validateBaseUrl(u: string): URL {
	let url: URL;
	try {
		url = new URL(u);
	} catch {
		throw new AiError("bad_base_url", "base URL 格式錯誤");
	}
	const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";
	if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new AiError("insecure_base_url", "只允許 https（http 僅限本機 127.0.0.1）");
	if (url.username || url.password) throw new AiError("bad_base_url", "base URL 不可包含帳密");
	return url;
}

type FetchLike = typeof fetch;

export class OpenAICompatProvider implements AiProvider {
	readonly kind: ProviderKind;
	#cfg: AiConfig;
	#key: () => string | undefined;
	#fetch: FetchLike;
	#timeoutMs: number;

	constructor(cfg: AiConfig, getKey: () => string | undefined, opts: { fetch?: FetchLike; timeoutMs?: number } = {}) {
		validateBaseUrl(cfg.base_url);
		this.kind = cfg.provider;
		this.#cfg = cfg;
		this.#key = getKey;
		this.#fetch = opts.fetch ?? fetch;
		this.#timeoutMs = opts.timeoutMs ?? 45_000;
	}

	#headers(): Record<string, string> {
		const key = this.#key();
		if (!key) throw new AiError("no_api_key", "尚未設定 API key");
		const h: Record<string, string> = { authorization: `Bearer ${key}`, "content-type": "application/json" };
		if (this.kind === "anthropic") {
			h["x-api-key"] = key;
			h["anthropic-version"] = "2023-06-01";
		}
		return h;
	}

	async #call(method: "GET" | "POST", path: string, body?: unknown, maxBytes = 2 * 1024 * 1024): Promise<Record<string, unknown>> {
		const url = this.#cfg.base_url.replace(/\/+$/, "") + path;
		let res: Response;
		try {
			res = await this.#fetch(url, {
				method,
				headers: this.#headers(),
				body: body === undefined ? undefined : JSON.stringify(body),
				signal: AbortSignal.timeout(this.#timeoutMs),
				redirect: "error",
			});
		} catch (e) {
			if (e instanceof AiError) throw e;
			throw new AiError("network", `連線失敗：${this.#clean((e as Error).message)}`);
		}
		const text = await readLimited(res, maxBytes);
		if (!res.ok) {
			const code = res.status === 401 || res.status === 403 ? "auth" : res.status === 429 ? "rate_limited" : res.status === 404 ? "not_found" : "http_error";
			let msg = text.slice(0, 300);
			try {
				const j = JSON.parse(text) as { error?: { message?: string } | string };
				msg = typeof j.error === "string" ? j.error : (j.error?.message ?? msg);
			} catch {
				/* 非 JSON */
			}
			throw new AiError(code, `HTTP ${res.status}: ${this.#clean(msg)}`);
		}
		try {
			return JSON.parse(text) as Record<string, unknown>;
		} catch {
			throw new AiError("bad_response", "回應不是 JSON");
		}
	}

	#clean(s: string): string {
		const key = this.#key();
		return redact(key ? s.split(key).join("[redacted]") : s, 300);
	}

	async chat(messages: ChatMsg[], opts: { maxTokens?: number } = {}): Promise<string> {
		if (!this.#cfg.model) throw new AiError("no_model", "尚未設定模型");
		const j = await this.#call("POST", "/chat/completions", { model: this.#cfg.model, messages, max_tokens: opts.maxTokens ?? 300, temperature: 0.6 });
		const choices = j.choices as { message?: { content?: unknown } }[] | undefined;
		const c = choices?.[0]?.message?.content;
		const text = typeof c === "string" ? c : Array.isArray(c) ? c.map((p: { text?: string }) => p.text ?? "").join("") : "";
		if (!text) throw new AiError("bad_response", "模型沒有回傳文字");
		return text;
	}

	async generateImage(prompt: string): Promise<{ bytes: Uint8Array; mime: string }> {
		if (!this.#cfg.image_model) throw new AiError("no_image_model", "此供應商未設定圖片模型");
		const body: Record<string, unknown> = { model: this.#cfg.image_model, prompt, n: 1 };
		if (!/gpt-image/.test(this.#cfg.image_model)) body.response_format = "b64_json";
		const j = await this.#call("POST", "/images/generations", body, 30 * 1024 * 1024);
		const d = (j.data as { b64_json?: string; url?: string }[] | undefined)?.[0];
		if (d?.b64_json) return { bytes: new Uint8Array(Buffer.from(d.b64_json, "base64")), mime: sniffMime(Buffer.from(d.b64_json.slice(0, 32), "base64")) };
		if (d?.url) {
			const u = new URL(d.url);
			if (u.protocol !== "https:") throw new AiError("bad_response", "圖片網址不是 https");
			const r = await this.#fetch(u, { signal: AbortSignal.timeout(this.#timeoutMs), redirect: "follow" });
			if (!r.ok) throw new AiError("http_error", `下載圖片失敗 HTTP ${r.status}`);
			const buf = new Uint8Array(await r.arrayBuffer());
			if (buf.byteLength > 20 * 1024 * 1024) throw new AiError("too_large", "圖片太大");
			return { bytes: buf, mime: sniffMime(buf) };
		}
		throw new AiError("bad_response", "沒有圖片資料");
	}

	async detect(): Promise<AiCapabilities> {
		const now = Date.now();
		try {
			const j = await this.#call("GET", "/models");
			const models = ((j.data as { id?: string }[] | undefined) ?? []).map((m) => String(m.id ?? "")).filter(Boolean).slice(0, 300);
			return { ...capabilitiesFromModels(this.kind, models, this.#cfg), models, checked_at: now, heuristic: true };
		} catch (e) {
			return { text: false, vision: false, image_gen: false, voice: false, models: [], checked_at: now, error: (e as Error).message, heuristic: true };
		}
	}
}

export function capabilitiesFromModels(kind: ProviderKind, models: string[], cfg?: Pick<AiConfig, "model" | "image_model">): Pick<AiCapabilities, "text" | "vision" | "image_gen" | "voice"> {
	const any = (re: RegExp) => models.some((m) => re.test(m));
	const text = models.length > 0;
	const image_gen = kind !== "anthropic" && (any(/gpt-image|dall-e|image|imagine|flux|sdxl|stable-diffusion/i) || (!!cfg?.image_model && models.includes(cfg.image_model)));
	const vision = kind === "anthropic" ? text : any(/gpt-4o|gpt-4\.1|gpt-5|o3|o4|vision|grok-(2-vision|4|vision)|llava|claude|gemini|qwen.*vl/i);
	const voice = any(/tts|whisper|transcribe|audio|realtime|voice/i);
	return { text, vision, image_gen, voice };
}

async function readLimited(res: Response, max: number): Promise<string> {
	const len = Number(res.headers.get("content-length") ?? 0);
	if (len > max) throw new AiError("too_large", "回應太大");
	if (!res.body) return "";
	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > max) {
			await reader.cancel();
			throw new AiError("too_large", "回應太大");
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks).toString("utf8");
}

export function sniffMime(b: Uint8Array): string {
	if (b[0] === 0x89 && b[1] === 0x50) return "image/png";
	if (b[0] === 0xff && b[1] === 0xd8) return "image/jpeg";
	if (b[0] === 0x52 && b[1] === 0x49 && b[8] === 0x57) return "image/webp";
	return "application/octet-stream";
}
