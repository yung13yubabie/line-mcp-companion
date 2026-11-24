/**
 * 可插拔的「風格模組」介面。
 *   - reply-filter：在 AI 產生回覆之後、排入佇列之前執行（例如去 AI 味）。每會話可開關。
 *   - composer：獨立的寫作模式（例如社群貼文草稿）。只產生草稿，絕不自動發布。
 * 新模組：實作其中一種介面，在 registry.ts 註冊，並在 THIRD_PARTY_NOTICES.md 補上授權與出處。
 */
import type { ChatMsg } from "../ai/prompt.ts";

export interface StyleModuleInfo {
	id: string;
	name: string;
	kind: "reply-filter" | "composer";
	/** SPDX 或授權名稱 */
	license: string;
	/** 原始專案網址 */
	source: string;
	/** 改作說明（授權要求標示修改） */
	changes: string;
}

export interface StyleFinding {
	rule: string;
	level: "A" | "B" | "H" | "F";
	match: string;
	index: number;
	advice: string;
}

export type Llm = (messages: ChatMsg[]) => Promise<string>;

export interface FilterResult {
	text: string;
	before: StyleFinding[];
	after: StyleFinding[];
	changed: boolean;
	method: "none" | "mechanical" | "llm" | "llm_rejected";
}

export interface ReplyFilterModule extends StyleModuleInfo {
	kind: "reply-filter";
	detect(text: string): StyleFinding[];
	apply(text: string, ctx: { llm?: Llm }): Promise<FilterResult>;
}

export interface ComposerMode {
	id: string;
	label: string;
	description: string;
}

export interface ComposerModule<I = unknown> extends StyleModuleInfo {
	kind: "composer";
	modes: ComposerMode[];
	buildPrompt(input: I): ChatMsg[];
	postProcess(raw: string, input: I): { text: string; warnings: string[] };
}

export type StyleModule = ReplyFilterModule | ComposerModule<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
