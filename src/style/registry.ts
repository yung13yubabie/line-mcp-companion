import type { StyleModule, StyleModuleInfo } from "./types.ts";
import { lieflat } from "./lieflat/index.ts";
import { socialPost } from "./social-post/index.ts";

/** 已安裝的風格模組。新增模組：在這裡加一行，並補 THIRD_PARTY_NOTICES.md。 */
export const STYLE_MODULES: StyleModule[] = [lieflat, socialPost];

export function moduleInfo(): (StyleModuleInfo & { modes?: { id: string; label: string; description: string }[] })[] {
	return STYLE_MODULES.map((m) => ({ id: m.id, name: m.name, kind: m.kind, license: m.license, source: m.source, changes: m.changes, ...(m.kind === "composer" ? { modes: m.modes } : {}) }));
}
