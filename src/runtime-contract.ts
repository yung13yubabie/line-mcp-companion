import type { resolveDataKey } from "./storage/data-key.ts";
import type { Store } from "./storage/db.ts";
import type { Whitelist } from "./whitelist.ts";
import type { ToolContext } from "./mcp/tools.ts";
import type { LoginState } from "./control/server.ts";
import type { Outbox } from "./ai/outbox.ts";
import type { AiService, AiServiceOptions } from "./ai/service.ts";
import type { AiPolicy } from "./ai/policy.ts";
import type { ScamDetector } from "./scam/detector.ts";
import type { ScamWarner } from "./scam/warner.ts";
import type { DigestStore } from "./storage/digests.ts";
import type { LinkReader } from "./links/reader.ts";
import type { DigestPoster } from "./ai/digest-post.ts";
import type { SyncEngine } from "./sync/engine.ts";
export interface RuntimeContext {
 store: Store; home: string; whitelist: Whitelist; ctx: ToolContext; outbox: Outbox; ai: AiService;
 policy: AiPolicy; scam: ScamDetector; warner: ScamWarner; digests: DigestStore; links: LinkReader; poster: DigestPoster;
 attachSync: (sync: SyncEngine) => void; pollLoop: () => Promise<void>; setLoginState: (state: LoginState) => void;
}
export interface RuntimeMode {
 isolated: boolean;
 dataDirectory: (home: string) => string;
 dataKeyResolver?: typeof resolveDataKey;
 aiOptions: Pick<AiServiceOptions, "providerExtensions">;
 initialize?: (context: RuntimeContext) => Promise<void>;
 stickerImage?: (id: string) => { bytes: Uint8Array; mime: string };
}
