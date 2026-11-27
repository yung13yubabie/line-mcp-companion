import { join } from "node:path";
import type { RuntimeMode } from "./runtime-contract.ts";
import { resolveDebugDataKey } from "./mock/data-key.ts";
import { initialize } from "./mock/runtime.ts";
import { MockAiProvider, mockStickerPng } from "./mock/mock-ai.ts";
/** Desktop/debug policy only; release bundler replaces this entire module. */
export function createRuntimeMode(env: NodeJS.ProcessEnv): RuntimeMode {
 if (env.LINE_MCP_MOCK !== "1") return { isolated: false, dataDirectory: home => home, aiOptions: {} };
 return { isolated: true, dataDirectory: home => join(home, "mock"), dataKeyResolver: resolveDebugDataKey,
  aiOptions: { providerExtensions: { mock: {
   preset: { base_url: "mock://local", model: "mock-chat", image_model: "mock-image" },
   availableWithoutKey: true, validateEndpoint: () => {}, create: () => new MockAiProvider(),
  } } },
  initialize, stickerImage: id => ({ bytes: mockStickerPng(id), mime: "image/png" }) };
}
