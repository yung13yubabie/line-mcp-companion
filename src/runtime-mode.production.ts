import type { RuntimeMode } from "./runtime-contract.ts";
/** Production policy deliberately never reads environment or QA preferences. */
export function createRuntimeMode(_env: NodeJS.ProcessEnv): RuntimeMode {
 return { isolated: false, dataDirectory: home => home, aiOptions: {} };
}
