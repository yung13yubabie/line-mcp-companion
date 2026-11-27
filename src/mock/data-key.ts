/** Debug-only ephemeral data key for a separate synthetic database. */
import { randomBytes } from "node:crypto";
import type { Store } from "../storage/db.ts";
import { SecretBox } from "../storage/secret-box.ts";
import { openSecretStore } from "../storage/kv-storage.ts";
import { resolveDataKey, type DataKeyResolution } from "../storage/data-key.ts";
export function resolveDebugDataKey(store: Store, env: NodeJS.ProcessEnv): DataKeyResolution {
 if (env.LMA_DATA_KEY || env.LMA_PASSPHRASE) return resolveDataKey(store, env);
 store.setSetting("data_key_check", "");
 store.db.exec("DELETE FROM line_kv");
 const box = new SecretBox(randomBytes(32));
 return { box, migrated: openSecretStore(store, box), source: "ephemeral" };
}
