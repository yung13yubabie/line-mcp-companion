import { BaseClient } from "@evex-dev/linejs/base";
import type { Store } from "../storage/db.ts";
import { SqliteKvStorage } from "../storage/kv-storage.ts";
import type { SecretBox } from "../storage/secret-box.ts";
import { installUpstreamGuards } from "../guard/upstream-guard.ts";

/**
 * 固定以次要裝置登入：主裝置（手機）保持登入。
 * refs/linejs/packages/linejs/base/core/utils/devices.ts:6,51-55 定義 ANDROIDSECONDARY；
 * devices.ts:18-22 isV3Support 含 ANDROIDSECONDARY → withQrCode 走 requestSQR2（V3 secure QR，base/login/mod.ts:196-310）。
 */
export const DEVICE = "ANDROIDSECONDARY" as const;
const AUTH_TOKEN_KEY = "authToken";

export interface QrHandlers {
	onQrUrl: (url: string) => void | Promise<void>;
	onPincode: (pin: string) => void | Promise<void>;
}

export class Session {
	readonly store: Store;
	readonly base: BaseClient;
	readonly kv: SqliteKvStorage;

	constructor(store: Store, box: SecretBox, opts: { endpoint?: string } = {}) {
		this.store = store;
		const storage = new SqliteKvStorage(store, box);
		this.kv = storage;
		this.base = new BaseClient({ device: DEVICE, storage, endpoint: opts.endpoint });
		installUpstreamGuards(this.base as never, {
			isReadReceiptEnabled: () => store.getSetting("read_receipts") === "on",
			isKeyRegistrationEnabled: () => store.getSetting("allow_key_registration") === "on",
			log: (e) => {
				if (e.event === "blocked") console.error(JSON.stringify({ t: new Date().toISOString(), ...e }));
			},
		});
		// LINEJS 不會自己保存 authToken（docs/docs/auth.md「Persisting authToken」），必須監聽 update:authtoken。
		this.base.on("update:authtoken", (token: string) => {
			this.base.authToken = token;
			storage.setSync(AUTH_TOKEN_KEY, token); // 加密後寫入
		});
	}

	savedToken(): string | undefined {
		return this.kv.getSync(AUTH_TOKEN_KEY) as string | undefined;
	}

	/** QR + PIN 登入（第一次）。 */
	async loginWithQr(h: QrHandlers): Promise<void> {
		this.base.on("qrcall", h.onQrUrl);
		this.base.on("pincall", h.onPincode);
		await this.base.loginProcess.login({ qr: true });
	}

	/** 用已保存或外部提供的 token 登入（之後每次啟動）。 */
	async loginWithToken(token?: string): Promise<void> {
		const t = token ?? this.savedToken();
		if (!t) throw new Error("no saved auth token; run QR login first");
		await this.base.loginProcess.login({ authToken: t });
	}

	get profile() {
		return this.base.profile;
	}
}
