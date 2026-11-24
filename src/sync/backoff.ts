/** 指數退避（含 jitter）：attempt 0 → ~1s，之後倍增，上限 5 分鐘。 */
export function backoffMs(attempt: number, opts: { baseMs?: number; maxMs?: number; rand?: () => number } = {}): number {
	const base = opts.baseMs ?? 1_000;
	const max = opts.maxMs ?? 300_000;
	const r = opts.rand ?? Math.random;
	const exp = Math.min(max, base * 2 ** Math.min(attempt, 20));
	return Math.round(exp * (0.5 + r() * 0.5));
}

/** token 失效 / 被登出（需要重新 QR 登入）的錯誤，不要一直重試 */
export function isAuthError(e: unknown): boolean {
	const s = `${(e as { code?: unknown })?.code ?? ""} ${(e as Error)?.message ?? String(e)}`;
	return /AUTHENTICATION_FAILED|NOT_AUTHORIZED|V3_TOKEN_CLIENT_LOGGED_OUT|MUST_REFRESH_V3_TOKEN|INVALID_AUTH|LOGGED_OUT|\b401\b/i.test(s);
}
