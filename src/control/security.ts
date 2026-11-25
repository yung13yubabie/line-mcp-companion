/** Bounded, content-free authentication telemetry shared by the local HTTP services. */
export type AuthFailureReason = "unauthorized" | "forbidden" | "replay" | "expired" | "invalid_request";

const emptyCounts = (): Record<AuthFailureReason, number> => ({ unauthorized: 0, forbidden: 0, replay: 0, expired: 0, invalid_request: 0 });
export interface AuthFailureSummary {
	counts: Record<AuthFailureReason, number>;
	rate_limited: number;
	report_failures: number;
}

/**
 * Invalid requests have their own budget: they cannot consume the authenticated client's budget.
 * Counters use a fixed set of reasons, never attacker-controlled tokens, nonces, paths or client names.
 * The first failure is reported promptly; subsequent events are aggregated for periodic flush().
 */
export class AuthFailureBudget {
	#capacity: number;
	#tokens: number;
	#last: number;
	#now: () => number;
	#report: (summary: AuthFailureSummary) => void;
	#first = true;
	#counts = emptyCounts();
	#pending = emptyCounts();
	#limited = 0;
	#pendingLimited = 0;
	#reportFailures = 0;
	constructor(opts: { perMinute?: number; now?: () => number; report?: (summary: AuthFailureSummary) => void } = {}) {
		this.#capacity = Math.max(1, Math.min(600, Math.floor(opts.perMinute ?? 30)));
		this.#tokens = this.#capacity;
		this.#now = opts.now ?? Date.now;
		this.#last = this.#now();
		this.#report = opts.report ?? (() => {});
	}
	reject(reason: AuthFailureReason): boolean {
		const now = this.#now();
		this.#tokens = Math.min(this.#capacity, this.#tokens + Math.max(0, now - this.#last) * this.#capacity / 60_000);
		this.#last = now;
		const withinBudget = this.#tokens >= 1;
		if (withinBudget) this.#tokens--;
		this.#counts[reason] = Math.min(Number.MAX_SAFE_INTEGER, this.#counts[reason] + 1);
		this.#pending[reason] = Math.min(Number.MAX_SAFE_INTEGER, this.#pending[reason] + 1);
		if (!withinBudget) {
			this.#limited = Math.min(Number.MAX_SAFE_INTEGER, this.#limited + 1);
			this.#pendingLimited = Math.min(Number.MAX_SAFE_INTEGER, this.#pendingLimited + 1);
		}
		if (this.#first) { this.#first = false; this.flush(); }
		return withinBudget;
	}
	flush(): void {
		if (!Object.values(this.#pending).some(Boolean)) return;
		const report = { counts: { ...this.#pending }, rate_limited: this.#pendingLimited, report_failures: this.#reportFailures };
		try {
			this.#report(report);
		} catch {
			// Optional telemetry must not crash a request handler or timer when storage is unavailable.
			// Keep the bounded pending counters for the next periodic attempt and expose the failure count.
			this.#reportFailures = Math.min(Number.MAX_SAFE_INTEGER, this.#reportFailures + 1);
			return;
		}
		this.#pending = emptyCounts();
		this.#pendingLimited = 0;
	}
	snapshot(): AuthFailureSummary {
		return { counts: { ...this.#counts }, rate_limited: this.#limited, report_failures: this.#reportFailures };
	}
}

export const CONTROL_AUTH_SKEW_MS = 120_000;

/** Keep a nonce until its signed timestamp can no longer be accepted, including future clock skew. */
export class ControlReplayWindow {
	#expires = new Map<string, number>();
	#now: () => number;
	#maxEntries: number;
	constructor(opts: { now?: () => number; maxEntries?: number } = {}) {
		this.#now = opts.now ?? Date.now;
		this.#maxEntries = Math.max(1, Math.min(8192, opts.maxEntries ?? 8192));
	}
	validTimestamp(timestamp: number): boolean {
		return Number.isSafeInteger(timestamp) && Math.abs(this.#now() - timestamp) <= CONTROL_AUTH_SKEW_MS;
	}
	consume(nonce: string, timestamp: number): boolean {
		const now = this.#now();
		if (!this.validTimestamp(timestamp)) return false;
		for (const [key, expires] of this.#expires) if (expires < now) this.#expires.delete(key);
		if (this.#expires.has(nonce) || this.#expires.size >= this.#maxEntries) return false;
		this.#expires.set(nonce, timestamp + CONTROL_AUTH_SKEW_MS);
		return true;
	}
}
