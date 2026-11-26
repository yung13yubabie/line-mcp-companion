import { Agent as HttpAgent, request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { pinnedLookup } from "./public-address.ts";

export class DownloadError extends Error {
	readonly code: string;
	constructor(code: string, message: string) { super(message); this.code = code; }
}

/** Injection seam for hermetic tests. Production callers leave it unset. */
export type RequestTransport = (url: URL, options: RequestOptions & { autoSelectFamily?: boolean; rejectUnauthorized?: boolean }, onResponse: (response: IncomingMessage) => void) => ClientRequest;

export interface BoundedResponse {
	status: number;
	headers: IncomingMessage["headers"];
	body: Buffer;
	truncated: boolean;
}

/** A total deadline, including DNS and every redirect, not a socket-idle timeout. */
export async function withDeadline<T>(milliseconds: number, action: (signal: AbortSignal) => Promise<T>): Promise<T> {
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout>;
	const expired = new Promise<never>((_resolve, reject) => {
		timer = setTimeout(() => {
			const error = new DownloadError("timeout", "timeout");
			controller.abort(error);
			reject(error);
		}, milliseconds);
	});
	try { return await Promise.race([action(controller.signal), expired]); }
	finally { clearTimeout(timer!); }
}

/**
 * One direct request to an address already checked by the caller. The original
 * URL remains intact for HTTP Host and normal TLS certificate/SNI verification.
 * No proxy environment, shared connection pool, cookies, auth, or redirecting API.
 */
export function requestPinned(url: URL, ip: string, options: {
	signal: AbortSignal;
	method: "GET" | "HEAD";
	maxBytes: number;
	truncate?: boolean;
	accept: string;
	userAgent?: string;
	validateHeaders?: (response: IncomingMessage) => void;
	request?: RequestTransport;
}): Promise<BoundedResponse> {
	options.signal.throwIfAborted();
	if (url.protocol !== "http:" && url.protocol !== "https:") throw new DownloadError("bad_url", "scheme_not_allowed");
	const agentOptions = { keepAlive: false, proxyEnv: {} };
	const agent = url.protocol === "https:" ? new HttpsAgent(agentOptions) : new HttpAgent(agentOptions);
	const transport = options.request ?? (url.protocol === "https:" ? httpsRequest : httpRequest);
	return new Promise((resolve, reject) => {
		let settled = false;
		let request: ClientRequest | undefined;
		let response: IncomingMessage | undefined;
		const finish = (error?: Error, value?: BoundedResponse) => {
			if (settled) return;
			settled = true;
			options.signal.removeEventListener("abort", onAbort);
			if (error) reject(error); else resolve(value!);
			response?.destroy();
			request?.destroy();
			agent.destroy();
		};
		const onAbort = () => finish(new DownloadError("timeout", "timeout"));
		options.signal.addEventListener("abort", onAbort, { once: true });
		try {
			request = transport(url, {
				method: options.method,
				lookup: pinnedLookup(ip),
				family: isIP(ip),
				autoSelectFamily: false,
				agent,
				signal: options.signal,
				maxHeaderSize: 16 * 1024,
				...(url.protocol === "https:" ? { rejectUnauthorized: true } : {}),
				headers: {
					"user-agent": options.userAgent ?? "LineMcpCompanion/0.3",
					accept: options.accept,
					"accept-encoding": "identity",
				},
			}, (res) => {
				response = res;
				res.on("error", () => finish(new DownloadError("network", "response_error")));
				res.on("aborted", () => finish(new DownloadError("network", "response_aborted")));
				res.on("close", () => { if (!settled) finish(new DownloadError("network", "response_incomplete")); });
				if (settled || options.signal.aborted) { res.destroy(); return; }
				try { options.validateHeaders?.(res); }
				catch (error) { finish(error as Error); return; }
				const chunks: Buffer[] = [];
				let total = 0;
				const result = (truncated: boolean): BoundedResponse => ({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks, total), truncated });
				res.on("data", (chunk: Buffer) => {
					if (settled) return;
					const remaining = options.maxBytes - total;
					if (chunk.length > remaining) {
						if (!options.truncate) { finish(new DownloadError("too_large", "回應太大")); return; }
						// Copy only the retained prefix; a view would keep a huge chunk alive.
						if (remaining > 0) chunks.push(Buffer.from(chunk.subarray(0, remaining)));
						total += Math.max(remaining, 0);
						finish(undefined, result(true));
						return;
					}
					chunks.push(Buffer.from(chunk));
					total += chunk.length;
				});
				res.on("end", () => {
					if (!res.complete) { finish(new DownloadError("network", "response_incomplete")); return; }
					finish(undefined, result(false));
				});
			});
			request.on("error", () => finish(new DownloadError("network", "request_failed")));
			if (settled) request.destroy();
			else request.end();
		} catch (error) { finish(error as Error); }
	});
}
