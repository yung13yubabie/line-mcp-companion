/** In-memory Node HTTP transport; never opens a socket or performs DNS. */
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ClientRequest, IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { RequestTransport } from "../../src/net/bounded-request.ts";

export class FakeResponse extends PassThrough {
	statusCode = 200;
	headers: IncomingHttpHeaders = { "content-type": "image/png" };
	complete = true;
}
export interface RequestRecord {
	url: URL;
	options: Parameters<RequestTransport>[1];
	response: FakeResponse;
	destroyed: boolean;
}
export function fakeTransport(configure: (record: RequestRecord) => (() => void) | void): { request: RequestTransport; seen: RequestRecord[] } {
	const seen: RequestRecord[] = [];
	const request: RequestTransport = (url, options, callback) => {
		const response = new FakeResponse();
		const record: RequestRecord = { url: new URL(url), options, response, destroyed: false };
		seen.push(record);
		const emit = configure(record);
		const req = Object.assign(new EventEmitter(), {
			end() {
				queueMicrotask(() => {
					if (record.destroyed) return;
					callback(response as unknown as IncomingMessage);
					if (!response.destroyed) emit?.();
				});
				return req;
			},
			destroy() { record.destroyed = true; response.destroy(); return req; },
		});
		return req as unknown as ClientRequest;
	};
	return { request, seen };
}
