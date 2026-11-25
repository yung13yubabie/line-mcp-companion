import { test } from "node:test";
import assert from "node:assert/strict";
import { crc32, deflateSync } from "node:zlib";
import { Agent } from "node:https";
import { isPublicIp } from "../src/net/public-address.ts";
import { downloadImage } from "../src/ai/image-download.ts";
import { MAX_IMAGE_BYTES, decodeImageBase64, validateRasterImage } from "../src/media/image-validation.ts";
import { DownloadError, requestPinned, withDeadline } from "../src/net/bounded-request.ts";
import { AiError, OpenAICompatProvider } from "../src/ai/provider.ts";
import { LinkReader } from "../src/links/reader.ts";
import { fakeTransport } from "./helpers/http-transport.ts";

const PUBLIC = "93.184.215.14";
const URL_IMAGE = "https://images.example/result.png?sig=synthetic";
function chunk(type: string, body: Buffer): Buffer {
	const header = Buffer.alloc(8);
	header.writeUInt32BE(body.length); header.write(type, 4);
	const checksum = Buffer.alloc(4); checksum.writeUInt32BE(crc32(Buffer.concat([header.subarray(4), body])));
	return Buffer.concat([header, body, checksum]);
}
function png(width = 1, height = 1): Buffer {
	const header = Buffer.alloc(13);
	header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 6;
	return Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", header), chunk("IDAT", deflateSync(Buffer.from([0, 23, 45, 67, 255]))), chunk("IEND", Buffer.alloc(0))]);
}
const PNG = png();
// Synthetic 2x2 solid-color fixtures generated locally with Pillow, no user data.
const JPEG = Buffer.from("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAACAAIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDyiiiiu04z/9k=", "base64");
const WEBP = Buffer.from("UklGRjAAAABXRUJQVlA4ICQAAABQAQCdASoCAAIAAUAmJQBOgC6gAP76IZfF3YjjJ4dVU9ffoAA=", "base64");
const JPEG_PROGRESSIVE = Buffer.from("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wgARCAACAAIDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAGTDD//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAEFAn//xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAEDAQE/AX//xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAECAQE/AX//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAY/An//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/IX//2gAMAwEAAgADAAAAEPv/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAEDAQE/EH//xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAECAQE/EH//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/EH//2Q==", "base64");
const WEBP_LOSSLESS = Buffer.from("UklGRh4AAABXRUJQVlA4TBEAAAAvAUAAAAfQll50qP+BiOh/AAA=", "base64");
const WEBP_ALPHA = Buffer.from("UklGRlAAAABXRUJQVlA4WAoAAAAQAAAAAQAAAQAAQUxQSAUAAAAAZGRkZABWUDggJAAAAFABAJ0BKgIAAgABQCYlAE6ALqAA/vohl8XdiOMnh1VT19+gAA==", "base64");
const resolvePublic = async () => [PUBLIC];
const hasCode = (code: string) => (error: unknown) => error instanceof DownloadError && error.code === code;

test("F13 egress policy rejects private/reserved/mapped/compatible/translation IPv4 and IPv6", () => {
	for (const address of [
		"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.31.255.255", "192.168.0.1",
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "::7f00:1", "::127.0.0.1", "::ffff:7f00:1", "::ffff:8.8.8.8", "0:0:0:0:0:ffff:7f00:1",
		"64:ff9b::7f00:1", "64:ff9b:1::a00:1", "100::1", "2001::7f00:1", "2001:2::1", "2001:db8::1",
		"2002:7f00:1::", "3fff::1", "4000::1", "5f00::1", "fc00::1", "fe80::1", "fe80::1%lo", "ff02::1", "bad-address",
	]) assert.equal(isPublicIp(address), false, address);
	for (const address of [PUBLIC, "8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"]) assert.equal(isPublicIp(address), true, address);
});

test("F13 rejects URL tricks and all private destinations before opening a socket", async () => {
	const transport = fakeTransport(() => { throw new Error("must not connect"); });
	for (const url of [
		"http://images.example/a.png", "file:///tmp/picture.png", "https://user:pass@images.example/a.png", "https://images.example:8443/a.png", "https://localhost/a.png",
		"https://127.0.0.1/a.png", "https://2130706433/a.png", "https://0x7f000001/a.png", "https://0177.0.0.1/a.png",
		"https://169.254.169.254/a.png", "https://[::1]/a.png", "https://[::7f00:1]/a.png", "https://[::ffff:7f00:1]/a.png", "https://[2002:7f00:1::]/a.png",
	]) await assert.rejects(downloadImage(url, { resolve: resolvePublic, request: transport.request }), (e: unknown) => e instanceof DownloadError);
	for (const addresses of [["127.0.0.1"], [PUBLIC, "10.0.0.7"], ["2606:4700:4700::1111", "fc00::1"], []]) {
		await assert.rejects(downloadImage(URL_IMAGE, { resolve: async () => addresses, request: transport.request }), hasCode("image_address_blocked"));
	}
	assert.equal(transport.seen.length, 0);
});

test("F13 resolves once, pins both lookup forms, retains HTTPS hostname, and sends no credentials", async () => {
	let dnsCalls = 0;
	const transport = fakeTransport(({ response }) => {
		response.headers["content-length"] = String(PNG.length);
		return () => response.end(PNG);
	});
	const result = await downloadImage(URL_IMAGE, { resolve: async () => (++dnsCalls === 1 ? [PUBLIC] : ["127.0.0.1"]), request: transport.request });
	assert.equal(result.mime, "image/png"); assert.deepEqual(result.bytes, PNG);
	assert.equal(dnsCalls, 1); assert.equal(transport.seen.length, 1);
	const { options, url } = transport.seen[0]!;
	assert.equal(url.hostname, "images.example"); assert.equal(url.search, "?sig=synthetic");
	assert.equal(options.rejectUnauthorized, true); assert.equal(options.autoSelectFamily, false);
	assert.ok(options.agent instanceof Agent); assert.deepEqual(options.agent.options.proxyEnv, {});
	assert.deepEqual(Object.keys(options.headers!).sort(), ["accept", "accept-encoding", "user-agent"]);
	assert.equal((options as Record<string, unknown>).checkServerIdentity, undefined);
	const lookup = options.lookup!;
	for (let i = 0; i < 2; i++) {
		lookup("images.example", {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, PUBLIC); assert.equal(family, 4); });
		(lookup as unknown as (h: string, o: object, cb: (e: unknown, addresses: unknown) => void) => void)("images.example", { all: true }, (error, addresses) => {
			assert.equal(error, null); assert.deepEqual(addresses, [{ address: PUBLIC, family: 4 }]);
		});
	}
	assert.equal(dnsCalls, 1, "socket lookups must not resolve again");
});

test("F13 rejects redirects without fetching Location", async () => {
	for (const status of [301, 302, 303, 307, 308]) {
		const transport = fakeTransport(({ response }) => { response.statusCode = status; response.headers.location = "https://127.0.0.1/internal"; return () => response.end(); });
		await assert.rejects(downloadImage(URL_IMAGE, { resolve: resolvePublic, request: transport.request }), hasCode("http_error"));
		assert.equal(transport.seen.length, 1); assert.equal(transport.seen[0]!.destroyed, true);
	}
});

test("F13 bounds declared and streamed bytes and rejects wrong MIME/encoding/length", async () => {
	for (const [headers, body, code] of [
		[{ "content-type": "image/png", "content-length": String(MAX_IMAGE_BYTES + 1) }, PNG, "too_large"],
		[{ "content-type": "image/png" }, Buffer.alloc(MAX_IMAGE_BYTES + 1), "too_large"],
		[{ "content-type": "text/html" }, PNG, "bad_image"],
		[{ "content-type": "image/svg+xml" }, Buffer.from("<svg/>"), "bad_image"],
		[{ "content-type": "image/jpeg" }, PNG, "bad_image"],
		[{ "content-type": "image/png", "content-encoding": "gzip" }, PNG, "bad_image"],
		[{ "content-type": "image/png", "content-length": String(PNG.length + 1) }, PNG, "bad_image"],
		[{ "content-type": "image/png", "content-length": "-1" }, PNG, "bad_image"],
	] as const) {
		const transport = fakeTransport(({ response }) => { response.headers = headers; return () => response.end(body); });
		await assert.rejects(downloadImage(URL_IMAGE, { resolve: resolvePublic, request: transport.request }), hasCode(code));
		assert.equal(transport.seen[0]!.destroyed, true);
	}
});

test("F13 total deadline expires during DNS and never starts a late request", async () => {
	let resolved!: (addresses: string[]) => void;
	const transport = fakeTransport(() => { throw new Error("must not connect"); });
	await assert.rejects(downloadImage(URL_IMAGE, { timeoutMs: 20, resolve: () => new Promise((r) => { resolved = r; }), request: transport.request }), hasCode("timeout"));
	resolved([PUBLIC]); await new Promise<void>((r) => setImmediate(r));
	assert.equal(transport.seen.length, 0);
});

test("F13 total deadline terminates a continually active image stream", async () => {
	let writes = 0;
	const transport = fakeTransport(({ response }) => () => {
		response.write(PNG.subarray(0, 1)); writes++;
		const interval = setInterval(() => { response.write(Buffer.from([0])); writes++; }, 5);
		response.once("close", () => clearInterval(interval));
	});
	await assert.rejects(downloadImage(URL_IMAGE, { timeoutMs: 50, resolve: resolvePublic, request: transport.request }), hasCode("timeout"));
	assert.ok(writes > 1); assert.equal(transport.seen[0]!.destroyed, true);
});

test("F13 validates complete PNG/JPEG/WebP and rejects magic-only, truncated, mismatched, large-dimension and corrupt PNG", () => {
	for (const [bytes, mime] of [[PNG, "image/png"], [JPEG, "image/jpeg"], [JPEG_PROGRESSIVE, "image/jpeg"], [WEBP, "image/webp"], [WEBP_LOSSLESS, "image/webp"], [WEBP_ALPHA, "image/webp"]] as const) {
		assert.equal(validateRasterImage(bytes, mime), mime);
		assert.deepEqual(decodeImageBase64(bytes.toString("base64")), { bytes, mime });
		assert.throws(() => validateRasterImage(bytes.subarray(0, bytes.length - 1)), hasCode("bad_image"));
		assert.throws(() => validateRasterImage(Buffer.concat([bytes, Buffer.from("trailing") ])), hasCode("bad_image"));
	}
	const corrupt = Buffer.from(PNG); corrupt[29] ^= 1;
	for (const bytes of [Buffer.alloc(0), PNG.subarray(0, 8), Buffer.from([0xff, 0xd8]), Buffer.from("<html/>"), corrupt, png(9000, 1), png(8000, 8000)]) {
		assert.throws(() => validateRasterImage(bytes), hasCode("bad_image"));
	}
	for (const value of [false, [], "@@@=", `${PNG.toString("base64")}\n`, "YQ=", "Y==="]) assert.throws(() => decodeImageBase64(value), hasCode("bad_image"));
	assert.throws(() => decodeImageBase64("A".repeat(4 * Math.ceil(MAX_IMAGE_BYTES / 3) + 4)), hasCode("too_large"));
});

test("F13 provider integration separates API auth from pinned image transport and validates base64", async () => {
	const apiCalls: RequestInit[] = [];
	let payload: unknown = { data: [{ url: URL_IMAGE, b64_json: null }] };
	const fakeFetch = (async (_url: unknown, options: RequestInit) => { apiCalls.push(options); return new Response(JSON.stringify(payload)); }) as typeof fetch;
	const transport = fakeTransport(({ response }) => () => response.end(PNG));
	const provider = new OpenAICompatProvider({ provider: "custom", base_url: "https://api.example/v1", model: "m", image_model: "img" }, () => "synthetic-api-key", {
		fetch: fakeFetch, imageDownload: { resolve: resolvePublic, request: transport.request },
	});
	assert.equal((await provider.generateImage("a test square")).mime, "image/png");
	assert.equal((apiCalls[0]!.headers as Record<string, string>).authorization, "Bearer synthetic-api-key");
	assert.equal((transport.seen[0]!.options.headers as Record<string, string>).authorization, undefined);
	payload = { data: [{ b64_json: WEBP.toString("base64") }] };
	assert.equal((await provider.generateImage("a test square")).mime, "image/webp"); assert.equal(transport.seen.length, 1);
	payload = { data: [{ b64_json: "iVBORw==" }] };
	await assert.rejects(provider.generateImage("test"), (error: unknown) => error instanceof AiError && error.code === "bad_image");
	payload = { data: [{ url: "https://127.0.0.1/internal" }] };
	await assert.rejects(provider.generateImage("test"), (error: unknown) => error instanceof AiError && error.code === "image_address_blocked");
	assert.equal(transport.seen.length, 1);
});

test("G07 reader copies only bounded bytes, marks even one oversized chunk, and stops immediately", async () => {
	const transport = fakeTransport(({ response }) => { response.headers["content-type"] = "text/plain"; return () => response.end(Buffer.from("hello".repeat(1000))); });
	const response = await withDeadline(1000, (signal) => requestPinned(new URL("https://news.example/"), PUBLIC, { signal, method: "GET", maxBytes: 17, truncate: true, accept: "text/plain", request: transport.request }));
	assert.equal(response.body.length, 17); assert.equal(response.body.toString(), "hellohellohellohe");
	assert.equal(response.truncated, true); assert.equal(transport.seen[0]!.destroyed, true);
});

test("G07 reader total deadline covers DNS and continually active streams", async () => {
	let resolved!: (addresses: string[]) => void;
	const never = fakeTransport(() => { throw new Error("late request"); });
	const dnsReader = new LinkReader({ timeoutMs: 20, resolve: () => new Promise((r) => { resolved = r; }), request: never.request });
	assert.equal((await dnsReader.read("https://news.example/article")).blocked, "fetch_failed:timeout");
	resolved([PUBLIC]); await new Promise<void>((r) => setImmediate(r)); assert.equal(never.seen.length, 0);
	let writes = 0;
	const slow = fakeTransport(({ response }) => {
		response.headers["content-type"] = "text/plain";
		return () => { response.write("start"); writes++; const interval = setInterval(() => { response.write("."); writes++; }, 5); response.once("close", () => clearInterval(interval)); };
	});
	const reader = new LinkReader({ timeoutMs: 50, resolve: resolvePublic, request: slow.request });
	assert.equal((await reader.read("https://news.example/article")).blocked, "fetch_failed:timeout");
	assert.ok(writes > 1); assert.equal(slow.seen[0]!.destroyed, true);
});

test("G07 reader rejects DNS private IPv6 transitions and preserves authorized public text reading", async () => {
	const transport = fakeTransport(({ response }) => { response.headers["content-type"] = "text/plain"; return () => response.end("public article"); });
	for (const ip of ["::7f00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2001::1", "3fff::1"]) {
		const reader = new LinkReader({ resolve: async () => [ip], request: transport.request });
		assert.equal((await reader.read("https://news.example/")).blocked, "private_address");
	}
	assert.equal(transport.seen.length, 0);
	const reader = new LinkReader({ resolve: resolvePublic, request: transport.request });
	const result = await reader.read("https://news.example/");
	assert.equal(result.ok, true); assert.equal(result.text, "public article"); assert.equal(transport.seen.length, 1);
});

test("G07 redirect hops share one deadline instead of resetting it", async () => {
	const transport = fakeTransport(({ url, response }) => {
		const hop = Number(url.pathname.slice(1) || "0");
		response.headers["content-type"] = "text/plain";
		if (hop < 3) { response.statusCode = 302; response.headers.location = `https://news.example/${hop + 1}`; }
		return () => {
			const timer = setTimeout(() => response.end("article"), 25);
			response.once("close", () => clearTimeout(timer));
		};
	});
	const reader = new LinkReader({ timeoutMs: 60, resolve: resolvePublic, request: transport.request });
	assert.equal((await reader.read("https://news.example/0")).blocked, "fetch_failed:timeout");
	assert.ok(transport.seen.length > 0 && transport.seen.length < 4);
	assert.ok(transport.seen.every((record) => record.destroyed));
});
