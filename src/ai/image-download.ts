/** Untrusted provider-generated image URLs have stricter rules than configured API endpoints. */
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { DownloadError, requestPinned, withDeadline, type RequestTransport } from "../net/bounded-request.ts";
import { bareHostname, isPublicIp } from "../net/public-address.ts";
import { MAX_IMAGE_BYTES, validateRasterImage, type RasterMime } from "../media/image-validation.ts";

export interface ImageDownloadOptions {
	timeoutMs?: number;
	/** Recheck before DNS/socket work and before releasing downloaded data. */
	assertAuthorized?: () => void;
	/** Dependency injection for hermetic tests only; no user-facing setting. */
	resolve?: (hostname: string) => Promise<string[]>;
	request?: RequestTransport;
}

export async function downloadImage(raw: string, options: ImageDownloadOptions = {}): Promise<{ bytes: Uint8Array; mime: RasterMime }> {
	let url: URL;
	try { url = new URL(raw); } catch { throw new DownloadError("bad_image_url", "圖片網址格式錯誤"); }
	if (raw.length > 8192 || url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) {
		throw new DownloadError("bad_image_url", "圖片網址只允許無帳密的 HTTPS 標準埠");
	}
	const host = bareHostname(url.hostname);
	if (!isIP(host) && (!host.includes(".") || host.length > 253)) throw new DownloadError("bad_image_url", "圖片網址必須使用公開主機");
	return withDeadline(options.timeoutMs ?? 45_000, async (signal) => {
		options.assertAuthorized?.();
		let addresses: string[];
		try {
			addresses = isIP(host) ? [host] : await (options.resolve
				? options.resolve(host)
				: lookup(host, { all: true, verbatim: true }).then((rows) => rows.map((row) => row.address)));
		} catch { throw new DownloadError("image_dns", "圖片網址 DNS 解析失敗"); }
		signal.throwIfAborted();
		options.assertAuthorized?.();
		if (!addresses.length || addresses.some((ip) => !isPublicIp(ip))) throw new DownloadError("image_address_blocked", "圖片網址不是允許的公開位址");
		let mime = "";
		const response = await requestPinned(url, addresses[0]!, {
			signal, method: "GET", maxBytes: MAX_IMAGE_BYTES,
			accept: "image/png,image/jpeg,image/webp",
			request: options.request,
			validateHeaders: (res) => {
				if (res.statusCode !== 200) throw new DownloadError("http_error", `下載圖片失敗 HTTP ${res.statusCode ?? 0}（不允許轉址）`);
				mime = String(res.headers["content-type"] ?? "").split(";", 1)[0]!.trim().toLowerCase();
				if (!["image/png", "image/jpeg", "image/webp"].includes(mime)) throw new DownloadError("bad_image", "圖片 Content-Type 不支援");
				const encoding = String(res.headers["content-encoding"] ?? "identity").trim().toLowerCase();
				if (encoding !== "identity") throw new DownloadError("bad_image", "圖片不可使用壓縮傳輸編碼");
				const length = res.headers["content-length"];
				if (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))) throw new DownloadError("bad_image", "圖片長度無效");
				if (length !== undefined && Number(length) > MAX_IMAGE_BYTES) throw new DownloadError("too_large", "圖片太大");
			},
		});
		signal.throwIfAborted();
		options.assertAuthorized?.();
		const length = response.headers["content-length"];
		if (length !== undefined && Number(length) !== response.body.length) throw new DownloadError("bad_image", "圖片長度不符");
		return { bytes: response.body, mime: validateRasterImage(response.body, mime) };
	});
}
