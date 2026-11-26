/** Bounded raster-container validation. This does not decode or re-encode pixels. */
import { crc32 } from "node:zlib";
import { DownloadError } from "../net/bounded-request.ts";

export const MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_SIDE = 8192;
const MAX_PIXELS = 40_000_000;
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export type RasterMime = "image/png" | "image/jpeg" | "image/webp";

function invalid(): never { throw new DownloadError("bad_image", "圖片格式錯誤或不支援"); }
function dimensions(width: number, height: number): void {
	if (width < 1 || height < 1 || width > MAX_SIDE || height > MAX_SIDE || width * height > MAX_PIXELS) invalid();
}

function png(b: Buffer): void {
	let offset = 8;
	let header = false;
	let palette = false;
	let data = false;
	let dataEnded = false;
	let dataBytes = 0;
	let indexed = false;
	while (offset + 12 <= b.length) {
		const length = b.readUInt32BE(offset);
		const end = offset + 12 + length;
		if (end > b.length) invalid();
		const type = b.toString("ascii", offset + 4, offset + 8);
		if (!/^[A-Za-z]{4}$/.test(type) || (type.charCodeAt(2) & 32)) invalid();
		if (crc32(b.subarray(offset + 4, end - 4)) !== b.readUInt32BE(end - 4)) invalid();
		const body = offset + 8;
		if (!header && type !== "IHDR") invalid();
		if (type === "IHDR") {
			if (header || length !== 13) invalid();
			header = true;
			dimensions(b.readUInt32BE(body), b.readUInt32BE(body + 4));
			const bitDepth = b[body + 8]!;
			const color = b[body + 9]!;
			const depths: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
			if (!depths[color]?.includes(bitDepth) || b[body + 10] !== 0 || b[body + 11] !== 0 || b[body + 12]! > 1) invalid();
			indexed = color === 3;
		} else if (type === "PLTE") {
			if (palette || data || !length || length > 768 || length % 3 !== 0) invalid();
			palette = true;
		} else if (type === "IDAT") {
			if (dataEnded || (indexed && !palette)) invalid();
			data = true;
			dataBytes += length;
		} else if (type === "IEND") {
			if (length !== 0 || !dataBytes || end !== b.length) invalid();
			return;
		} else {
			// Animation and unknown critical chunks require a different decoder policy.
			if (["acTL", "fcTL", "fdAT"].includes(type) || !(type.charCodeAt(0) & 32)) invalid();
		}
		if (data && type !== "IDAT") dataEnded = true;
		offset = end;
	}
	invalid();
}

function jpeg(b: Buffer): void {
	let offset = 2;
	let frame = false;
	let scan = false;
	while (offset < b.length) {
		if (b[offset++] !== 0xff) invalid();
		while (b[offset] === 0xff) offset++;
		const marker = b[offset++];
		if (marker === 0xd9) { if (!frame || !scan || offset !== b.length) invalid(); return; }
		if (marker === undefined || marker === 0 || marker === 0xd8 || marker === 1 || (marker >= 0xd0 && marker <= 0xd7)) invalid();
		if (offset + 2 > b.length) invalid();
		const length = b.readUInt16BE(offset);
		const end = offset + length;
		if (length < 2 || end > b.length) invalid();
		if ([0xc0, 0xc1, 0xc2].includes(marker)) {
			if (frame || length < 11 || b[offset + 2] !== 8) invalid();
			const components = b[offset + 7]!;
			if (![1, 3, 4].includes(components) || length !== 8 + 3 * components) invalid();
			dimensions(b.readUInt16BE(offset + 5), b.readUInt16BE(offset + 3));
			frame = true;
		} else if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) invalid();
		if (marker === 0xda) {
			if (!frame || length < 8 || !b[offset + 2] || length !== 6 + 2 * b[offset + 2]!) invalid();
			scan = true;
			offset = end;
			// Entropy bytes may contain stuffed FF00 and restart markers. Stop at
			// the next structural marker so progressive JPEG scans are checked too.
			while (offset < b.length) {
				if (b[offset] !== 0xff) { offset++; continue; }
				const start = offset;
				while (b[offset] === 0xff) offset++;
				const next = b[offset];
				if (next === 0 || (next !== undefined && next >= 0xd0 && next <= 0xd7)) { offset++; continue; }
				offset = start;
				break;
			}
		} else offset = end;
	}
	invalid();
}

function webp(b: Buffer): void {
	if (b.length < 20 || b.readUInt32LE(4) !== b.length - 8) invalid();
	let offset = 12;
	let extended: [number, number] | undefined;
	let image: [number, number] | undefined;
	while (offset + 8 <= b.length) {
		const type = b.toString("ascii", offset, offset + 4);
		const length = b.readUInt32LE(offset + 4);
		const body = offset + 8;
		const end = body + length;
		const next = end + (length & 1);
		if (next > b.length || (next > end && b[end] !== 0)) invalid();
		if (type === "VP8X") {
			if (offset !== 12 || length !== 10 || (b[body]! & 0xc3) || b[body + 1] || b[body + 2] || b[body + 3]) invalid();
			extended = [b.readUIntLE(body + 4, 3) + 1, b.readUIntLE(body + 7, 3) + 1];
			dimensions(...extended);
		} else if (type === "VP8 " || type === "VP8L") {
			if (image) invalid();
			if (type === "VP8 ") {
				if (length < 10 || (b[body]! & 1) || !b.subarray(body + 3, body + 6).equals(Buffer.from([0x9d, 0x01, 0x2a]))) invalid();
				image = [b.readUInt16LE(body + 6) & 0x3fff, b.readUInt16LE(body + 8) & 0x3fff];
			} else {
				if (length < 6 || b[body] !== 0x2f) invalid();
				const bits = b.readUInt32LE(body + 1);
				if (bits >>> 29) invalid();
				image = [(bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1];
			}
			dimensions(...image);
		} else if (!["ALPH", "ICCP", "EXIF", "XMP "].includes(type)) invalid();
		offset = next;
	}
	if (offset !== b.length || !image || (extended && (extended[0] !== image[0] || extended[1] !== image[1]))) invalid();
}

/** Accept a complete supported container with bounded dimensions, no trailing bytes or animation. */
export function validateRasterImage(bytes: Uint8Array, declaredMime?: string): RasterMime {
	if (bytes.length > MAX_IMAGE_BYTES) throw new DownloadError("too_large", "圖片太大");
	const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let mime: RasterMime;
	if (b.subarray(0, 8).equals(PNG)) { png(b); mime = "image/png"; }
	else if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) { jpeg(b); mime = "image/jpeg"; }
	else if (b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP") { webp(b); mime = "image/webp"; }
	else invalid();
	if (declaredMime !== undefined && declaredMime !== mime) invalid();
	return mime;
}

export function decodeImageBase64(encoded: unknown): { bytes: Uint8Array; mime: RasterMime } {
	if (typeof encoded !== "string" || !encoded.length) invalid();
	if (encoded.length > 4 * Math.ceil(MAX_IMAGE_BYTES / 3)) throw new DownloadError("too_large", "圖片太大");
	// Buffer.from silently accepts junk, URL-safe alphabet, and missing padding.
	if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) invalid();
	const bytes = Buffer.from(encoded, "base64");
	if (bytes.toString("base64") !== encoded) invalid();
	return { bytes, mime: validateRasterImage(bytes) };
}
