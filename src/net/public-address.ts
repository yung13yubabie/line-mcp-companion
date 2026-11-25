/** Conservative egress policy for untrusted URLs; not a general IP geolocation API. */
import { BlockList, isIP, type LookupFunction } from "node:net";

const BLOCK4 = new BlockList();
for (const [network, prefix] of [
	["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
	["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
	["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
	["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) BLOCK4.addSubnet(network, prefix, "ipv4");

const GLOBAL6 = new BlockList();
GLOBAL6.addSubnet("2000::", 3, "ipv6");
const BLOCK6 = new BlockList();
// IANA special-purpose ranges inside global unicast. Reject the complete IETF
// protocol-assignment range, including otherwise public special-purpose anycast.
// Also exclude 6to4: its embedded IPv4 destination must not bypass IPv4 policy.
for (const [network, prefix] of [
	["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20],
] as const) BLOCK6.addSubnet(network, prefix, "ipv6");

/** IPv6 mapped/compatible, NAT64, Teredo, ULA, link-local, and reserved space fail closed. */
export function isPublicIp(ip: string): boolean {
	if (ip.includes("%")) return false; // scoped addresses are never Internet destinations
	const version = isIP(ip);
	if (version === 4) return !BLOCK4.check(ip, "ipv4");
	if (version === 6) return GLOBAL6.check(ip, "ipv6") && !BLOCK6.check(ip, "ipv6");
	return false;
}

export const bareHostname = (host: string): string => host.replace(/^\[|\]$/g, "");

/** Use the already-checked address for every socket lookup, never resolve twice. */
export function pinnedLookup(ip: string): LookupFunction {
	const family = isIP(ip);
	if (!family) throw new Error("invalid_pinned_address");
	return (_host, options, callback) => {
		if ((options as { all?: boolean }).all) {
			(callback as unknown as (err: null, addresses: { address: string; family: number }[]) => void)(null, [{ address: ip, family }]);
		} else callback(null, ip, family);
	};
}
