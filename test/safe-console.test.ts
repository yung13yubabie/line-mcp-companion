import { test } from "node:test";
import assert from "node:assert/strict";
import { installSafeConsole } from "../src/control/safe-console.ts";

test("console entry points redact formatted objects, Error arguments and rotated credentials", () => {
 const output: string[] = [];
 const sink = { log: (...args: unknown[]) => { output.push(String(args[0])); }, error: (...args: unknown[]) => { output.push(String(args[0])); }, warn: (...args: unknown[]) => { output.push(String(args[0])); }, info: (...args: unknown[]) => { output.push(String(args[0])); } };
 let secret = "synthetic-credential-one";
 const restore = installSafeConsole(sink, () => [secret]);
 sink.log("nested %o", { authorization: secret, nested: { token: secret } });
 sink.error(new Error(`request rejected ${secret}`));
 secret = "synthetic-credential-two";
 sink.warn({ token: secret });
 sink.info("harmless status %d", 200);
 assert.equal(output.length, 4);
 assert.ok(output.every((line) => !line.includes("synthetic-credential")));
 assert.match(output[0]!, /redacted/);
 assert.match(output[1]!, /request rejected/);
 assert.equal(output[3], "harmless status 200");
 restore();
});
