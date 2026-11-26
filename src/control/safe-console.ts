/** Format every argument before redaction, including Error objects and nested values. */
import { formatWithOptions } from "node:util";
import { redact } from "../ai/audit.ts";

export function installSafeConsole(target: Pick<Console, "log" | "error" | "warn" | "info">, secrets: () => string[]): () => void {
 const originals = new Map<"log" | "error" | "warn" | "info", (...args: unknown[]) => void>();
 for (const method of ["log", "error", "warn", "info"] as const) {
  const original = target[method];
  originals.set(method, original);
  target[method] = (...args: unknown[]) => {
   let text = formatWithOptions({ customInspect: false, getters: false, depth: 4, maxArrayLength: 50, maxStringLength: 4096, breakLength: Infinity }, ...args);
   for (const secret of secrets().filter((s) => s.length >= 8).sort((a, b) => b.length - a.length)) text = text.split(secret).join("[redacted]");
   original.call(target, redact(text, 8192));
  };
 }
 return () => { for (const [method, original] of originals) target[method] = original; };
}
