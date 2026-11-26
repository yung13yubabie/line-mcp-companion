# Independent defensive review, 2026-11-26

Reviewer: independent child agent; did not edit production code. Baseline: `a913a96576276ea304dbeac4c6c37d8eadcf0ad0`. Reviewed the local patch before other role summaries; findings and tests below concern only this review scope.

## Confirmed findings and verification

- **IA-01, plaintext audit snapshots:** Baseline `src/ai/audit.ts` wrote arbitrary truncated detail into plaintext `audit_log`; `AiService.suggest/imageToQueue` and Outbox passed message/prompt text. An independently written safety-expectation test failed on baseline (the first two tests in `audit-content.test.mjs`; `audit-before.tap`, exit 1). The patch minimizes both audit streams to fixed metadata and migrates legacy detail. Those two unchanged cases now pass; the third, added after the patch, separately checks a synthetic disk-backed SQLite/WAL marker is absent from current database/WAL files after migration. This does not prove deletion from backups, external copies or filesystem historical storage.
- **IA-02, local MCP default privileges:** Baseline local HTTP builds omitted `allowWrite`, exposing registered write tools subject to existing application gates. Patch reads `mcp_allow_write === 'on'` for each request. A standard MCP SDK Client over real loopback HTTP independently verified default `tools/list` and direct `tools/call` denial, explicit opt-in through the HMAC authenticated control endpoint, one successful synthetic synchronization, then denial on the next request after opt-out with no extra synthetic side effect. Read access remained usable. This test does not exercise real LINE or prove server identity.
- **IA-03, console and Android diagnostics:** Patch formats object/Error/string arguments before current-known-secret redaction. Two independent in-memory sink tests pass for nested objects, Errors, interpolation, a changed current secret, ordinary metadata and output length. Default object inspection did not execute custom inspectors or getters in the tested case. Android code now reads fixed 4096-byte chunks and writes through the bounded file helper; reviewed statically only. No compiler/emulator/device was available to this reviewer.

## Evidence

- `audit-before.tap`: 2 expected safety assertions failed, baseline.
- `audit-console-after.tap`: 5 tests passed, 0 failed/skipped (3 audit + 2 console).
- `mcp-after.tap`: 1 standard-client entry-point scenario passed, 0 failed/skipped.
- Node `v24.22.3`; in-memory and temporary synthetic SQLite; synthetic current tokens; no production credentials or real chats.
- `git diff --check` passed at review time.

Reviewed patch-file SHA-256 snapshot (not a final commit attestation):

| File | SHA-256 |
| --- | --- |
| src/ai/audit.ts | 2f415ff99785e931244475876e22fa0a836cbfa34eb2ea19072e3015ec55641e |
| src/control/safe-console.ts | 5c73b32d2c9d6d1669aac53fc1c1e91b988aae9d0794c12b86806a93e274d757 |
| src/mcp/server.ts | 0d233368c65dca1f7c0bdb48d96b0e9505f00b347385538e26f80cbdf423fadd |
| android/app/src/main/java/tw/linemcp/app/BoundedNodeLog.kt | b9762ceccf53ce899d064607c7f403e127edb117e1b988036f2752fb65d6277e |
| android/app/src/main/java/tw/linemcp/app/NodeService.kt | b0cb5de332b8235e568c254b15fe976dbb49c24afea371b4e2450050984d31f7 |

## Remaining limitations and release opinion

G01 local MCP server identity remains open. Read-only defaults reduce privileges but do not authenticate the server to an external client. No port-occupation, interception or token-capture test was performed. Existing OAuth send consent is unchecked by default; its fallback requested scope behavior is a least-privilege improvement opportunity, not independently demonstrated privilege bypass.

`EventLog.ai/scam` freeform detail and `outbox.error` still accept regex-redacted upstream error strings. The metadata-only audit change does not establish that every log or stored diagnostic is content-free. Existing transcript/message storage is not claimed fully encrypted. No real LINE login/sync, provider call, background execution, APK launch/upgrade, ABI runtime or signing/release verification was performed by this reviewer.

Opinion: listed patch scenarios independently verified; **formal production release remains NO-GO** for server identity, supported runtime, original release signing and device validation gates. This is a bounded independent review, not complete system assurance.
