# Independent patch gate — 2026-11-26

**Static review gate: PASS for submitting the focused packaging-validation patch to PR #11 and its normal CI. This is not merge, release, supported-runtime or Android-device acceptance.**

Reviewed parser SHA256 `2daf4baba211cdf51da69d219ade1312ebbbbb0babd217caa3d14548c4f4eed6`; test file SHA256 `093fc39febe73ede4dc00e9d5064b9368b28c8429ecf979265c2e7c1f19b2f3f`. Production runtime lock, native bytes, support approval and signing configuration are unchanged.

## Independent work completed

- Read the final parser, final linkage validator, prepare ordering, report semantics, native tests, workflow diff and packaging documentation independently. No production source was written by this auditor.
- The parser checks bounded ELF64/file-backed metadata, exact local dependency graph, Node direct TLS edges, ssl→crypto, approved local search paths, shared SONAMEs, executable/interpreter contracts, RELRO tail safety and exact-provider GNU version *name* definitions. Parent auxiliary version names cannot stand in for actual definitions; version indexes, counts, chains, singleton tags and metadata ranges have bounded rejection paths.
- The final PT_DYNAMIC check now requires filesz<=memsz and a unique LOAD-backed virtual mapping whose file offset agrees with the segment. This closes the concrete independent counterexample discovered during review.
- Prepare validates each ABI's final target-byte graph before copying that ABI and before recording output hashes. A later ABI failure can leave an earlier valid ABI's reversible staging copy, but cannot record the failed contract as approved. No claim of an atomic whole-directory transaction is made.
- Workflow changes add zipalign existence/verification and prepare/per-ABI static JSON receipts to the existing review build. Permissions, trigger, signing configuration and release behavior are unchanged. The reports explicitly separate provenance checked during this call from byte-only verification and do not claim Android/TLS execution.
- Read the root's raw re-verification receipts: supplied original APK signatures/package metadata and zipalign both exit0 for each ABI. Public certificate is 032c8b839478924d89f03c26da668289ab1d24b348cc2d5cb0894bb197fde046; packages are tw.linemcp.app.review/code5/min29/target35 and exact ABI. This is independent receipt inspection, not an additional apksigner execution by this auditor.

## Independent 23-case validation

`independent_patch_cases.py` uses original supplied ELF bytes in memory and separate small synthetic program-header fixtures. It never runs or loads Android native code. Final `independent-cases-after-dynamic-fix.json` reports **23/23 passed**, with parser source hash unchanged before/after import and execution.

For each ABI it accepts the exact original packaged graph and rejects zero/out-of-executable entry, executable shared-library entry, unsafe runtime search path, wrong Android interpreter, missing exact-provider OpenSSL version definition, unmapped PT_DYNAMIC virtual address, PT_DYNAMIC virtual/file-offset disagreement and PT_DYNAMIC filesz greater than memsz. Three separate RELRO cases accept safe surplus padding and reject protected-tail collisions with same-LOAD writable data or another LOAD's BSS.

The initial run observed the six PT_DYNAMIC rejections missing while the author was concurrently fixing the parser. Its saved receipt hashes the file at the *end* of that run, so its source hash can refer to the newer file than the imported module. Treat `independent-cases-before-dynamic-fix.json` as evidence of observed pre-fix behavior, **not proof that the final 2daf parser fails**. The rerun fixes the audit script's hash timing and records source stability explicitly. No further static blocking finding remains within this focused scope.

## Boundaries and remaining blockers

- This gate checks GNU version names, not every dynsym relocation or Android API29 platform-stub symbol. The baseline independent symbol inspection separately confirmed the original Node/ssl strong OpenSSL imports have exact-provider symbol+version definitions. Neither result establishes runtime ABI/TLS success.
- The original fixed APKs remain the old artifact source ec7acc84a1b241976c89778e33313a03514e8dd2. They verify that the new static rules accept the reviewed native bytes; they do not establish that the new source patch has built successfully. New real CI source/tree/artifact identity is still to be checked after the parent supplies it.
- OpenSSL3.6.5 remains blocked by the unchanged production policy. Mixed compiler-note metadata and source-authentication limits are disclosed. No source-build, support-upgrade or license replacement claim is made.
- All device/Android execution remains NOT ATTEMPTED by this auditor: install/startup/API29/TLS/CA/SQLite/MCP/lifecycle/reboot and physical 16 KiB behavior. Official [Android guidance](https://developer.android.com/guide/practices/page-sizes) separates ELF/ZIP static checks from runtime verification. A genuine 16 KiB result needs the tested hash/ABI, PAGE_SIZE=16384 and evidence this app's compatibility mode is disabled. No device or global setting was touched.

Baseline details remain in INDEPENDENT-BASELINE.md and the associated JSON/raw readelf records. Ignored build/audit evidence writes completed via normal escalation after the read-only sandbox initially prevented writing; there is no pending or denied action.
