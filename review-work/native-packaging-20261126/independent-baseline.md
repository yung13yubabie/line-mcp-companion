# Independent baseline native packaging audit — 2026-11-26

Scope: supplied fixed PR #11 review APKs only; static host inspection. No APK/native code executed, Android device/emulator contacted, package downloaded, CI triggered, production source changed, or signing key accessed by this auditor.

## Fixed inputs

- Head e1b25d2dd960bf31363b073b92f9108e75f2d300; tree 49a633dd53ad3400fd77a354561f8b3c7a8f2a73.
- Artifact source-commit.txt: ec7acc84a1b241976c89778e33313a03514e8dd2 (PR merge artifact; not described as a new packaging fix artifact).
- ARM64 APK SHA256 ab91cf16b7a85fd575d8da5a6d7c2526312922df787d22c1d063fc1cd4fb922e.
- x86_64 APK SHA256 cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4.
- Existing CI signature reports say APK v2 debug certificate 032c8b839478924d89f03c26da668289ab1d24b348cc2d5cb0894bb197fde046. This auditor read those reports; did not independently invoke apksigner in this round.

## Confirmed static results

1. Independently invoked the frozen script's verify_provenance on already committed public inputs: pinned InRelease signature, signed compressed indexes, selected package Version/Architecture/Filename/SHA256/Size and signed snapshot date all passed. No .deb was fetched or rebuilt. This authenticates the pinned signed binary-package metadata; it does not reproduce the upstream source builds.
2. Independently invoked frozen verify_outputs on both supplied APKs: exact ABI/native inventory, embedded lock, all 22 native hashes/machines and 94 license files per APK passed. Full APK hashes equal supplied SHA256SUMS.
3. Independently parsed all 22 ELF headers/program headers and used host readelf for dynamic metadata. All LOADs have alignment >=0x4000 and congruent file offset/vaddr modulo 0x4000, in-file segment bounds and filesz<=memsz. No writable+executable LOAD, executable GNU_STACK or DT_TEXTREL observed.
4. Both libnode executables: ET_DYN, nonzero entry point, /system/bin/linker64 interpreter, $ORIGIN runpath, direct libtx_ssl.so and libtx_crypto.so dependencies. Shared Termux outputs have their correct renamed SONAMEs and $ORIGIN; AndroidX SONAME is correct and has no runpath. All DT_NEEDED names close within the same ABI's packaged files or libc.so/libm.so/libdl.so. VERNEED filenames are renamed consistently; no old OpenSSL SONAME residue found.
5. For each ABI, all 617 strong versioned OpenSSL imports in libnode and 553 in libtx_ssl have a matching symbol+version in their exact VERNEED named packaged provider, not merely a union of arbitrary exports. libtx_ssl requires OPENSSL_3.6.0 from libtx_crypto; this corroborates the package lock's actual 3.6 branch. It is not a claim of TLS runtime success or patch support.
6. Strong system symbol-version names observed: LIBC and LIBC_N only. Android ident notes: Node/c-ares/OpenSSL/ICU libraries except icudata/SQLite/zlib declare API24, NDK r30 build16248370; libc++ declares API21, NDK r28 build13004108; AndroidX declares API21, NDK r25c build9519653; icudata has no Android ident. These metadata do not establish that every imported system symbol is available on API29. No complete Android platform-stub symbol comparison or Android API29 runtime test was performed.
7. Production support policy independently rejected the unchanged lock with OPENSSL_36_EOL / OPENSSL_BRANCH_UNSUPPORTED. production_ready remains false. No runtime bytes or approval are upgraded by these packaging checks.

## RELRO: avoid a padding false positive

The official [16 KB guidance](https://developer.android.com/guide/practices/page-sizes#check_the_relro_security_flag) distinguishes protection from trailing writable data. All 20 Termux/Node outputs satisfy aligned RELRO end or an end exactly equal to their containing writable LOAD end.

The two AndroidX libraries have nonaligned RELRO ends extending beyond their original writable LOAD's used memory: ARM64 RELRO [0x5c40,0x6000), LOAD [0x5c40,0x5fd0); x86_64 RELRO [0x5ec0,0x7000), LOAD [0x5ec0,0x6268). Their next writable LOADs begin at 0x9fd0 and 0xa268. They do not satisfy the documentation's literal equality example, but the surplus is padding, and no other writable memory is in the protected trailing page.

Independent interval check across *all* PF_W LOAD memory ranges (including BSS) found no intersection with [RELRO_end, ceil_16K(RELRO_end)) for any of the 22 ELFs. All pass this semantic protection condition. Do not label the AndroidX padding as an observed failure or reject solely because RELRO end != LOAD end. These are static observations, not a 16 KB device test.

## Confirmed gaps and acceptance checks

- Frozen verify_outputs checked exact bytes/architecture/LOAD alignment but did not itself enforce final ELF dynamic closure, direct TLS links, SONAME, executable interpreter contract or RELRO tail safety. Prepare had some dependency/runpath checks, but a future independently reviewed output-hash update could otherwise bless incorrect dynamic metadata. Add reusable validation on final outputs and final APK; synthetic fixtures must independently cover each rejection. Do not weaken the existing byte inventory/provenance or production support gate.
- Package version libc++ 30 and supplemental NDK-r30 NOTICE are not evidence that libc++ was compiled with NDK r30. Its ELF note says r28. Disclose signed package authentication, per-binary note metadata and source-build reproducibility as separate evidence. No license replacement is prescribed by this observation.
- For the patch: inspect implementation independently; run meaningful positive and negative synthetic coverage; verify existing APK passes without changing its hashes; then verify a genuinely new CI artifact, source/tree identity and final APK metadata. A previous artifact cannot verify a new source patch.
- Device acceptance remains NOT ATTEMPTED: installation, native startup, API29 behavior, ABI-specific execution, TLS/CA/SQLite operation, local MCP flow and restart. A claimed 16 KB runtime result requires the tested APK hash/ABI, guest PAGE_SIZE=16384 and evidence this app's compatibility mode is disabled. No global device settings changes or device access are authorized here.

## Evidence

- input-native-inventory.json: independent readelf metadata and native hashes.
- elfs/{ABI}/*.so.{header,segments,dynamic,versions,notes}.txt: raw host readelf outputs from the supplied bytes.
- baseline-static-verification.json: signed metadata verification, existing APK verifier results and parsed LOAD properties.
- relro-symbols-toolchain.json: independent RELRO-tail intervals, exact-provider symbol results, Android ident details.

This baseline is not approval to release, merge #11, change the lock/runtime, or claim Android runtime acceptance. A write to this ignored audit receipt initially hit the read-only sandbox; the authorized build/audit-only evidence write then completed through normal escalation. No denied operation remains pending.
