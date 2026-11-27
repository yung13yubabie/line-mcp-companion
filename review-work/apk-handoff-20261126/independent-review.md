# Independent Review APK handoff static gate — 2026-11-26

**PASS for the focused tool/workflow patch to proceed to normal CI review. Not installation, upgrade, merge or release approval.**

Frozen scripts/review-apk.py SHA256161df3d7ed91720092363d70d586588fa0678a0ec9362317b5a14626fff51de6; test/review-apk.test.py SHA256117fe265ca9acaf65018b902fbbd3aa14774dd6856d059fcdde84b95cf4f97b2. Independent source inspection and git diff --check completed. No production code was modified by this auditor.

## Confirmed contract

inspect uses only caller-selected apksigner verify and aapt dump badging against a private read-only snapshot. It checks tool exit status, explicit single current signer, supported signature schemes, exact Review package/version form, one supported ABI, numeric bounded versionCode/min/targetSDK and non-debuggable metadata. Missing/malformed/duplicate critical fields, unsupported split/major-version metadata and unsupported lineage are rejected. Input and snapshot fingerprints are rechecked. Tool provenance is a caller prerequisite; the script does not authenticate the publisher or APK source merely because a self-signature verifies.

compare directly reinspects both APKs; it does not trust supplied JSON. The same package/ABI/current signer and a strictly increasing numeric versionCode are necessary to emit eligible_for_authorized_isolated_upgrade_test. versionName is not used for ordering. Same-code rejection is this workflow's conservative prerequisite, not a claim that Android universally forbids same-version reinstalls. See official [versioning](https://developer.android.com/studio/publish/versioning), [app signing](https://developer.android.com/studio/publish/app-signing) and [apksigner verification](https://developer.android.com/tools/apksigner).

Before decision, both original input hashes/sizes are rechecked against their individual inspections. This fixes the focused aggregate-boundary gap independently demonstrated in before-aggregate-boundary.json: the earlier8c820b87fb5f2fcebcce66efb542c6312234207c16df46332a0fd44cb15d71d8 version could emit eligible after baseline changed while candidate was being inspected. That reproduction used dummy bytes and a mocked runner, not a signed APK or Android execution. The final version blocks the same case. These repeated checks are bounded consistency detection, not a kernel immutability guarantee.

Report targets cannot alias an input or build tool through normal path, symlink or hardlink checks, and safe targets are updated atomically. Unsafe targets are left untouched and the command returns nonzero with a blocked stdout receipt; consumers must check exit status rather than trusting an old report at an unsafe path.

## Independent evidence

independent-cases.py / after-independent-cases.json: **34/34 passed**, with final source hash stable before/after execution. Includes four groups of existing actual official signature/badging output, the actual old→new signer difference plus unchanged code5 rejection, malformed duplicate metadata, invalid version ranges, unsupported split/major/ABI/signer/rotation cases, symlink/hardlink protection and aggregate baseline mutation.

The sole positive full-wrapper decision case uses a mocked runner and synthetic invalid-APK bytes. It establishes only decision logic and verifies all runtime/device/upgrade/source fields remain not_tested. It is not evidence of a real APK upgrade or device acceptance. Root separately ran the frozen CLI against supplied real APKs with the existing verified official BuildTools; the independent receipt check is recorded below.

Historical real files remain blocked: original signer032c8b839478924d89f03c26da668289ab1d24b348cc2d5cb0894bb197fde046 versus head79 signer5de076edcbe627b325814a8e08ed024db98fd3fc988b6d7286fef9fbe9443113, with versionCode5 in both groups. Same signer continuity has not been established, and no signing keys were accessed, created, persisted or replaced by this tool or auditor.

## Workflow/docs scope and remaining checks

Android-review adds only per-ABI inspect JSON after the existing build/verification steps; Security adds only the new unit test step. Workflow permissions remain contents:read; triggers and signing configuration are unchanged. Documentation correctly limits key-operation claims to this tool/local checks; the existing CI signing flow may still yield different ephemeral Review signers. The docs also state baseline files are not evidence of what is installed on a device.

The true CLI run against existing actual APKs is recorded below. The next fixed source's real CI artifact remains a separate pending validation step. No new artifact was downloaded or CI triggered by this auditor. All installation, data retention, runtime compatibility, local MCP, reboot and physical16KiB/compat-off acceptance remain NOT TESTED. OpenSSL/Node support and formal signer blockers remain unchanged; no merge/tag/Release or external device/quota action is authorized by this receipt.

## Actual host CLI receipt follow-up

The parent then executed the frozen CLI using existing official SDK35 tools against all four real supplied APKs: four inspect commands exit0 and the two original→head79 comparisons exit1. This auditor independently read all six raw JSON reports, confirmed apksigner/aapt exits0 and snapshot/input checks, and rehashed every referenced supplied input to its receipt hash. Each compare is blocked for exactly signer_mismatch and version_not_advanced; inspect upgrade decisions remain not_assessed, and every runtime/device/upgrade/source scope remains not_tested. See real-cli-receipt-check.json for hashes. This is real signed-APK host inspection/comparison, not real upgrade success.

No focused static blocker remains. The upcoming fixed commit's true CI build/artifact remains to be independently bound after the parent supplies it; the previous artifact cannot cover a new tool/workflow source revision.
