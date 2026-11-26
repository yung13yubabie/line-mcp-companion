# Temporary draft: hosted-runner validation of the fixed PR #11 APK

This draft is validation infrastructure only. It does not modify main or PR #11, rebuild an APK, create/use signing private keys, merge, release, add repository secrets, or grant Actions/release write permissions. The workflow has only `contents:read` and runs only on the same-repository draft head `validation/pr11-hosted-20261126`, using the standard free public `ubuntu-24.04` runner with an 8-minute timeout.

GitHub documents Android hardware acceleration on standard Linux hosted runners. The capability itself is measured here, without changing KVM permissions, udev, groups, kernel or platform restrictions: https://docs.github.com/en/actions/reference/runners/github-hosted-runners

## Phase 1: actual capability and fixed input

1. Record actual runner KVM existence/read/write access, official installed emulator/adb versions, `emulator -accel-check`, installed SDK images, and disk free bytes. Do not infer current capability from the cloud workspace or documentation alone.
2. Only if those gates pass, make one normal authenticated request with the job's contents-read token to the existing artifact download API. Do not request `actions:read`, use user/repository secrets, transfer connector credentials, or try another route if the API denies access. A normal API-provided signed redirect is fetched with a separate request without Authorization; its URL is not persisted or printed.
3. Download bytes must match ZIP size73,613,578 and SHA256 `0e62f61cc7fe7b572657110583285a9bcd46e4e73e4e88e727902bfd1542de43`; source-commit must be `ec7acc84a1b241976c89778e33313a03514e8dd2`, the PR merge source with the same tree as head `e1b25d2dd960bf31363b073b92f9108e75f2d300`.
4. The actual x86_64 APK must match SHA256 `cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4`. No build, re-signing or alternative APK substitution is permitted.

The dedicated draft is excluded from the existing Android-review build job only when draft + same-repository + exact head all match, preventing an unrelated replacement APK/test signer. All other review-build scopes and all existing permissions remain unchanged. This temporary change is not intended for merge.

## Receipts and remaining stages

`acceptance-results/status.json` distinguishes the harness's actual run/head/merge SHA from the fixed APK's producer head/source. It initializes all Android stages as `not_attempted`. `capabilities.json` preserves the actual commands and exits. Read-denial HTTP status and fixed API error text are retained without tokens, Authorization headers, or signed download URLs. Redacted receipts are retained as ordinary workflow artifacts, with no Release publication.

Phase 1 does not start an AVD or claim installation, cold start, foreground/background, restart, or Android MCP results. If capability/input gates pass, a subsequent scoped validation update can execute those stages using official SDK images and synthetic data. Product and real-device gates remain open until their separate evidence exists. Any emulator result is not a physical-device result. No user phone/App, other app data or real LINE account/chat is used.

## Preserved first hosted observation

Run45799213629 genuinely ran on the standard hosted runner. Receipt artifact15106087773 has ZIP SHA256 `3f2bed311fe3822770e975d274d9052cde4fb7e7bf7242c500fbdac203f3bd00`.

- Disk free91,436,396,544 bytes; adb37.0.1 version command exit0.
- `/dev/kvm` exists, but runner read/write access is false.
- Preinstalled emulator was absent, so version and accelerator probes were exit127 `tool_missing`.
- Fixed artifact API was not called; there was no observed artifact403. No AVD/install/launch/MCP/restart happened.

The next probe installs only the missing official stable emulator37.3.10 into RUNNER_TEMP, verifies its exact archive size/SHA256 against previously independently checked Google metadata, then repeats the actual accelerator check. It does not change device permissions, group membership or udev. This resolves the reversible missing-tool issue without pretending the KVM access issue has been resolved.
