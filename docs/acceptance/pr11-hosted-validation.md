# Temporary draft: one bounded software test of the fixed PR #11 APK

This draft is validation infrastructure only and is not intended for merge. The workflow runs only for the exact same-repository draft branch `validation/pr11-hosted-20261126`, on a standard public `ubuntu-24.04` runner. Its sole explicit permission remains `contents: read`, with no user/repository secret, signing key, Release permission or added Actions permission. The existing Android review build is skipped only for this exact draft/same-repo/head combination, so no replacement APK or signer is created.

## Preserved capability observations

| Actual run | Observed result |
| --- | --- |
| [45799213629](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45799213629) | Disk91,436,396,544 bytes; adb37.0.1 exit0. KVM exists but is not readable/writable by the runner. Emulator absent; version/accelerator probes exit127 `tool_missing`. |
| [45799878155](https://github.com/yung13yubabie/line-mcp-companion/actions/runs/45799878155) | Official emulator37.3.10 downloaded into RUNNER_TEMP with exact size/SHA256 verified. Accelerator exit11: no KVM permission. Version exit127: missing `libpulse.so.0`. Disk90,193,641,472 bytes. |

Both stopped before the fixed artifact API, image download, AVD boot, installation or App/MCP checks. There was no observed artifact403 in these runs. No KVM ACL, udev, group, kernel or platform restriction was changed.

Receipt ZIP SHA256 values: artifact15106087773 `3f2bed311fe3822770e975d274d9052cde4fb7e7bf7242c500fbdac203f3bd00`; artifact15107240122 `66fefdbbdf67e74d6cd5e476f3636411bd8fccf66781c98a84952987d5d536af`.

## Authorized single software attempt

The [official emulator command-line documentation](https://developer.android.com/studio/run/emulator-commandline) documents `-accel off` with `ANDROID_I_WANT_MY_TCG=yes`, while describing this software mode as unsupported and very slow. It is an explicit, bounded capability experiment, not a supported production-runtime claim. KVM is observed, never changed or required by this path. The job timeout is15 minutes; dependency work is bounded to150 seconds; the image/AVD/smoke stage is bounded to480 seconds including cleanup, with boot at most300 seconds. There is no automatic retry or fallback run.

1. Require at least8 GiB free. Use the existing official emulator, or download the pinned official stable37.3.10 archive into RUNNER_TEMP and verify exact size/SHA256.
2. Resolve the known libpulse dependency only using the runner's existing Ubuntu/Canonical APT metadata and official package sources. Download missing packages without `apt update`/install/new source/key, verify cached strong digest and size, and unpack using `dpkg-deb -x` into a non-root private prefix. Do not run maintainer scripts. If any prerequisite or final emulator version probe fails, preserve diagnostics and stop.
3. Only after those gates, issue one normal request to existing artifact15103578619 using the ordinary read-only job token. An API-provided signed redirect is fetched in a new request without Authorization; its URL is never printed or retained. A denial stops this route: no alternative identity, permission, local copy, upload, re-sign or substitute APK.
4. Require the ZIP to be73,613,578 bytes with SHA256 `0e62f61cc7fe7b572657110583285a9bcd46e4e73e4e88e727902bfd1542de43`. Require source `ec7acc84a1b241976c89778e33313a03514e8dd2`, the producer merge source with the same tree as PR #11 head `e1b25d2dd960bf31363b073b92f9108e75f2d300`. Require x86_64 APK SHA256 `cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4`.
5. Only verified fixed bytes permit the official minimum-compatible API29 AOSP x86_64 image download, checked against official archive size/SHA1. Create a fresh private AVD; launch once headless, no audio, no snapshots, `-accel off`,1024 MiB RAM/two cores. Keep Android security defaults. Use a private adb server and this emulator's exact serial only; never attach to a user device.
6. Record actual boot, API/ABI/page size, one normal installation, cold start, HOME/foreground, and own App process stop/start separately. An App process restart is not a guest reboot or persisted-state acceptance. A normal own-App hello endpoint may be checked with empty data; HTTP204/header presence alone is not PSK authentication or successful MCP tool use. Do not read private files/keys via root or run-as. Authenticated MCP read-only acceptance and physical-device testing remain unverified unless separate real evidence exists.

## Evidence interpretation and stop rule

`acceptance-results/status.json` identifies the harness run/head/merge separately from the fixed APK's producer. Every Android stage starts `not_attempted`; only actual completed checks may change it. Dependency, capability, image and software receipts retain exits, actual hashes and the earliest stop without credentials or signed download URLs. A successful limited smoke result still leaves overall acceptance incomplete when authenticated read-only MCP and physical-device checks are outstanding.

If dependency access, fixed input, software capacity or the bounded time budget blocks this single trial, end this cloud route and report that first blocker and every untested stage. Do not automatically rerun or switch image/APK/identity. No main/PR #11 merge, tag, Release, user phone/App, real LINE account/chat, other App data, Daybreak, sandbox bypass or exploit reproduction is authorized. Production release remains NO-GO.
