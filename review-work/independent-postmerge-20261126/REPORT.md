# Independent post-merge defensive review — 2026-11-26

Reviewer: independent child agent. Baseline main: `44a0e7452f89e8af569bf4213c606d5eca1968cf`. I read the relevant original source and patches independently before using implementation summaries. I did not edit production source. This report binds a local patch snapshot, not a final remote commit or APK.

## Verified behavior

### Native production policy

**IP-01 / confirmed configuration-policy gap:** original `verify_policy` accepted the actual EOL runtime when only `production_ready=true` and `production_blockers=[]` were supplied. My independently written safety assertion failed against the baseline (`runtime-independent-before.txt`, exit 1). The unchanged assertion passes with the patch. The patch separately checks supported component versions, full dual-ABI package version agreement, the advisory review window, an exact UTC snapshot age, and the original approval state; production CLI also revalidates signed provenance.

I independently exercised timezone-equivalent signed dates, a one-second date relabel, an exact 30-day boundary, a one-second stale/future boundary, duplicate Node ABI selection, a nonstable OpenSSL label, cross-ABI Debian revision disagreement, and a synthetic future-supported label which must still fail the real signed package index. These cases passed. The signed snapshot and actual native binaries were not replaced. Passing the synthetic lifecycle candidate is a necessary-policy test only, not evidence that such an Android runtime is available or safe.

I independently checked the official [OpenSSL advisory](https://openssl-library.org/news/secadv/20261124.txt), [release strategy](https://openssl-library.org/policies/releasestrat/), [3.6 EOL notice](https://openssl-library.org/post/2026-11-01-eol34-36/) and [Node release schedule](https://raw.githubusercontent.com/nodejs/Release/main/schedule.json). The December OpenSSL fix is scheduled after this review date; it cannot be treated as an acquired and validated replacement. Component announcement applicability is distinct from exploitability in this app; no exploit was attempted.

### MCP protected adapter path

The new codec/handler/adapter were read before my own validation. They use a separate MCP PSK domain, directional HMAC-derived keys, random GCM IVs, authenticated context and an authenticated fresh-challenge/startup-epoch exchange. Direction keys are derived from PSK and purpose; they are not new per-request KDF outputs. A new startup epoch prevents an old instance's synthetic frame from being accepted by a new handler.

Independently verified:

- Codec rejects wrong key, direction, epoch, nonce, timestamp, response status, altered tag/ciphertext and truncation; normal round trip works; request size boundary and strict loopback URL configuration work.
- Own loopback mailbox rejects a bad tag without consuming the subsequent valid fixture nonce; then rejects replay and an expired timestamp. A new handler rejects the old epoch frame. Authenticated rate-limit replies are encrypted and status-bound. A tiny request budget confirmed hello/invalid authentication do not consume the normal authenticated budget.
- A tiny send-tool budget permits one synthetic policy mutation and refuses the second. During code review I identified that an earlier draft bypassed this existing limit; the final reviewed patch places budget hooks after authentication/schema and before dispatch. No pre-fix dynamic send-bypass claim is made.
- A real standard SDK `StdioClientTransport` starts the actual adapter, initializes, lists/calls tools, rejects a direct write call by default, permits an explicitly enabled synthetic operation, and rejects it on a later request after downgrade. Read access remains usable.
- The actual `src/main.ts` application entry was started with **fresh temporary storage, mock=false, no saved LINE token, separate synthetic MCP/Control secrets via stdin**, and ephemeral loopback ports. Its startup succeeded; legacy HTTP returned 403; the real SDK-to-stdio-to-main path returned sync status `online=false` and read-only tools. The tested process was stopped and its temporary files removed. No login, real synchronization, AI provider or external connector action was invoked.
- The adapter's protected-key-file entry works with an owner-only regular file and rejects mode 0644 and a symlink. Tested stdout/stderr do not contain the synthetic PSK.

Earlier review observations about startup token upper bounds, copying the secure URL, request/send budget placement and native date/version precision were addressed in the reviewed patch. Android UI code was read statically; I did not run the Android UI.

## Independent execution evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Native approval-flip safety expectation on baseline | Expected failure, exit 1 | runtime-independent-before.txt |
| Independently authored native tests | 7/7, exit 0 | runtime-independent-after.txt |
| Existing native regression suite | 43/43, exit 0 | runtime-suite-after.txt |
| Independently authored MCP tests | 7/7, exit 0 | mcp-channel-after.tap |
| Existing Node regression suite | 158/158, no failed/skipped, exit 0 | node-suite-after.tap |
| TypeScript | exit 0 | typecheck-after.txt |
| git diff --check | exit 0 | reviewer tool output |

Node v24.22.3; synthetic data and keys; own loopback; public committed signed source metadata. `mcp-channel-initial.tap` preserves an earlier four-case pass before more independent cases were added. Runtime and MCP test source files in this directory were authored by this reviewer. Local test passes are not new GitHub CI, Android-build or APK claims.

## Patch snapshot SHA-256

| File | SHA-256 |
| --- | --- |
| src/mcp/secure-channel.ts | `29ccf4ab9647bb4ed80d46b1ce24ce257c8d52b1df6c78f393d734ac69061714` |
| src/mcp/secure-http.ts | `5b87d18f89cac912a6bb1c60bcf8b1180e8e749d53ee1431121bdbf13f5e740f` |
| src/mcp/server.ts | `4bbca2d1badfc2db8cf94f57482707df045863f169cd92c37e1a5355e9f77136` |
| src/main.ts | `6e36bb2a9fe4cd8f4ac8801e4aba5f5ffaca73f0d96a06bc689cd963e8ecf6ab` |
| scripts/mcp-stdio.ts | `5ca2bb8825d0da133603a85d488c4980a66317dcf09af525cd1d089ee3629e6b` |
| scripts/node-android/native-runtime.py | `fae485ed5eedb0489990957515fe73d7b6a609f70635ea3260e39cb3cefb9d5d` |
| android/app/src/main/java/tw/linemcp/app/Settings.kt | `f6906a337c64c70674e11c186eadcde91e5eb7b4b148c0e161436d1263dad581` |

## Limits and decision

The protected path authenticates possession of a shared MCP PSK. Multiple clients holding it share a trust domain; this does not provide per-client identity/revocation, a server-only hardware/public-key identity or TLS. Low-level `startMcpHttp` preserves a legacy default for old development fixtures; application main explicitly disables it unless the development compatibility environment option is set. Legacy callers and cloud gateway/tunnel inner paths are not thereby secured. No automatic plaintext fallback exists in the adapter. Environment-key mode cannot erase historical OS process environments; the protected-file path reduces that exposure but requires the user's client to support stdio on the same device.

No device/emulator, Android/Termux compatibility, background lifecycle, APK upgrade, real LINE/account, real provider, production keystore, new runtime build or Android binary execution was verified here. No port occupation, token interception, sandbox bypass, vulnerability exploitation or third-party probing was performed. Existing event-detail/outbox error data lifecycle and broader prior-review limitations were not made complete by this change.

The listed local native-policy and adapter scenarios are independently verified. This is partial mitigation for the checked local MCP path, not clearance of every G01 route. **Formal production release remains NO-GO** for the unresolved supported-runtime, formal signing and device-validation gates, plus unverified remaining entry paths. Fixed commit/remote CI/new APK verification must be recorded separately after the implementer freezes the patch.
