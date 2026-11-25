# Security Review Brief — LINE MCP Companion

Scope: Android app `tw.linemcp.app` (Kotlin/Compose UI + embedded Node 24 running LINEJS), the local
MCP server, the local control API, AI features and the anti-scam module. Version 0.2.0.
All paths are relative to the repository root.

## 1. Architecture

```
Android process (uid of tw.linemcp.app)
├─ Kotlin UI (MainActivity, FragmentActivity + Compose)
│    └─ HTTP → 127.0.0.1:47824 /control  (Bearer control token)
├─ NodeService (foreground service, dataSync) ─ spawns child process:
│    libnode.so  assets/nodeapp/main.mjs   (env: tokens, LMA_DATA_KEY, optional LMA_AI_KEY)
│      ├─ auth/session.ts     LINEJS BaseClient, device = ANDROIDSECONDARY (secondary device login)
│      ├─ guard/upstream-guard.ts  blocks read receipts, E2EE key registration, and any send
│      │                            call that does not hold a send permit
│      ├─ sync/*              long-poll sync + exponential backoff, auth-error stop
│      ├─ storage/*           node:sqlite (filesDir/line.db), FTS5; line_kv encrypted (AES-256-GCM)
│      ├─ ai/*                policy, outbox (confirm queue), provider (OpenAI-compatible), prompt
│      ├─ scam/*              rule detector, sample table, quoted-reply warner
│      ├─ style/*             lieflat (de-AI-tone, CC BY-NC), social-post (draft only)
│      ├─ mcp/server.ts       127.0.0.1:47823/mcp (Streamable HTTP, stateless)
│      └─ control/server.ts   127.0.0.1:47824/control
└─ KeepaliveWorker (WorkManager, 15 min) restarts the service if the control port is dead
```

Desktop/dev: the same `src/main.ts` runs under Node 24 (`npm start`).

## 2. Trust boundaries & threat model

| Boundary | Untrusted side | Main threats | Controls |
| --- | --- | --- | --- |
| LINE servers → Node | message content from any contact | prompt injection, scam content, malformed data | messages are data only; injection heuristics; AI output sanitised; nothing auto-sends without policy |
| Other apps on the phone → loopback ports | any local app (no permission needed to hit 127.0.0.1) | read chats, send messages, steal tokens | Bearer tokens (timing-safe), whitelist, rate limits, no CORS, Origin rejected, Host must be loopback |
| Web pages in a browser on the phone | JS on any site | DNS rebinding / CSRF to loopback | any `Origin` header → 403; `Host` must be `127.0.0.1`/`localhost`/`[::1]`; no CORS headers |
| MCP client (external AI) | the AI model and whatever it read | sending messages the user did not want, exfiltrating other chats | MCP whitelist + separate AI whitelist, per-chat mode, confirm queue (default ON), caps, active hours, kill switch, audit |
| AI provider (built-in mode) | provider response | injection in output, key leakage | output sanitiser (secret check, URL flag, length), forced confirmation on flags |
| Device storage | other apps (no), backups, rooted device / forensic copy | token / key theft | app-private storage, `allowBackup=false`, line_kv AES-GCM with Keystore-protected key, secrets in EncryptedSharedPreferences |
| Clipboard | other apps, clipboard previews | token leakage | copy only after BiometricPrompt/device credential; `EXTRA_IS_SENSITIVE`; auto-clear after 60 s |
| Shoulder surfing | — | token visible | token masked by default, reveal needs auth, auto re-mask after 30 s |

Out of scope / accepted: a rooted device or malware with the app's uid; LINE account restriction risk
(unofficial protocol — disclosed in README and first-run screen).

## 3. Where secrets live

| Secret | Storage | In transit |
| --- | --- | --- |
| LINE auth token, refresh token, E2EE private keys (LINEJS storage) | SQLite `line_kv`, each value `enc:v1:` AES-256-GCM, AAD = `line_kv:<key>` (`src/storage/secret-box.ts`, `kv-storage.ts`) | never leaves Node except to LINE |
| Data key (32 bytes) for the above | Android: EncryptedSharedPreferences `secrets` (`Secrets.kt`, Keystore AES-256-GCM master key). Desktop: derived from `LMA_PASSPHRASE` with scrypt (N=2^15), salt in `settings.data_key_salt` | env `LMA_DATA_KEY` at spawn; Node deletes it from `process.env` immediately; never written to disk by Node |
| Key check | `settings.data_key_check` = truncated SHA-256 fingerprint; wrong key ⇒ refuse to start (no overwrite) | — |
| Control token | EncryptedSharedPreferences | env at spawn (deleted by Node); HTTP header on loopback |
| MCP token | EncryptedSharedPreferences; rotated at runtime via `/control/mcp/rotate` (new value saved back) | env at spawn (deleted); shown to user only after auth |
| AI API key | EncryptedSharedPreferences; Node keeps it **in memory only** (never in SQLite) | env `LMA_AI_KEY` at spawn (deleted) or `POST /control/ai/key`; HTTPS to provider |
| Release signing key | `../keys/release.jks` (outside repo, gitignored, 0600) + `../keys/keystore.pass` (0600) | — |

Legacy migration: on start, any plaintext `line_kv` row is encrypted, then `secure_delete=ON`, `VACUUM`,
`wal_checkpoint(TRUNCATE)` remove the old plaintext pages (test: `test/security.test.ts`).

## 4. Network listeners and egress

Listeners (both bind **127.0.0.1 only**; code refuses other hosts):

| Port | Service | Auth | Limits |
| --- | --- | --- | --- |
| 47823 | MCP `/mcp` (POST only, stateless JSON) | `Bearer` MCP token (≥16 chars, required — server refuses to start without one) | 120 req/min global, 10 send-tool calls/min, body ≤ 256 KB, headers timeout 10 s, request timeout 60 s, Origin ⇒ 403, non-loopback Host ⇒ 403 |
| 47824 | Control `/control/*` (Kotlin UI only) | `Bearer` control token (≥16, required), timing-safe | body ≤ 256 KB, Origin ⇒ 403 |

Egress: LINE servers (via LINEJS, HTTPS); the configured AI base URL (must be `https`, or `http` only for
loopback; no credentials in URL); `stickershop.line-scdn.net` for sticker images (numeric id only,
≤ 512 KB, cached; mock mode generates images locally). Android `network_security_config` blocks
cleartext except 127.0.0.1 (applies to the Kotlin side; Node enforces its own URL validation).

## 5. Permission gates (send path)

Every outgoing message goes through `Outbox` (`src/ai/outbox.ts`) and the real sender requires a
send permit (`withSendPermit`); LINEJS send methods called outside it are blocked by the upstream guard.

`AiPolicy.checkBasic` (`src/ai/policy.ts`), in order: kill switch → AI master switch → chat in MCP
whitelist → chat in AI whitelist → mode ≠ off → image permission. `checkSend` adds active hours, min
interval, hourly cap (skipped only when the user approves in the queue) and always per-chat and global
daily caps. `needsConfirmation` = mode ≠ auto OR confirm_send (default true) OR any risk flag.
Kill switch ON returns all scheduled items to pending and cancels scheduled scam warnings.

Driver mode (`ai_driver`): `connector` (default) — no in-app AI calls; external MCP clients send via the
same gates. `builtin` — in-app provider drafts suggestions/auto replies.

Anti-scam warnings (`src/scam/warner.ts`) are the only messages that skip the confirm queue, and only for
groups where the user switched them on (default OFF). Still gated by: kill switch, MCP whitelist,
per-sender+category cooldown (30 min), one warning per message, per-group daily cap (10), audit log.
Warnings never quote the scam text; nicknames are sanitised; LINE banned words are replaced.

MCP `add_scam_sample` can only add `SCAM` samples (cannot whitelist a pattern via OK samples).

## 6. Security fixes in this release (t233u)

1. **Disclaimer**: README banner and a blocking first-run screen (unofficial protocol, ban risk, use a
   secondary/test account, not affiliated with LY Corporation); also reachable from Settings.
2. **Release signing**: dedicated RSA-4096 keystore (`../keys/`, gitignored, password file 0600). Gradle
   signs release only with it and never falls back to the debug key. Cert SHA-256
   `75:E7:2F:E9:BC:01:B9:E8:9F:78:A9:42:53:12:58:1C:1D:4D:AA:92:E9:CB:E2:14:63:F8:76:18:97:EC:A9:0A` (in README).
3. **Secrets at rest**: LINE token / E2EE keys AES-256-GCM encrypted with a Keystore-protected key passed
   via env at spawn; plaintext migration + wipe; desktop requires `LMA_PASSPHRASE` or refuses (exit 78).
4. **Token UI**: MCP token masked; reveal/copy require BiometricPrompt (`BIOMETRIC_STRONG|DEVICE_CREDENTIAL`,
   API 29: `BIOMETRIC_WEAK|DEVICE_CREDENTIAL`; no screen lock ⇒ refused); clipboard `EXTRA_IS_SENSITIVE`,
   auto-cleared after 60 s; rotate button (auth required) — old token invalid immediately.
5. **Desktop/dev**: missing tokens are generated randomly and printed once to stderr; tokens < 16 chars ⇒
   refuse; servers refuse to start without a token and refuse non-loopback binds; unauthenticated
   requests always 401.

Tests: `test/security.test.ts` (crypto round-trip/tamper/AAD, migration wipes plaintext from db+WAL,
wrong key refused, no key ⇒ exit 78, generated tokens + 127.0.0.1 bind, token-less/short-token/non-loopback
refusal, 401s), `test/ai.test.ts` (whitelist gating, confirm queue, caps, active hours incl. overnight,
kill switch, stickers, injection, connector mode, scam rules/warnings/mentions).

## 7. Known risks / items for the reviewer

- Unofficial LINE protocol; account restriction possible. Real-account flows (login, sync, send, E2EE,
  mentions metadata `MENTION`) are **not verified against a real account** in this build.
- Any app on the device can attempt loopback connections; security rests on the tokens. Env vars of the
  Node child are readable by the same uid only (`/proc/<pid>/environ`), and are deleted after read.
- `LMA_DATA_KEY` lives in Node memory for the process lifetime; a memory dump with app uid reveals it.
- Mock mode (debug builds only) uses an ephemeral key and wipes `line_kv` in the mock DB; release bundles
  replace mock modules with stubs (`scripts/bundle.ts`) and `scripts/purge-mock-check.sh` verifies APKs.
- Prompt-injection detection is heuristic; the real defence is that the model has no tools and every send
  passes the policy + (by default) a human confirmation.
- `src/style/lieflat/` is CC BY-NC 4.0 (non-commercial) — license constraint, not a security issue.
- Tunnelling the MCP port to the internet (docs/connectors.md) is user-initiated and outside the app's
  control; Host/Origin checks will reject naive tunnels by design.
- Image download in `OpenAICompatProvider.generateImage` follows redirects from the provider's response URL.
- WorkManager restarts the foreground service from background; on Android 12+ this needs the battery
  optimisation exemption (user prompted in Settings).

## 8. Build & test

```
cd app
npm install
npm test                 # 30 tests, offline, no LINE login, no real AI calls
npm run typecheck
npm run android:debug    # debug APKs with mock mode
npm run android:release  # release APKs (mock purged, signed with ../keys/release.jks)
apksigner verify --print-certs <apk>
```
Run desktop: `LMA_PASSPHRASE='…' npm start` (or `LINE_MCP_MOCK=1 npm start` for offline mock data).
