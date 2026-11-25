# Security Review Brief — LINE MCP Companion

Scope: Android app `tw.linemcp.app` (Kotlin/Compose UI + embedded Node 24 running LINEJS), the local
MCP server, the local control API, AI features and the anti-scam module. Version 0.2.1.
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
| MCP client (external AI) | the AI model and whatever it read | sending messages the user did not want, exfiltrating other chats | MCP whitelist + separate AI whitelist, per-chat mode, per-chat trust REVIEW by default (MCP cannot approve or promote unless the user enables it in-app), caps, active hours, kill switch, audit |
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
| 47825 | Connector gateway (cloud MCP clients; **off by default**, `connector_enabled`) — `/mcp` (Streamable HTTP), legacy `GET /sse` + `POST /messages`, OAuth endpoints, `/.well-known/*` | OAuth 2.1 access token (scope `line.read` / `line.send`) **or** the static MCP token (`connector_allow_static`, **default on** — see §7) | 120 req/min, 10 send-tool calls/min, 30 auth-endpoint req/min, body ≤ 256 KB, headers timeout 10 s; Host must equal the configured public URL host or loopback (else 403, anti DNS-rebinding); Origin allow-list (chatgpt.com, chat.openai.com, claude.ai, grok.com, gemini.google.com, Inspector on :6274) |

The gateway is reached from the internet only through a user-started HTTPS tunnel (`src/mcp/tunnel.ts`
spawns `cloudflared tunnel --url http://127.0.0.1:47825` when the binary exists — desktop only; Android has
no cloudflared, so Tailscale Funnel / ngrok / a reverse proxy is the user's choice). The quick-tunnel URL is
written into `connector_public_url` automatically. Public URL must be bare `https://host`.

Egress: link reading (§5.9, per chat, default off); LINE servers (via LINEJS, HTTPS); the configured AI base URL (must be `https`, or `http` only for
loopback; no credentials in URL); `stickershop.line-scdn.net` for sticker images (numeric id only,
≤ 512 KB, cached; mock mode generates images locally). Android `network_security_config` blocks
cleartext except 127.0.0.1 (applies to the Kotlin side; Node enforces its own URL validation).

## 5. Permission gates (send path)

Every outgoing message goes through `Outbox` (`src/ai/outbox.ts`) and the real sender requires a
send permit (`withSendPermit`); LINEJS send methods called outside it are blocked by the upstream guard.

`AiPolicy.checkBasic` (`src/ai/policy.ts`), in order: kill switch → AI master switch → chat in MCP
whitelist → chat in AI whitelist → mode ≠ off → image permission. `checkSend` adds active hours, min
interval, hourly cap (skipped only when the user approves in the queue) and always per-chat and global
daily caps. `needsConfirmation` = mode ≠ auto OR trust = REVIEW OR any risk flag.

### 5.1 Per-chat trust state machine (t235u)

Two independent states per chat: `ai` (AI 代聊, column `chat_ai.confirm_send`) and `scam` (scam
warnings, column `scam_warn.trust`). Each is `REVIEW` (default) or `AUTO`.

| From → To | Who may do it | Notes |
| --- | --- | --- |
| REVIEW → AUTO | user in the app (per-chat chips); MCP `set_chat_trust` **only** with `confirm_auto: true` **and** the in-app toggle 「允許 MCP 升級到自動」 (`mcp_allow_promote`, default OFF) | chat must be in the whitelist(s) |
| AUTO → REVIEW | always: 總控台 「降回審核」 per chat, 「全部降回審核」, per-chat settings, MCP `set_chat_trust` (never gated) | |
| any → REVIEW (system) | kill switch ON (`demoteAll`), chat removed from the AI whitelist | logged with actor `system` |

REVIEW: every AI reply and every scam warning is created as `pending` in the confirm queue; the user can
edit text / sticker / template, then approve or reject. AUTO: sends without confirmation, but caps,
cooldowns, active hours, the kill switch and risk flags (forced confirmation) still apply. Every change is
written to `trust_log` (chat, feature, from, to, actor ui|mcp|system, reason, time) and shown in 總控台
(「信任狀態」) and per chat; it is also mirrored into the audit log.

### 5.2 MCP review tools (t236u)

`list_pending`, `edit_pending`, `reject_pending` — always allowed for whitelisted chats.
`approve_pending` — only when the in-app toggle 「允許 MCP 核准佇列」 (`mcp_allow_approve`, default OFF) is
on; otherwise a connector could approve its own drafts and bypass REVIEW. `get_chat_trust`,
`set_chat_trust` (see 5.1). Approve / set_trust / compose count toward the send-tool rate limit
(10/min). All MCP actions are audited with actor `mcp`.

### 5.3 Anti-scam warnings

Warnings follow the `scam` trust state (REVIEW by default — queued; AUTO only after the user promotes).
Gates: kill switch, MCP whitelist, per-sender+category cooldown (30 min, pending items count), one
warning per message, per-group daily cap (10), trusted-member whitelist, audit log. Warnings never quote
the scam text; nicknames are sanitised; LINE banned words are replaced.

Custom / connector-written warning text (`compose_scam_warning`, queue edit, 寫提醒 dialog) passes
`checkCustomWarning` (`src/scam/warner.ts`): ≤ 300 chars; rejects any link (http/www/line.me/lin.ee or
any `name.tld`), LINE IDs (`line id …`, `@…digits`), and any run of ≥ 10 normalised characters copied
from the scam message; then `scrubNotice` (banned words). Built-in templates/samples are reference only.

Trusted members (per group, `scam_member`): never trigger warnings; the detection is still recorded in the
audit log once as `suppressed_member`. 「誤判→信任此人」 on an alert marks it false positive, cancels a
queued warning and trusts the sender (UI or MCP `mark_scam_false_positive`; `trust_scam_member` edits the list).

MCP `add_scam_sample` can only add `SCAM` samples (cannot whitelist a pattern via OK samples).

### 5.4 Audit logs (t237u)

`scam_log` (chat, sender id + name, time, message id, text snapshot, category, rule, action:
alert_only / queued / scheduled / sent / rejected / suppressed_member / cooldown / daily_cap / …) and
`ai_log` (trigger message who/what, generated reply, edits, approve/reject, sent time, failures). Sender
names, message snapshots and reply texts are **encrypted at rest** with the same AES-256-GCM data key
(`src/storage/event-log.ts`, AAD bound to table/chat/message/field); rule names, categories and actions are
plaintext. Retention `log_retention_days` (default 30, 1–365) pruned hourly; 「清除紀錄」 deletes with
`secure_delete` + WAL checkpoint. CSV export (UI via SAF, control API `?format=csv`, MCP
`get_scam_log`/`get_ai_log`) decrypts on the device; cells are formula-injection guarded (`=+-@` prefixed
with `'`). Exported CSV is plaintext — user's responsibility once shared.

### 5.5 Hidden / removed messages (t238u, t239u)

Messages shown as 「此訊息已被隱藏。」 (admin-hidden, reported, deleted, unsent) are detected by exact text,
LINEJS talk ops `NOTIFIED_DESTROY_MESSAGE` / `DESTROY_MESSAGE`, and (helper `src/sync/square-events.ts`)
Square message state DELETED/FORBIDDEN/UNSENT or `CONTENTS_HIDDEN`. They are flagged `message.hidden`,
never used as AI context or trigger, never replied to, their text is withheld from MCP reads, and any
pending/scheduled reply targeting one is cancelled. Per user instruction they are **not logged at all**
(silent skip). Limitation: Square (OpenChat) sync is not wired in this build, so the Square path is
unit-tested only.

### 5.6 AI provider and de-identification (t241u)

Built-in AI = any OpenAI-compatible Chat Completions endpoint (base URL / model / key) plus an optional
fallback chain (tried in order on error). `max_tokens_field` handles providers that need
`max_completion_tokens` (OpenAI) vs `max_tokens` (others; auto-retry once on a 400 naming the field).
Loopback base URLs (e.g. llama-server) need no key. De-identification (`ai_deidentify`, default ON, applied
only to non-loopback URLs; port of anti-scam-helper `chat-training.mjs`, Apache-2.0): member names → 成員A…,
phone numbers, e-mails, LINE IDs, URLs (except the 165 anti-fraud site), national ID, bank account and address patterns are masked before sending; names are restored in
the reply. Also applied to the optional LLM scam judge.

### 5.7 Connector OAuth 2.1 (t239u) — `src/mcp/oauth.ts`, `src/mcp/gateway.ts`

- Metadata: RFC 8414 (`/.well-known/oauth-authorization-server`), RFC 9728 protected-resource metadata (root
  and `/mcp` suffix), `WWW-Authenticate: Bearer resource_metadata=…` on 401, RFC 9207 `iss` in redirects.
- DCR (RFC 7591): redirect URIs https or http-loopback only, ≤ 5; auth methods `none` /
  `client_secret_post` / `client_secret_basic`; ≤ 20 registrations/hour, capped client count; names sanitised.
- Authorization: code + **PKCE S256 required**, `resource` (RFC 8707) checked against our base, codes 5 min,
  one-time. The consent page requires the **6-digit pairing code shown only inside the app** (10-min TTL,
  renewable, timing-safe compare; 5 wrong ⇒ 60 s lock-out; counter survives code rotation). The user picks
  scope: `line.read` only, or also `line.send` (checkbox, default off).
- Tokens: random, stored as SHA-256 hashes only; access 1 h, refresh 30 d with **rotation and reuse
  detection** (reusing a rotated refresh token revokes the whole family). Revocation endpoint (RFC 7009) and
  per-client revoke in the app (設定 → 雲端連接器). Scope down-grade on refresh only.
- `line.read` ⇒ the MCP server for that request registers read-only tools only (`READ_ONLY_TOOLS`);
  `line.send` adds write tools, which still pass every in-app gate (whitelists, trust state, caps, kill switch,
  `mcp_allow_approve`, `mcp_allow_promote`). Tool annotations (`readOnlyHint`/`destructiveHint`/
  `openWorldHint`) and per-tool `securitySchemes` are set so ChatGPT asks the user before writes.
- ChatGPT-style `search` / `fetch` are aliases over whitelisted messages (`line-mcp://chat/<id>/<msg>` ids).

### 5.8 Digests 日報 (t244u, t245u) — `src/storage/digests.ts`, `src/ai/digest-post.ts`

- Written back by connectors (`save_digest`) or generated by the in-app AI (`AiService.generateDigest`).
  Validation: every `source_message_id` must exist **in that chat** (or `chat:msg` for cross-chat digests),
  every referenced chat must be whitelisted, hidden messages are dropped as sources, timestamps are taken
  from the DB (caller-supplied times ignored), period sanity, ≤ 30 items, title/headline/body stripped of
  HTML / control / bidi characters and length-capped. Title + items are **AES-256-GCM encrypted** (`body_enc`,
  AAD bound to the row); `chats`, period, source label, counts are plaintext for filtering.
- MCP `list_digests` / `get_digest` hide digests that touch any non-whitelisted chat; `delete_digest`.
- In-app generation sends message lines with `#n` references (not real ids), applies de-identification
  for cloud providers, tells the model the messages are data not instructions, and maps `#n` back; unknown
  refs are dropped.
- **Posting** (`post_digest` MCP tool, 📤 button, daily schedule): always through `Outbox.enqueue` with origin
  `digest` → kill switch, AI master switch, target in MCP whitelist **and** AI whitelist, mode ≠ off, caps,
  min interval, active hours. Confirmation follows the target chat's **AI trust state only** (`trustOnly`):
  REVIEW ⇒ pending in the confirm queue; AUTO ⇒ scheduled after the delay. Rendered text has **all URLs
  replaced by ［連結］** and LINE IDs masked (so a digest of a scam conversation can't re-broadcast the scam
  link), LINE banned words scrubbed, ≤ 1500 chars. `post_digest` is in the send-rate bucket and needs scope
  `line.send` on the gateway; MCP can only post digests it can see (whitelist).
- Schedules (`digest_schedule`, ≤ 10): target and source chats must be whitelisted at save time; the
  per-minute tick (Asia/Taipei) runs each schedule at most once per day (`last_run_day` written *before*
  posting), skips digests touching chats no longer whitelisted, and optionally generates missing digests with
  the in-app AI (only when the built-in driver has a key). Skips / failures are audited.

### 5.9 Link reading (t245u) — `src/links/reader.ts`

Per-chat toggle `link_read:<chat>` (**default off**; 聊天 AI 設定 → 讀取連結). Used by MCP `read_link`,
the 🔗 button in the chat view, and digest generation (titles only, ≤ 5 URLs, marked untrusted). Pipeline —
any failure returns `blocked: <reason>` and **nothing is fetched**:

1. Static rules: http/https only, ≤ 2048 chars, no userinfo, ports 80/443/8080/8443 only, no bare hostnames,
   LINE invite / add-friend links (line.me, lin.ee), built-in + user (`link_blocklist`) scam domains, IP
   literals must be public, anti-scam text score ≥ 6 on the URL (mainstream sites exempt).
2. DNS: all resolved addresses must be public (blocks loopback, RFC1918, link-local/metadata 169.254/16,
   CGNAT, 0/8, benchmarking 198.18/15, TEST-NETs, multicast/reserved, ::1, ULA fc00::/7, fe80::/10,
   NAT64, IPv4-mapped/compatible forms decoded and re-checked). The connection is made to **the checked IP**
   (custom `lookup`), TLS SNI/cert still use the hostname ⇒ no DNS-rebinding TOCTOU.
3. Redirects followed manually, ≤ 3 hops, every hop re-runs 1–2. Known shorteners are expanded with HEAD.
4. Optional Google Safe Browsing v4 for the whole chain (`LMA_SAFE_BROWSING_KEY`, in memory only); an
   unreachable API fails open (noted in the result), a match blocks.
5. Fetch: GET, no cookies sent or stored, `accept-encoding: identity`, 8 s timeout, 512 KB cap (truncated),
   only `text/html`, `text/plain`, `application/xhtml+xml`. No JS: HTML is regex-stripped (script, style,
   iframe, object, form, svg, … removed, entities decoded with `<`/`>` neutralised, control/bidi chars
   removed); output = title ≤ 200, description ≤ 400, text ≤ 4000 chars + `injection_flags` + an
   "UNTRUSTED web content" note. 1-hour in-memory cache (200 entries).
6. `read_link` requires the chat whitelisted + toggle on; hidden messages are refused; calls are audited
   (count + block reasons, not URLs).

Note: networks whose resolver returns fake-IP answers (198.18.0.0/15, e.g. some VPN/proxy apps) make every
lookup look private, so link reading fails closed there (this is what the dev box does).
Mock builds swap in fixed offline responses (`MOCK_LINK_PAGES`) — no network.

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
kill switch, stickers, injection, connector mode, scam rules/warnings/mentions, trust state machine,
MCP review tools + permission toggles, custom warning checks, trusted members / false positive, encrypted
logs + CSV + retention, hidden messages, de-identification, fallback chain, max-tokens retry, digests
save/validate/encrypt/list/delete + AI generation, digest posting + schedules, `read_link` gating),
`test/links.test.ts` (IP classification, static blocks, local fake server: shortener expansion, redirect to
scam domain / metadata IP / private DNS, mixed public+private DNS, NXDOMAIN, redirect loop, content type,
size cap, no cookies, cache), `test/connector.test.ts` (Host/Origin, DCR, PKCE, pairing code + lock-out,
consent, token/refresh rotation + reuse revocation, scope ⇒ tool set, SSE).

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
- Tunnelling the gateway (47825) to the internet is user-initiated. The MCP port 47823 itself still rejects
  non-loopback Host. **Static token on the gateway defaults ON** (`connector_allow_static`) for clients
  without OAuth (xAI API remote MCP, Inspector); anyone holding the token over the tunnel gets full
  read + send tools — reviewer: consider default OFF.
- A quick-tunnel URL is public and unauthenticated at the edge; the only gates are OAuth / static token
  plus the pairing code at consent. Pairing code is 6 digits (lock-out 60 s after 5 tries ⇒ ~7,200 guesses/day max).
- OAuth consent page and pairing code display are HTML/Compose only; no CSRF token beyond the one-time
  nonce bound to the pending authorization (reviewer: check `completeConsent`).
- Link reader: HTML is parsed with regexes (output is plain text only and never rendered as HTML, so a
  parser bypass yields at most odd text). Safe Browsing fails open when unreachable. `useOffline()` exists in
  release code but is only called from the mock path (stripped in release).
- Digests: a connector with `line.send` + an AUTO-trust target can post digest text it wrote itself (URLs
  stripped, caps apply). Cross-chat digests can move summaries of chat A into group B — intended, but a
  privacy consideration; schedules show source chats explicitly.
- Image download in `OpenAICompatProvider.generateImage` follows redirects from the provider's response URL.
- WorkManager restarts the foreground service from background; on Android 12+ this needs the battery
  optimisation exemption (user prompted in Settings).

## 8. Build & test

```
cd app
npm install
npm test                 # 47 tests, offline, no LINE login, no real AI calls
npm run typecheck
npm run android:debug    # debug APKs with mock mode
npm run android:release  # release APKs (mock purged, signed with ../keys/release.jks)
apksigner verify --print-certs <apk>
```
Run desktop: `LMA_PASSPHRASE='…' npm start` (or `LINE_MCP_MOCK=1 npm start` for offline mock data).
