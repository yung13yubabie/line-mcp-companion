# Third-party notices

This project (Apache-2.0) uses or adapts the following works. Each entry lists what was used,
where it lives in this repository, what was changed, and the license terms.

---

## LINEJS (`@evex-dev/linejs`)

- Source: https://github.com/evex-dev/linejs
- Use: npm dependency (unmodified) — LINE protocol client (login, sync, send, E2EE).
- License: MIT

```
MIT License

Copyright (c) 2024-2026 Evex Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## line-mcp-server

- Source: https://github.com/stickerdaniel/line-mcp-server (Apache License 2.0; the upstream repository has no NOTICE file)
- Use: design reference only — the read-receipt guard and E2EE key-registration guard in
  `src/guard/upstream-guard.ts` follow the same boundaries described in its `docs/architecture.md`.
  No source files were copied.
- License: Apache-2.0 — https://www.apache.org/licenses/LICENSE-2.0

---

## anti-scam-helper (mars-tw)

- Source: https://github.com/mars-tw/anti-scam-helper
- License: Apache-2.0 — https://www.apache.org/licenses/LICENSE-2.0
- Files derived from it (modified, per Apache-2.0 §4(b)):
  - `src/scam/rules.ts` — from `guard/rules.mjs` and `guard/notify-rules.mjs`: text / link / LINE-ID scoring
    rules, URL-shortener list, mainstream-domain list, warning-tone and "is this a scam?" exclusions,
    anti-bypass rule (warning words + link still count). Ported to TypeScript; removed kick / admin-name /
    exchange-phishing / file-scan logic that needs group-admin rights or external lists; thresholds re-tuned
    for alert-only use; added category mapping and one-line tips.
  - `src/scam/samples.default.json` — the example corpus from `guard/scam-patterns.example.json`
    (categories and OK counter-examples), unchanged text, used as the built-in, user-extendable sample table.
  - `src/ai/deidentify.ts` — `deidentify()` from `guard/chat-training.mjs`: member names → 成員A/B…, and
    masking of e-mail, URLs (165 anti-fraud site kept), national ID, mobile / landline numbers, bank account,
    LINE ID, @ID and address patterns before text goes to a non-local LLM. Ported to TypeScript; added
    `reidentify()` to restore names in the model reply.
  - `src/scam/warner.ts` — `scrubNotice`, `safeName`, `stripMentions` from `guard/notice.mjs`, and the notice
    behaviour (quote-reply the scam message, never quote scam text, at most 3 mentions, retry without
    mentions if mentioning fails). Ported to TypeScript; new template format without agent labels.
- Upstream sources cited by the sample corpus: Taiwan CIB / NPA 165 announcements (see the JSON file).

---

## claude-skill-social-post (Hao0321)

- Source: https://github.com/Hao0321/claude-skill-social-post
- Use: writing modes, voice card, priority order, evidence and platform rules summarised into prompts in
  `src/style/social-post/` (see `src/style/social-post/NOTICE.md`). Draft-only: this app never publishes.
- License: MIT

```
MIT License

Copyright (c) 2026 Hao0321 contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Lieflat Less AI Tone (去AI味) — shiujan

- Source: https://github.com/larashero3-dotcom/lieflat-less-ai-tone
- Use: adapted detection rules and rewrite principles in `src/style/lieflat/` (see `src/style/lieflat/NOTICE.md`
  for the list of changes).
- License: **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** —
  https://creativecommons.org/licenses/by-nc/4.0/
- **This directory is not covered by this project's Apache-2.0 license. Non-commercial use only.**
  For commercial use obtain a license from the author (https://lieflat.work/skills/less-ai-tone/#pricing)
  or remove the module (delete `src/style/lieflat/` and its entry in `src/style/registry.ts`; the
  per-chat "去 AI 味" switch then disappears). The author does not endorse this project.

---

## Other npm dependencies

Runtime dependencies such as `@modelcontextprotocol/sdk` (MIT) and `zod` (MIT) keep their own licenses;
see `node_modules/*/LICENSE`. Android dependencies (AndroidX, Jetpack Compose, ZXing core) are Apache-2.0.
Node.js (`libnode.so`, built from source) is MIT with bundled third-party licenses listed in the Node.js
`LICENSE` file.
