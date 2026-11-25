# Native package provenance snapshot

These are public verification inputs, not executable build instructions or secrets.

- Repository: https://packages.termux.dev/apt/termux-main/
- Signed snapshot date: 2026-11-25 07:12:38 UTC.
- Public-key source: https://github.com/termux/termux-packages/blob/0e0d1929ab4047ce7407d881fa1b6ff421024640/packages/termux-keyring/termux-autobuilds.gpg
- Required signer fingerprint: `CC72CF8BA7DBFA0182877D045A897D96E57CF20C`.
- Package version and hash selection: `android/native-runtime.lock.json`.

`native-runtime.py prepare` verifies the InRelease signature with an isolated GnuPG home, then verifies the compressed package indexes against the signed SHA-256 list and the selected packages against those indexes. Package maintainer scripts are never executed.

The public ICU 79.1 LICENSE and NDK r30 NOTICE.toolchain are supplementary license texts retrieved from their official, immutable source commits. Their URLs, hashes and reasons are in the lockfile's `notice_overrides`. They are not represented as part of the APT signature; their exact bytes are separately pinned and preserved in APK assets. Termux shared license texts are provided by the signed `termux-licenses` package.

This authenticates the selected binary packages to the pinned signing key. It does not certify a vulnerability-free runtime, independently reproduce the Termux builds, or establish production approval. The current OpenSSL 3.6 runtime is end of life and production packaging is blocked. See `docs/android-build.md`.
