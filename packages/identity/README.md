# OWC local device identity

This package provides the v0 Ed25519 device-signing identity as a capability rather than an exportable private-key container.

`LocalFileDeviceIdentityStore` creates or opens exactly one identity beneath a caller-supplied private directory, returns public metadata plus signing and archive-construction methods, and never returns serialized private-key bytes.

The reference layout is `device/identity.json`, `device/private-key.pk8`, and `device/public-key.spki`; both directories use POSIX mode `0700`, all files use `0600`, and every path is rejected if it is a symlink, hard link, special entry, owned by another user, or has a weaker mode.

Creation serializes cooperating writers with an exclusive owner-only lock, writes a complete same-parent staging directory using exclusive files, flushes every file and directory, and renames the completed directory into place without replacing an existing identity.

Opening derives the public key from the PKCS#8 private key, compares it byte-for-byte with the stored DER SPKI key, recomputes the raw public key, fingerprint, key identifier, and complete canonical metadata record, and fails closed on any mismatch.

Diagnostics expose only fixed codes, fixed messages, and validated public identity fields; they never expose paths, parser details, OS errors, or private bytes.

The local-file adapter intentionally refuses platforms where its POSIX owner and mode contract cannot be enforced.

Operating-system keychain integration is a future identity-store adapter; key rotation history, recovery, and revocation are outside v0 and require future adapters and protocol work.

Run this slice with `pnpm exec prettier --check "packages/identity/**/*.{ts,md}"`, `pnpm exec tsc --noEmit`, and `pnpm exec tsx --test "packages/identity/**/*.test.ts"`.
