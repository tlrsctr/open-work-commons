# Minimal valid v0 fixture

This directory represents one unpacked logical archive plus a derived resume bundle.

`archive-manifest.json` signs the event, Git state, and checkpoint entries; `resume/resume-bundle.json` is deliberately outside the signed entry list because it cites the archive payload digest and is produced only after verification.

The published resume JSON is the exact stable reference-compiler serialization: 4,158 UTF-8 bytes with SHA-256 `b8b3df7574d27750eb8f8d55a5f2eeadc535323ebadbfe7eed5ac8b8cddf2fb3`. Its corresponding Markdown serialization is 3,674 bytes with SHA-256 `889767e9a060cd185cb0f0e5921daec71c0a3b9f3736dda38cb8765a6e1c8b53`, so the bundle records 4,158 as `actual_utf8_bytes`.

The embedded Ed25519 key is a disposable fixture identity and MUST NOT be trusted for real work.

The expected result is schema-valid, digest-valid, signature-valid, internally complete, and signer-untrusted unless the fixture key identifier is supplied explicitly as a test trust anchor.
