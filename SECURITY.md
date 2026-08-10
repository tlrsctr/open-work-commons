# Security policy

Open Work Commons is pre-alpha and must not yet be used for secrets, regulated data, production incident records, or other sensitive work.

## Reporting

Do not disclose a suspected vulnerability in a public issue. Use GitHub's **Security → Advisories → Report a vulnerability** flow in the canonical repository so the report reaches its maintainers privately. If that interface is unavailable, contact the repository owner privately through the source-host account; do not include exploit details in a public issue or discussion.

## Security boundaries

- Capture-provider output is untrusted input.
- Archive inspection must not execute content, resolve external references, or write outside its destination.
- Redaction happens before durable storage.
- Raw transcripts are excluded by default.
- Verification distinguishes byte integrity, signature validity, signer trust, and factual evidence.
- Offline verification must perform no DNS, registry, API, model, or time-authority access.

## Supported versions

No version is supported until the first signed release. Security behavior in `main` may change while the v0 protocol remains Candidate.
