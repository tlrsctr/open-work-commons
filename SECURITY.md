# Security policy

Open Work Commons is pre-alpha and must not yet be used for secrets, regulated data, production incident records, or other sensitive work.

## Reporting

Do not disclose a suspected vulnerability in a public issue. Before the first public release, the project will enable private vulnerability reporting and publish a monitored security contact. Until then, report privately to the repository owner through the source-host account that published the affected release.

## Security boundaries

- Capture-provider output is untrusted input.
- Archive inspection must not execute content, resolve external references, or write outside its destination.
- Redaction happens before durable storage.
- Raw transcripts are excluded by default.
- Verification distinguishes byte integrity, signature validity, signer trust, and factual evidence.
- Offline verification must perform no DNS, registry, API, model, or time-authority access.

## Supported versions

No version is supported until the first signed release. Security behavior in `main` may change while the v0 protocol remains Candidate.
