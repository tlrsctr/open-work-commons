# Contributing

Open Work Commons accepts contributions that improve people's ability to capture, move, inspect, verify, and continue their work without depending on one vendor.

## Before opening a change

1. Read [AGENTS.md](AGENTS.md) and the applicable RFCs.
2. Open or reference an issue that states the observable outcome and compatibility impact.
3. Keep protocol changes separate from reference-implementation changes.
4. Add or update conformance fixtures when normative behavior changes.
5. Run `pnpm check` from a clean checkout.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign each commit with `git commit -s` to certify that you have the right to submit the work under this repository's license. Contributors retain their copyright. The project does not require copyright assignment or a blanket contributor agreement that permits unilateral proprietary relicensing.

## Privacy and provenance

Never contribute real transcripts, credentials, private repositories, personal data, hidden chain-of-thought, or customer artifacts. Use synthetic fixtures. Every imported third-party file must preserve its license and attribution.

## Compatibility

A change to a Stable protocol profile requires a versioned migration and conformance evidence. Until two independent implementations pass a profile, it remains Draft or Candidate and must not be advertised as a stable standard.
