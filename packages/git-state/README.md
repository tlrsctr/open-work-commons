# Exact local Git-state capture

This package captures the v0 Git-state object without fetching, contacting a remote, running hooks, or requiring a configured remote.

`verifyExternalGitState` independently re-captures a local repository using the declared `captured_at`, `base_commit`, `repository_id`, and uniform untracked inclusion policy, then compares the capture serialization plus tracked-patch and untracked commitments.

Its result is intentionally bounded to `matched`, `mismatched`, or `unavailable` plus a fixed reason code; it never returns a local path, Git diagnostic, patch byte, or file byte.

`captureGitState` requires an explicit capture timestamp and an injected command runner.

The caller must complete authorization and redaction before invoking capture because even manifest-only untracked entries bind file bytes through their digest.

The included Node runner invokes only local Git plumbing and porcelain commands, clears repository-redirecting Git environment variables, suppresses system and global Git configuration and attributes, disables replacement objects, external diff helpers, text conversion, pagers, and optional index locks, and applies output and time limits.

Capture inspects the remaining effective repository configuration before status or diff and fails closed if any clean, smudge, or process filter command is configured, so hostile repository filters are never invoked by the reference capture path.

Git does not provide an atomic transaction spanning configuration inspection and worktree observation; a same-privilege process can race that check, which remains a residual local-host risk despite the two-observation consistency test.

External verification inherits that residual race and reports any drift detected between its two complete observations as unavailable rather than guessing whether the declared state matches.

Mixed per-file inclusion is valid archive vocabulary but is not emitted by the v0 capture implementation, so the external verifier fails closed with `declared_state_unsupported` rather than silently broadening it to the all-files inclusion mode.

Repository identity defaults to a SHA-256 digest of the sorted root-commit set reachable from `HEAD`, namespaced by the Git object format; callers may instead supply a stable repository identifier.

Tracked index and worktree changes are emitted as one binary artifact with the magic `OWC-GIT-PATCH\0`, version byte `1`, and two length-prefixed sections named `index.diff` and `worktree.diff`.

Each section contains exact `git diff --binary --full-index` output, so binary changes are not coerced through UTF-8.

Untracked paths come only from `git ls-files --others --exclude-standard -z`, are restricted to the archive-safe v0 path profile, sorted by UTF-8 bytes, opened without following a final symlink, and always bound by digest and byte length.

Manifest-only rows retain that byte commitment with `included: false` and no artifact reference; explicit inclusion adds a matching reference at `artifacts/git/untracked/<repository-path>` while preserving the original repository-relative path as a separate identity.

Ignored files never enter the manifest or returned artifacts.

The capture uses two complete observations and fails if their state, status, patches, or untracked bytes differ.

This narrows but cannot eliminate filesystem races because Git does not provide an atomic worktree snapshot.

Shallow histories require an explicit stable repository identifier because deepening them could change the default root-derived identity.

Submodule worktrees, unmerged indexes, and assume-unchanged or skip-worktree entries fail closed in v0 because their nested, conflicted, or deliberately hidden bytes cannot be represented exactly by the current schema.
