# Source-session decisions before interruption

These are visible human decisions supplied to the source agent before the interruption. They are not given directly to a baseline receiver.

1. Parse all timestamps strictly. Invalid timestamps are programmer errors and must throw `TypeError`; do not silently convert them into blockers.
2. Reject a policy with duplicate required-check identifiers using `TypeError`.
3. Evidence observed after `policy.as_of` is not current. If no non-future exact-subject observation exists, return reason `future`.
4. First select observations for the exact subject. Evidence for another subject must never displace valid evidence for this subject. If observations exist for a check but none match, return `subject_mismatch`.
5. Among exact-subject observations at or before `as_of`, use the greatest `observed_at`. If two observations share that timestamp and disagree on result, return `ambiguous`; identical duplicates are harmless.
6. Apply staleness to the selected latest observation before interpreting its result. Evidence exactly `max_age_seconds` old is current; anything older returns `stale`.
7. A current selected result maps to no blocker for `passed`, `failed` for `failed`, and `unknown` for `unknown`.
8. Return one blocker per required check and sort by UTF-16 code-unit order using ordinary JavaScript string comparison. Do not mutate or reorder caller-owned arrays.
