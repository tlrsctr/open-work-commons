/**
 * Evaluate whether every required check has current passing evidence.
 *
 * This is the deliberately interrupted implementation. Its public contract is
 * stable, but source-session decisions remain to be implemented by the
 * benchmark participant.
 */
export function evaluatePromotionGate({ policy, evidence }) {
  const blockers = [];

  for (const checkId of policy.required_checks) {
    const candidates = evidence
      .filter(
        (item) =>
          item.check_id === checkId &&
          item.subject_digest === policy.subject_digest,
      )
      .toSorted((left, right) =>
        left.observed_at < right.observed_at
          ? 1
          : left.observed_at > right.observed_at
            ? -1
            : 0,
      );
    const latest = candidates[0];

    if (!latest) {
      blockers.push({ check_id: checkId, reason: "missing" });
    } else if (latest.result !== "passed") {
      blockers.push({ check_id: checkId, reason: latest.result });
    }
  }

  blockers.sort((left, right) =>
    left.check_id < right.check_id
      ? -1
      : left.check_id > right.check_id
        ? 1
        : 0,
  );
  return { allowed: blockers.length === 0, blockers };
}
