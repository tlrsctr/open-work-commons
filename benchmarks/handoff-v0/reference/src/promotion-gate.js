const CORE_RESULTS = new Set(["passed", "failed", "unknown"]);
const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** Custodian reference implementation; never copy this into a participant run. */
export function evaluatePromotionGate({ policy, evidence }) {
  validatePolicy(policy);
  const observations = evidence.map((item) => validateEvidence(item));
  const asOf = parseTimestamp(policy.as_of);
  const blockers = [];

  for (const checkId of policy.required_checks) {
    const forCheck = observations.filter((item) => item.check_id === checkId);
    const forSubject = forCheck.filter(
      (item) => item.subject_digest === policy.subject_digest,
    );
    if (forSubject.length === 0) {
      blockers.push({
        check_id: checkId,
        reason: forCheck.length === 0 ? "missing" : "subject_mismatch",
      });
      continue;
    }

    const currentOrPast = forSubject.filter(
      (item) => item.observed_epoch <= asOf,
    );
    if (currentOrPast.length === 0) {
      blockers.push({ check_id: checkId, reason: "future" });
      continue;
    }

    const latestEpoch = Math.max(
      ...currentOrPast.map((item) => item.observed_epoch),
    );
    const latestResults = new Set(
      currentOrPast
        .filter((item) => item.observed_epoch === latestEpoch)
        .map((item) => item.result),
    );
    if (latestResults.size !== 1) {
      blockers.push({ check_id: checkId, reason: "ambiguous" });
      continue;
    }
    if ((asOf - latestEpoch) / 1000 > policy.max_age_seconds) {
      blockers.push({ check_id: checkId, reason: "stale" });
      continue;
    }

    const [result] = latestResults;
    if (result !== "passed") {
      blockers.push({ check_id: checkId, reason: result });
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

function validatePolicy(policy) {
  if (
    typeof policy !== "object" ||
    policy === null ||
    typeof policy.subject_digest !== "string" ||
    !Array.isArray(policy.required_checks) ||
    !Number.isFinite(policy.max_age_seconds) ||
    policy.max_age_seconds < 0
  ) {
    throw new TypeError("Invalid policy.");
  }
  parseTimestamp(policy.as_of);
  const identifiers = new Set();
  for (const checkId of policy.required_checks) {
    if (typeof checkId !== "string" || checkId.length === 0) {
      throw new TypeError("Invalid required check identifier.");
    }
    if (identifiers.has(checkId)) {
      throw new TypeError("Duplicate required check identifier.");
    }
    identifiers.add(checkId);
  }
}

function validateEvidence(item) {
  if (
    typeof item !== "object" ||
    item === null ||
    typeof item.check_id !== "string" ||
    typeof item.subject_digest !== "string" ||
    !CORE_RESULTS.has(item.result)
  ) {
    throw new TypeError("Invalid evidence.");
  }
  return { ...item, observed_epoch: parseTimestamp(item.observed_at) };
}

function parseTimestamp(value) {
  if (typeof value !== "string") throw new TypeError("Invalid timestamp.");
  const match = TIMESTAMP.exec(value);
  if (!match) throw new TypeError("Invalid timestamp.");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = Number(match[8] ?? 0);
  const offsetMinute = Number(match[9] ?? 0);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new TypeError("Invalid timestamp.");
  }
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) throw new TypeError("Invalid timestamp.");
  return epoch;
}

function daysInMonth(year, month) {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
