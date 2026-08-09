const V0_ARCHIVE_PATH = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

/** Matches the v0 schema and the stricter RFC-002 path invariants. */
export function isSafeArchivePath(path: unknown): path is string {
  if (typeof path !== "string" || path.length < 1 || path.length > 1024) {
    return false;
  }
  if (!V0_ARCHIVE_PATH.test(path)) return false;
  const segments = path.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}
