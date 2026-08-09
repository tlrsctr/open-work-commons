const V0_ARCHIVE_PATH = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

export function isSafeArchivePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1024) {
    return false;
  }
  if (!V0_ARCHIVE_PATH.test(value)) return false;
  return value
    .split("/")
    .every(
      (segment) => segment.length > 0 && segment !== "." && segment !== "..",
    );
}
