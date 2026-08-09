export type LocalStoreErrorCode =
  | "invalid_workspace"
  | "unsupported_platform"
  | "unsupported_store"
  | "policy_denied"
  | "policy_failure"
  | "invalid_input"
  | "resource_limit"
  | "conflict"
  | "not_found"
  | "integrity_failure"
  | "store_busy";

const SAFE_MESSAGES: Readonly<Record<LocalStoreErrorCode, string>> = {
  invalid_workspace: "The local workspace store is invalid.",
  unsupported_platform:
    "This local workspace store cannot enforce its security contract on this platform.",
  unsupported_store: "The local workspace store version is unsupported.",
  policy_denied: "The local policy denied the operation.",
  policy_failure: "The local policy could not authorize the operation.",
  invalid_input: "The local store input is invalid.",
  resource_limit: "The local store resource limit was exceeded.",
  conflict: "The immutable local store contains a conflicting object.",
  not_found: "The requested local store object was not found.",
  integrity_failure: "The local store integrity check failed.",
  store_busy: "The local workspace store is locked by another writer.",
};

/** Diagnostics are deliberately fixed and never interpolate captured content. */
export class LocalStoreError extends Error {
  constructor(readonly code: LocalStoreErrorCode) {
    super(SAFE_MESSAGES[code]);
    this.name = "LocalStoreError";
  }
}

export function asSafeStoreError(
  error: unknown,
  fallback: LocalStoreErrorCode,
): LocalStoreError {
  return error instanceof LocalStoreError
    ? error
    : new LocalStoreError(fallback);
}
