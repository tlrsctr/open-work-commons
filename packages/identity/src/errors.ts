export type DeviceIdentityErrorCode =
  | "not_found"
  | "unsupported_platform"
  | "unsafe_storage"
  | "unsafe_permissions"
  | "integrity_failure"
  | "identity_busy"
  | "signing_failure";

const SAFE_MESSAGES: Readonly<Record<DeviceIdentityErrorCode, string>> = {
  not_found: "The local device identity was not found.",
  unsupported_platform:
    "This local-file identity store cannot enforce its security contract on this platform.",
  unsafe_storage: "The local device identity storage layout is unsafe.",
  unsafe_permissions:
    "The local device identity storage permissions are unsafe.",
  integrity_failure: "The local device identity integrity check failed.",
  identity_busy: "Another local device identity operation is in progress.",
  signing_failure: "The local device identity could not sign the payload.",
};

/** Fixed diagnostics never include paths, key bytes, parser errors, or OS details. */
export class DeviceIdentityError extends Error {
  constructor(readonly code: DeviceIdentityErrorCode) {
    super(SAFE_MESSAGES[code]);
    this.name = "DeviceIdentityError";
  }
}

export function asSafeDeviceIdentityError(
  error: unknown,
  fallback: DeviceIdentityErrorCode,
): DeviceIdentityError {
  return error instanceof DeviceIdentityError
    ? error
    : new DeviceIdentityError(fallback);
}
