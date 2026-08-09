import type {
  CreateSignedArchiveInput,
  Digest,
  LogicalArchive,
} from "../../archive/src/index.js";

import type { DeviceIdentityErrorCode } from "./errors.js";

export interface PublicDeviceIdentity {
  readonly format: "open-work-commons-device-identity";
  readonly schema_version: "0.1";
  readonly algorithm: "ed25519";
  readonly key_id: string;
  readonly fingerprint: Digest;
  /** Unpadded base64url encoding of the 32 raw Ed25519 public-key bytes. */
  readonly public_key: string;
  /** Unpadded base64url encoding of the DER SubjectPublicKeyInfo bytes. */
  readonly public_key_spki: string;
}

export type UnsignedArchiveInput = Omit<CreateSignedArchiveInput, "signingKey">;

/**
 * A signing capability, not an exportable key container. Implementations MUST
 * NOT expose serialized private-key bytes through this interface.
 */
export interface DeviceSigningIdentity {
  readonly publicIdentity: PublicDeviceIdentity;
  sign(payload: Uint8Array): string;
  createSignedArchive(input: UnsignedArchiveInput): LogicalArchive;
}

export type DeviceIdentityDiagnostic =
  | {
      readonly ok: true;
      readonly code: "ready";
      readonly identity: PublicDeviceIdentity;
      readonly message: "The local device identity is ready.";
    }
  | {
      readonly ok: false;
      readonly code: DeviceIdentityErrorCode;
      readonly identity: null;
      readonly message: string;
    };

export interface DeviceIdentityStore {
  open(): Promise<DeviceSigningIdentity>;
  openOrCreate(): Promise<DeviceSigningIdentity>;
  diagnose(): Promise<DeviceIdentityDiagnostic>;
}
