import type { KeyObject } from "node:crypto";

export type ArchiveEntryRole =
  "event" | "git-state" | "checkpoint" | "artifact" | "evidence" | "extension";

export type Digest = `sha256:${string}`;

export interface ArchiveEntryDescriptor {
  readonly path: string;
  readonly media_type: string;
  readonly role: ArchiveEntryRole;
  readonly byte_length: number;
  readonly digest: Digest;
  readonly required_for_verification?: boolean;
}

export interface ArchiveExclusion {
  readonly category: string;
  readonly reason: string;
  readonly policy: string;
}

export interface ArchiveDeclaredLimits {
  readonly entry_count: number;
  readonly expanded_bytes: number;
  readonly max_entry_bytes: number;
}

export interface ArchiveManifest {
  readonly format: "open-work-commons-portable-archive";
  readonly schema_version: "0.1";
  readonly archive_id: string;
  readonly created_at: string;
  readonly root_checkpoint: {
    readonly checkpoint_id: string;
    readonly path: string;
    readonly digest: Digest;
  };
  readonly entries: readonly ArchiveEntryDescriptor[];
  readonly exclusions: readonly ArchiveExclusion[];
  readonly limits: ArchiveDeclaredLimits;
  readonly signature: {
    readonly canonicalization: "RFC8785";
    readonly digest_algorithm: "sha256";
    readonly signature_algorithm: "ed25519";
    readonly key_id: string;
    readonly public_key: string;
    readonly payload_digest: Digest;
    readonly value: string;
  };
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/**
 * A logical file is already in memory. Verification never extracts, opens, or
 * executes it. `kind` exists so packed-container adapters can preserve special
 * entry metadata and have this verifier reject it before inspecting bytes.
 */
export interface LogicalArchiveEntry {
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly kind?: string;
}

/** An unpacked logical archive. `archive-manifest.json` is kept out of entries. */
export interface LogicalArchive {
  readonly manifestBytes: Uint8Array;
  readonly entries: readonly LogicalArchiveEntry[];
}

interface ArchiveEntryInputBase {
  readonly path: string;
  readonly mediaType: string;
  readonly role: ArchiveEntryRole;
  readonly requiredForVerification?: boolean;
}

export interface ArchiveBytesEntryInput extends ArchiveEntryInputBase {
  readonly bytes: Uint8Array;
  readonly json?: never;
}

export interface ArchiveJsonEntryInput extends ArchiveEntryInputBase {
  readonly json: unknown;
  readonly bytes?: never;
}

export type ArchiveEntryInput = ArchiveBytesEntryInput | ArchiveJsonEntryInput;

export interface CreateSignedArchiveInput {
  readonly archiveId: string;
  readonly createdAt: string;
  readonly rootCheckpoint: {
    readonly checkpointId: string;
    readonly path: string;
  };
  readonly entries: readonly ArchiveEntryInput[];
  readonly exclusions: readonly ArchiveExclusion[];
  readonly signingKey: {
    readonly keyId: string;
    readonly privateKey: KeyObject;
  };
  readonly limits?: ArchiveDeclaredLimits;
  readonly extensions?: Readonly<Record<string, unknown>>;
}

export interface GeneratedSigningKey {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly publicKeyBase64Url: string;
  readonly fingerprint: Digest;
}

export interface VerifierLimits {
  readonly maxManifestBytes: number;
  readonly maxEntryCount: number;
  readonly maxExpandedBytes: number;
  readonly maxEntryBytes: number;
  readonly maxJsonDepth: number;
  readonly maxJsonStringBytes: number;
}

export type VerificationIssueCode =
  | "invalid_archive"
  | "manifest_too_large"
  | "manifest_json_invalid"
  | "manifest_duplicate_json_key"
  | "manifest_schema_invalid"
  | "unsupported_archive_version"
  | "unsafe_path"
  | "duplicate_path"
  | "special_entry"
  | "missing_entry"
  | "unlisted_entry"
  | "entry_count_limit"
  | "expanded_bytes_limit"
  | "entry_bytes_limit"
  | "declared_limit_invalid"
  | "entry_length_mismatch"
  | "entry_digest_mismatch"
  | "payload_digest_mismatch"
  | "signature_invalid"
  | "entry_json_invalid"
  | "entry_schema_invalid"
  | "reference_missing"
  | "reference_digest_mismatch"
  | "reference_identity_mismatch"
  | "checkpoint_cycle";

export interface VerificationIssue {
  readonly code: VerificationIssueCode;
  /** A structural location or already-validated safe archive path. */
  readonly location: string;
  /** A fixed diagnostic that never contains captured payload text. */
  readonly message: string;
}

export interface VerifyArchiveOptions {
  readonly trustedSignerFingerprints?: readonly string[];
  readonly limits?: Partial<VerifierLimits>;
}

export type ExternalRepositoryVerification =
  | { readonly status: "not-checked" }
  | {
      readonly status: "matched";
      readonly reason: "exact_git_state_match";
    }
  | {
      readonly status: "mismatched";
      readonly reason:
        | "git_state_mismatch"
        | "tracked_patch_mismatch"
        | "untracked_manifest_mismatch";
    }
  | {
      readonly status: "unavailable";
      readonly reason:
        | "declared_base_unavailable"
        | "declared_state_unavailable"
        | "declared_state_unsupported"
        | "git_output_ambiguous"
        | "git_unavailable"
        | "repository_changed"
        | "repository_state_unsupported"
        | "repository_unavailable"
        | "verification_limit_exceeded";
    };

export interface ArchiveVerificationResult {
  readonly integrity: {
    readonly valid: boolean;
    readonly issues: readonly VerificationIssue[];
  };
  readonly signer: {
    readonly keyId: string | null;
    readonly fingerprint: Digest | null;
    readonly signatureValid: boolean;
    readonly trust: "trusted" | "untrusted" | "not-configured" | "unavailable";
    readonly trusted: boolean;
  };
  readonly archive: {
    readonly archiveId: string | null;
    readonly rootCheckpointId: string | null;
    readonly payloadDigest: Digest | null;
    readonly entryCount: number | null;
  };
  /** Independent local observation; never contributes to archive integrity. */
  readonly externalRepositoryVerification: ExternalRepositoryVerification;
}

export class ArchiveInputError extends Error {
  constructor(
    readonly code: VerificationIssueCode,
    message: string,
  ) {
    super(message);
    this.name = "ArchiveInputError";
  }
}
