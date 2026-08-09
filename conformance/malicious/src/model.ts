export type LogicalMemberKind =
  | "file"
  | "symlink"
  | "hard-link"
  | "directory"
  | "fifo"
  | "socket"
  | "block-device"
  | "character-device";

export interface LogicalMember {
  readonly logicalPath: string;
  readonly kind: LogicalMemberKind;
  readonly bytes: Uint8Array;
}

export interface LogicalArchive {
  readonly manifestBytes: Uint8Array;
  readonly members: readonly LogicalMember[];
  readonly trustAnchors: ReadonlySet<string>;
}

export interface OracleLimits {
  readonly maxPackedBytes: number;
  readonly maxExpandedBytes: number;
  readonly maxEntryCount: number;
  readonly maxEntryBytes: number;
  readonly maxJsonDepth: number;
  readonly maxJsonStringBytes: number;
}

export const defaultOracleLimits: OracleLimits = {
  maxPackedBytes: 16 * 1024 * 1024,
  maxExpandedBytes: 16 * 1024 * 1024,
  maxEntryCount: 1024,
  maxEntryBytes: 8 * 1024 * 1024,
  maxJsonDepth: 128,
  maxJsonStringBytes: 8 * 1024 * 1024,
};

export type FailureCategory =
  | "duplicate-json-key"
  | "invalid-json"
  | "invalid-schema"
  | "unsafe-path"
  | "duplicate-manifest-path"
  | "duplicate-logical-path"
  | "unsafe-entry-kind"
  | "missing-entry"
  | "entry-byte-length"
  | "entry-digest"
  | "signature-payload-digest"
  | "signature-invalid"
  | "untrusted-signer"
  | "root-checkpoint-digest"
  | "root-checkpoint-identity"
  | "reference-missing"
  | "reference-digest"
  | "checkpoint-parent-missing"
  | "checkpoint-parent-cycle"
  | "git-state-substitution"
  | "evidence-source-substitution"
  | "evidence-identity-substitution"
  | "resource-packed-bytes"
  | "resource-expanded-bytes"
  | "resource-entry-count"
  | "resource-entry-bytes"
  | "resource-json-depth"
  | "resource-json-string";

export class CorpusFailure extends Error {
  constructor(
    readonly category: FailureCategory,
    readonly affectedObject: string,
  ) {
    super(failureMessages[category]);
    this.name = "CorpusFailure";
  }
}

const failureMessages: Readonly<Record<FailureCategory, string>> = {
  "duplicate-json-key": "A JSON object contains a duplicate key.",
  "invalid-json": "A signed JSON object is invalid.",
  "invalid-schema": "A signed JSON object does not satisfy its schema.",
  "unsafe-path": "An archive path is unsafe.",
  "duplicate-manifest-path": "A manifest path is duplicated.",
  "duplicate-logical-path": "A logical container path is duplicated.",
  "unsafe-entry-kind": "A logical container member is not a regular file.",
  "missing-entry": "A listed archive entry is missing.",
  "entry-byte-length": "A listed entry has an unexpected byte length.",
  "entry-digest": "A listed entry has an unexpected digest.",
  "signature-payload-digest": "The signing projection digest is invalid.",
  "signature-invalid": "The manifest signature is invalid.",
  "untrusted-signer": "The valid manifest signer is not trusted.",
  "root-checkpoint-digest": "The root checkpoint digest is inconsistent.",
  "root-checkpoint-identity": "The root checkpoint identity is inconsistent.",
  "reference-missing": "A signed object reference is missing.",
  "reference-digest": "A signed object reference is inconsistent.",
  "checkpoint-parent-missing": "A checkpoint parent is missing.",
  "checkpoint-parent-cycle": "The checkpoint parent graph is cyclic.",
  "git-state-substitution": "The Git-state reference is inconsistent.",
  "evidence-source-substitution": "An evidence source is inconsistent.",
  "evidence-identity-substitution": "An evidence identity is inconsistent.",
  "resource-packed-bytes": "The archive exceeds the packed-byte limit.",
  "resource-expanded-bytes": "The archive exceeds the expanded-byte limit.",
  "resource-entry-count": "The archive exceeds the entry-count limit.",
  "resource-entry-bytes": "An archive entry exceeds its byte limit.",
  "resource-json-depth": "A JSON object exceeds the nesting limit.",
  "resource-json-string": "A JSON string exceeds its byte limit.",
};

export interface OracleSuccess {
  readonly integrityValid: true;
  readonly signerTrusted: true;
  readonly verifiedEntries: readonly string[];
  readonly resumeEligibleEntries: readonly string[];
  readonly ignoredEntryCount: number;
  readonly untrustedContent: readonly {
    readonly source: string;
    readonly value: string;
    readonly executionAllowed: false;
  }[];
}

export interface MutationVector {
  readonly id: string;
  readonly archive: LogicalArchive;
  readonly limits?: OracleLimits;
  readonly expected:
    | {
        readonly outcome: "failure";
        readonly category: FailureCategory;
        readonly affectedObject: string;
      }
    | {
        readonly outcome: "success";
        readonly ignoredEntryCount: number;
      };
  readonly hostileText?: readonly string[];
}
