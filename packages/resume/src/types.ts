import type {
  ArchiveVerificationResult,
  Digest,
  LogicalArchive,
} from "../../archive/src/index.js";

export type ResumeTarget = "codex" | "claude";

export interface ResumeBudgetInput {
  readonly maxItems: number;
  readonly maxUtf8Bytes: number;
}

export interface CompileResumeBundleInput {
  readonly archive: LogicalArchive;
  readonly verification: ArchiveVerificationResult;
  readonly target: ResumeTarget;
  readonly budget: ResumeBudgetInput;
}

export interface ResumeSource {
  readonly path: string;
  readonly digest: Digest;
  readonly label: string;
}

export interface SourcedStatement {
  readonly statement: string;
  readonly source_paths: readonly string[];
}

export interface ResumeEvidence {
  readonly statement: string;
  readonly result: "passed" | "failed" | "unknown";
  readonly subject_digest: Digest;
  readonly source_paths: readonly string[];
}

export interface ResumeClaim extends SourcedStatement {
  readonly claim_id: string;
  readonly actor_id: string;
  readonly subject_digest: Digest;
}

export interface ResumeExactGitState {
  readonly schema_version: "0.1";
  readonly repository_id: string;
  readonly object_format: "sha1" | "sha256";
  readonly captured_at: string;
  readonly base_commit: string;
  readonly head_commit: string;
  readonly head_tree: string;
  readonly head_ref: string | null;
  readonly worktree: {
    readonly clean: boolean;
    readonly patch?: {
      readonly path: string;
      readonly digest: Digest;
      readonly byte_length: number;
    };
    readonly untracked: readonly {
      readonly path: string;
      readonly included: boolean;
      readonly digest: Digest | null;
      readonly byte_length: number | null;
    }[];
  };
  readonly source_paths: readonly string[];
}

export interface MaterialOmission {
  readonly category: "unparsed-content" | "budgeted-items";
  readonly count: number;
  readonly reason: "policy-boundary" | "item-budget" | "utf8-byte-budget";
  readonly details: Readonly<Record<string, number>>;
}

export interface ResumeBundleExtensions {
  readonly "openworkcommons.org/claims": readonly ResumeClaim[];
  readonly "openworkcommons.org/exact_git_state": ResumeExactGitState;
  readonly "openworkcommons.org/material_omissions": readonly MaterialOmission[];
  readonly "openworkcommons.org/exclusions": readonly {
    readonly category: string;
    readonly reason: string;
    readonly policy: string;
    readonly source_paths: readonly string[];
  }[];
}

/** Provider-neutral JSON object matching the v0 resume schema plus v0 extensions. */
export interface ResumeBundle {
  readonly schema_version: "0.1";
  readonly source_archive: {
    readonly archive_id: string;
    readonly payload_digest: Digest;
    readonly signer_key_id: string;
  };
  readonly source_checkpoint: {
    readonly checkpoint_id: string;
    readonly path: string;
    readonly digest: Digest;
  };
  readonly target: {
    readonly provider: ResumeTarget;
    readonly format: "json-and-markdown";
  };
  readonly objective: SourcedStatement;
  readonly constraints: readonly SourcedStatement[];
  readonly git: {
    readonly repository_id: string;
    readonly base_commit: string;
    readonly head_commit: string;
    readonly head_tree: string;
    readonly clean: boolean;
    readonly source_paths: readonly string[];
  };
  readonly decisions: readonly SourcedStatement[];
  readonly evidence: readonly ResumeEvidence[];
  readonly evidence_gaps: readonly SourcedStatement[];
  readonly open_questions: readonly SourcedStatement[];
  readonly next_action: SourcedStatement;
  readonly sources: readonly ResumeSource[];
  readonly exclusions: readonly {
    readonly category: string;
    readonly reason: string;
  }[];
  readonly budget: {
    readonly max_items: number;
    /** Shared cap for each complete serialization returned by the compiler. */
    readonly max_utf8_bytes: number;
    readonly actual_items: number;
    /** Maximum of the complete JSON and Markdown UTF-8 byte lengths. */
    readonly actual_utf8_bytes: number;
  };
  readonly untrusted_content: {
    readonly execution_allowed: false;
    readonly delimiter: "OWC_UNTRUSTED_CONTENT";
  };
  readonly extensions: ResumeBundleExtensions;
}

export interface ResumeCompilation {
  readonly bundle: ResumeBundle;
  /** Stable two-space JSON with a trailing newline. */
  readonly json: string;
  /** Prompt-facing derivative with a trailing newline. */
  readonly markdown: string;
}

export type ResumeCompileErrorCode =
  | "invalid_budget"
  | "invalid_verification"
  | "untrusted_signer"
  | "invalid_archive"
  | "archive_identity_mismatch"
  | "archive_parse_failure"
  | "budget_too_small";

export class ResumeCompileError extends Error {
  constructor(
    readonly code: ResumeCompileErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ResumeCompileError";
  }
}
