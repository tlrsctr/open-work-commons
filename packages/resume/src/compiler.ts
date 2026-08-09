import {
  DEFAULT_VERIFIER_LIMITS,
  parseJsonSafely,
  verifyLogicalArchive,
  type ArchiveEntryDescriptor,
  type ArchiveManifest,
  type ArchiveVerificationResult,
  type Digest,
  type LogicalArchive,
  type LogicalArchiveEntry,
} from "../../archive/src/index.js";

import { renderResumeMarkdown } from "./markdown.js";
import {
  ResumeCompileError,
  type CompileResumeBundleInput,
  type MaterialOmission,
  type ResumeBundle,
  type ResumeClaim,
  type ResumeCompilation,
  type ResumeEvidence,
  type ResumeExactGitState,
  type ResumeSource,
  type SourcedStatement,
} from "./types.js";

interface Checkpoint {
  readonly checkpoint_id: string;
  readonly work: {
    readonly objective: string;
    readonly constraints: readonly string[];
  };
  readonly event_refs: readonly {
    readonly event_id: string;
    readonly path: string;
    readonly digest: Digest;
  }[];
  readonly git_state: { readonly path: string; readonly digest: Digest };
  readonly artifacts: readonly { readonly path: string }[];
  readonly claims: readonly {
    readonly claim_id: string;
    readonly statement: string;
    readonly actor_id: string;
    readonly subject_digest: Digest;
  }[];
  readonly evidence: readonly {
    readonly evidence_id: string;
    readonly kind: string;
    readonly issuer: string;
    readonly subject_digest: Digest;
    readonly result: "passed" | "failed" | "unknown";
    readonly observed_at: string;
    readonly source?: { readonly path: string; readonly digest: Digest };
  }[];
  readonly open_questions: readonly string[];
  readonly exclusions: readonly {
    readonly category: string;
    readonly reason: string;
    readonly policy: string;
  }[];
  readonly next_action: {
    readonly statement: string;
    readonly source_paths: readonly string[];
  };
}

interface NormalizedEvent {
  readonly event_type: string;
  readonly payload: {
    readonly inline?: unknown;
    readonly path?: string;
  };
}

interface GitState {
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
}

type OptionalItem =
  | { readonly id: string; readonly kind: "claim"; readonly value: ResumeClaim }
  | {
      readonly id: string;
      readonly kind: "decision";
      readonly value: SourcedStatement;
    }
  | {
      readonly id: string;
      readonly kind: "evidence";
      readonly value: ResumeEvidence;
    }
  | {
      readonly id: string;
      readonly kind: "gap";
      readonly value: SourcedStatement;
    }
  | {
      readonly id: string;
      readonly kind: "question";
      readonly value: SourcedStatement;
    };

interface DerivedArchive {
  readonly manifest: ArchiveManifest;
  readonly checkpointPath: string;
  readonly checkpointDigest: Digest;
  readonly checkpoint: Checkpoint;
  readonly git: ResumeExactGitState;
  readonly objective: SourcedStatement;
  readonly constraints: readonly SourcedStatement[];
  readonly nextAction: SourcedStatement;
  readonly exclusions: readonly {
    readonly category: string;
    readonly reason: string;
  }[];
  readonly sourcedExclusions: readonly {
    readonly category: string;
    readonly reason: string;
    readonly policy: string;
    readonly source_paths: readonly string[];
  }[];
  readonly optionalItems: readonly OptionalItem[];
  readonly policyOmission: MaterialOmission | null;
}

interface OmittedItem {
  readonly item: OptionalItem;
  readonly reason: "item-budget" | "utf8-byte-budget";
}

/**
 * Compile a bounded handoff from a cryptographically verified logical archive.
 *
 * The compiler re-verifies the exact in-memory archive before parsing any
 * captured entry. It performs no I/O, link resolution, command execution, or
 * model call.
 */
export function compileResumeBundle(
  input: CompileResumeBundleInput,
): ResumeCompilation {
  assertBudget(input.budget.maxItems, input.budget.maxUtf8Bytes);
  assertTarget(input.target);
  assertSuppliedVerification(input.verification);

  // Re-verification closes the gap where a caller supplies a successful result
  // for an archive and then substitutes or mutates entry bytes.
  const freshVerification = verifyLogicalArchive(input.archive);
  if (
    !freshVerification.integrity.valid ||
    !freshVerification.signer.signatureValid
  ) {
    throw new ResumeCompileError(
      "invalid_archive",
      "The logical archive does not pass fresh offline integrity verification.",
    );
  }
  if (!sameArchiveIdentity(input.verification, freshVerification)) {
    throw new ResumeCompileError(
      "archive_identity_mismatch",
      "The verification result does not identify the exact logical archive.",
    );
  }

  // No captured JSON is parsed before both the supplied and fresh results have
  // succeeded and their archive identities match.
  const derived = deriveVerifiedArchive(input.archive, freshVerification);
  const selected = new Set(derived.optionalItems.map((item) => item.id));
  const omitted: OmittedItem[] = [];

  while (true) {
    const materialOmissions = materialOmissionsFor(derived, omitted);
    const provisional = assembleBundle(
      derived,
      selected,
      materialOmissions,
      input,
      0,
      0,
    );
    const sources = sourceListFor(provisional, derived.manifest);
    const itemCount = countRenderedItems(provisional, sources);

    if (itemCount > input.budget.maxItems) {
      if (
        !removeLowestPriority(
          derived.optionalItems,
          selected,
          omitted,
          "item-budget",
        )
      ) {
        throw budgetTooSmall("item");
      }
      continue;
    }

    const withItems = assembleBundle(
      derived,
      selected,
      materialOmissions,
      input,
      itemCount,
      0,
      sources,
    );
    const rendered = stabilizeSerializationBytes(withItems);
    if (rendered.actualBytes > input.budget.maxUtf8Bytes) {
      if (
        !removeLowestPriority(
          derived.optionalItems,
          selected,
          omitted,
          "utf8-byte-budget",
        )
      ) {
        throw budgetTooSmall("UTF-8 byte");
      }
      continue;
    }

    if (
      rendered.actualBytes !== rendered.bundle.budget.actual_utf8_bytes ||
      rendered.jsonBytes > rendered.bundle.budget.max_utf8_bytes ||
      rendered.markdownBytes > rendered.bundle.budget.max_utf8_bytes ||
      rendered.bundle.budget.actual_items > rendered.bundle.budget.max_items
    ) {
      throw new ResumeCompileError(
        "budget_too_small",
        "The resume bundle could not be rendered inside the declared budgets.",
      );
    }

    return {
      bundle: rendered.bundle,
      json: rendered.json,
      markdown: rendered.markdown,
    };
  }
}

function assertBudget(maxItems: number, maxUtf8Bytes: number): void {
  if (!Number.isSafeInteger(maxItems) || maxItems < 1) {
    throw new ResumeCompileError(
      "invalid_budget",
      "maxItems must be a positive safe integer.",
    );
  }
  if (!Number.isSafeInteger(maxUtf8Bytes) || maxUtf8Bytes < 1) {
    throw new ResumeCompileError(
      "invalid_budget",
      "maxUtf8Bytes must be a positive safe integer.",
    );
  }
}

function assertTarget(target: string): asserts target is "codex" | "claude" {
  if (target !== "codex" && target !== "claude") {
    throw new ResumeCompileError(
      "invalid_verification",
      "Resume target must be codex or claude.",
    );
  }
}

function assertSuppliedVerification(result: ArchiveVerificationResult): void {
  if (
    !result ||
    !result.integrity.valid ||
    result.integrity.issues.length !== 0 ||
    !result.signer.signatureValid ||
    result.archive.archiveId === null ||
    result.archive.rootCheckpointId === null ||
    result.archive.payloadDigest === null ||
    result.archive.entryCount === null ||
    result.signer.keyId === null ||
    result.signer.fingerprint === null
  ) {
    throw new ResumeCompileError(
      "invalid_verification",
      "A successful archive integrity verification result is required.",
    );
  }
  if (result.signer.trust === "untrusted") {
    throw new ResumeCompileError(
      "untrusted_signer",
      "The archive signer conflicts with the configured trust anchor.",
    );
  }
  if (
    (result.signer.trust === "trusted") !== result.signer.trusted ||
    result.signer.trust === "unavailable"
  ) {
    throw new ResumeCompileError(
      "invalid_verification",
      "The signer state in the verification result is inconsistent.",
    );
  }
}

function sameArchiveIdentity(
  supplied: ArchiveVerificationResult,
  fresh: ArchiveVerificationResult,
): boolean {
  return (
    supplied.archive.archiveId === fresh.archive.archiveId &&
    supplied.archive.rootCheckpointId === fresh.archive.rootCheckpointId &&
    supplied.archive.payloadDigest === fresh.archive.payloadDigest &&
    supplied.archive.entryCount === fresh.archive.entryCount &&
    supplied.signer.keyId === fresh.signer.keyId &&
    supplied.signer.fingerprint === fresh.signer.fingerprint &&
    supplied.signer.signatureValid === fresh.signer.signatureValid
  );
}

function deriveVerifiedArchive(
  archive: LogicalArchive,
  verification: ArchiveVerificationResult,
): DerivedArchive {
  const manifest = parseVerifiedJson<ArchiveManifest>(
    archive.manifestBytes,
    "archive manifest",
  );
  if (
    manifest.archive_id !== verification.archive.archiveId ||
    manifest.signature.payload_digest !== verification.archive.payloadDigest ||
    manifest.signature.key_id !== verification.signer.keyId
  ) {
    throw new ResumeCompileError(
      "archive_identity_mismatch",
      "The parsed manifest does not match the verified archive identity.",
    );
  }

  const entries = uniqueEntryMap(archive.entries);
  const descriptorByPath = new Map(
    manifest.entries.map((descriptor) => [descriptor.path, descriptor]),
  );
  const checkpointDescriptor = requireDescriptor(
    descriptorByPath,
    manifest.root_checkpoint.path,
    "checkpoint",
  );
  const checkpoint = parseVerifiedJson<Checkpoint>(
    requireEntry(entries, checkpointDescriptor.path).bytes,
    "root checkpoint",
  );
  const gitDescriptor = requireDescriptor(
    descriptorByPath,
    checkpoint.git_state.path,
    "git-state",
  );
  const gitState = parseVerifiedJson<GitState>(
    requireEntry(entries, gitDescriptor.path).bytes,
    "Git state",
  );
  const git = copyExactGitState(gitState, gitDescriptor.path);

  const eventValues = checkpoint.event_refs.map((reference) => {
    const descriptor = requireDescriptor(
      descriptorByPath,
      reference.path,
      "event",
    );
    return {
      path: reference.path,
      event: parseVerifiedJson<NormalizedEvent>(
        requireEntry(entries, descriptor.path).bytes,
        "normalized event",
      ),
    };
  });

  const objectivePaths = uniqueSorted([
    checkpointDescriptor.path,
    ...eventValues
      .filter(
        ({ event }) => eventObjective(event) === checkpoint.work.objective,
      )
      .map(({ path }) => path),
  ]);
  const decisions = eventValues.flatMap(({ path, event }, index) => {
    const statement = explicitDecision(event);
    return statement === null
      ? []
      : [
          {
            id: `decision:${index}`,
            kind: "decision" as const,
            value: { statement, source_paths: [path] },
          },
        ];
  });
  const evidence = checkpoint.evidence.map((item, index): OptionalItem => ({
    id: `evidence:${index}`,
    kind: "evidence",
    value: {
      // This is a structural rendering of exact fields, not a summary or a
      // claim that the evidence result is true.
      statement: `evidence_id=${JSON.stringify(item.evidence_id)}; kind=${JSON.stringify(item.kind)}; issuer=${JSON.stringify(item.issuer)}; observed_at=${JSON.stringify(item.observed_at)}`,
      result: item.result,
      subject_digest: item.subject_digest,
      source_paths: uniqueSorted([
        checkpointDescriptor.path,
        ...(item.source === undefined ? [] : [item.source.path]),
      ]),
    },
  }));
  const gaps = deriveEvidenceGaps(checkpoint, checkpointDescriptor.path);
  const questions = checkpoint.open_questions.map(
    (statement, index): OptionalItem => ({
      id: `question:${index}`,
      kind: "question",
      value: { statement, source_paths: [checkpointDescriptor.path] },
    }),
  );
  const claims = checkpoint.claims.map((claim, index): OptionalItem => ({
    id: `claim:${index}`,
    kind: "claim",
    value: {
      claim_id: claim.claim_id,
      statement: claim.statement,
      actor_id: claim.actor_id,
      subject_digest: claim.subject_digest,
      source_paths: [checkpointDescriptor.path],
    },
  }));

  // Priority is left-to-right. Removal happens from the right so unsupported
  // agent claims leave the bundle before independent evidence and decisions.
  const optionalItems: readonly OptionalItem[] = [
    ...evidence,
    ...decisions,
    ...gaps,
    ...questions,
    ...claims,
  ];
  const policyOmission = derivePolicyOmission(
    checkpoint,
    manifest,
    eventValues,
  );

  return {
    manifest,
    checkpointPath: checkpointDescriptor.path,
    checkpointDigest: checkpointDescriptor.digest,
    checkpoint,
    git,
    objective: {
      statement: checkpoint.work.objective,
      source_paths: objectivePaths,
    },
    constraints: checkpoint.work.constraints.map((statement) => ({
      statement,
      source_paths: [checkpointDescriptor.path],
    })),
    nextAction: {
      statement: checkpoint.next_action.statement,
      source_paths: uniqueSorted([
        checkpointDescriptor.path,
        ...checkpoint.next_action.source_paths,
      ]),
    },
    exclusions: checkpoint.exclusions.map(({ category, reason }) => ({
      category,
      reason,
    })),
    sourcedExclusions: checkpoint.exclusions.map(
      ({ category, reason, policy }) => ({
        category,
        reason,
        policy,
        source_paths: [checkpointDescriptor.path],
      }),
    ),
    optionalItems,
    policyOmission,
  };
}

function assembleBundle(
  derived: DerivedArchive,
  selected: ReadonlySet<string>,
  materialOmissions: readonly MaterialOmission[],
  input: CompileResumeBundleInput,
  actualItems: number,
  actualUtf8Bytes: number,
  suppliedSources?: readonly ResumeSource[],
): ResumeBundle {
  const selectedOf = <K extends OptionalItem["kind"]>(kind: K) =>
    derived.optionalItems.filter(
      (item): item is Extract<OptionalItem, { kind: K }> =>
        item.kind === kind && selected.has(item.id),
    );
  const claims = selectedOf("claim").map((item) => item.value);
  const decisions = selectedOf("decision").map((item) => item.value);
  const evidence = selectedOf("evidence").map((item) => item.value);
  const gaps = selectedOf("gap").map((item) => item.value);
  const questions = selectedOf("question").map((item) => item.value);

  const withoutSources: ResumeBundle = {
    schema_version: "0.1",
    source_archive: {
      archive_id: derived.manifest.archive_id,
      payload_digest: derived.manifest.signature.payload_digest,
      signer_key_id: derived.manifest.signature.key_id,
    },
    source_checkpoint: {
      checkpoint_id: derived.checkpoint.checkpoint_id,
      path: derived.checkpointPath,
      digest: derived.checkpointDigest,
    },
    target: { provider: input.target, format: "json-and-markdown" },
    objective: derived.objective,
    constraints: derived.constraints,
    git: {
      repository_id: derived.git.repository_id,
      base_commit: derived.git.base_commit,
      head_commit: derived.git.head_commit,
      head_tree: derived.git.head_tree,
      clean: derived.git.worktree.clean,
      source_paths: derived.git.source_paths,
    },
    decisions,
    evidence,
    evidence_gaps: gaps,
    open_questions: questions,
    next_action: derived.nextAction,
    sources: suppliedSources ?? [],
    exclusions: derived.exclusions,
    budget: {
      max_items: input.budget.maxItems,
      max_utf8_bytes: input.budget.maxUtf8Bytes,
      actual_items: actualItems,
      actual_utf8_bytes: actualUtf8Bytes,
    },
    untrusted_content: {
      execution_allowed: false,
      delimiter: "OWC_UNTRUSTED_CONTENT",
    },
    extensions: {
      "openworkcommons.org/claims": claims,
      "openworkcommons.org/exact_git_state": derived.git,
      "openworkcommons.org/material_omissions": materialOmissions,
      "openworkcommons.org/exclusions": derived.sourcedExclusions,
    },
  };
  if (suppliedSources !== undefined) return withoutSources;
  return {
    ...withoutSources,
    sources: sourceListFor(withoutSources, derived.manifest),
  };
}

function sourceListFor(
  bundle: ResumeBundle,
  manifest: ArchiveManifest,
): readonly ResumeSource[] {
  const paths = new Set<string>();
  const add = (statement: SourcedStatement | ResumeEvidence | ResumeClaim) => {
    statement.source_paths.forEach((path) => paths.add(path));
  };
  add(bundle.objective);
  bundle.constraints.forEach(add);
  bundle.decisions.forEach(add);
  bundle.evidence.forEach(add);
  bundle.evidence_gaps.forEach(add);
  bundle.open_questions.forEach(add);
  add(bundle.next_action);
  bundle.extensions["openworkcommons.org/claims"].forEach(add);
  bundle.extensions["openworkcommons.org/exact_git_state"].source_paths.forEach(
    (path) => paths.add(path),
  );
  bundle.extensions["openworkcommons.org/exclusions"].forEach((item) =>
    item.source_paths.forEach((path) => paths.add(path)),
  );

  const descriptors = new Map(
    manifest.entries.map((descriptor) => [descriptor.path, descriptor]),
  );
  return [...paths].sort(compareStrings).map((path): ResumeSource => {
    const descriptor = descriptors.get(path);
    if (!descriptor) {
      throw new ResumeCompileError(
        "archive_parse_failure",
        "A cited source is absent from the verified manifest.",
      );
    }
    return {
      path,
      digest: descriptor.digest,
      label: sourceLabel(descriptor),
    };
  });
}

function sourceLabel(descriptor: ArchiveEntryDescriptor): string {
  switch (descriptor.role) {
    case "checkpoint":
      return "Root checkpoint";
    case "git-state":
      return "Exact Git state";
    case "event":
      return "Normalized session event";
    case "evidence":
      return "Evidence object";
    case "artifact":
      return "Referenced artifact";
    case "extension":
      return "Namespaced extension";
  }
}

function countRenderedItems(
  bundle: ResumeBundle,
  sources: readonly ResumeSource[],
): number {
  const git = bundle.extensions["openworkcommons.org/exact_git_state"];
  return (
    1 +
    bundle.constraints.length +
    1 +
    (git.worktree.patch === undefined ? 0 : 1) +
    git.worktree.untracked.length +
    bundle.extensions["openworkcommons.org/claims"].length +
    bundle.decisions.length +
    bundle.evidence.length +
    bundle.evidence_gaps.length +
    bundle.open_questions.length +
    bundle.exclusions.length +
    1 +
    bundle.extensions["openworkcommons.org/material_omissions"].length +
    sources.length
  );
}

function materialOmissionsFor(
  derived: DerivedArchive,
  omitted: readonly OmittedItem[],
): readonly MaterialOmission[] {
  const output: MaterialOmission[] = [];
  if (derived.policyOmission !== null) output.push(derived.policyOmission);
  if (omitted.length > 0) {
    const details: Record<string, number> = {};
    for (const { item, reason } of omitted) {
      const key = `${reason}:${item.kind}`;
      details[key] = (details[key] ?? 0) + 1;
    }
    output.push({
      category: "budgeted-items",
      count: omitted.length,
      reason: omitted.some((item) => item.reason === "utf8-byte-budget")
        ? "utf8-byte-budget"
        : "item-budget",
      details: sortedRecord(details),
    });
  }
  return output;
}

function derivePolicyOmission(
  checkpoint: Checkpoint,
  manifest: ArchiveManifest,
  events: readonly { readonly path: string; readonly event: NormalizedEvent }[],
): MaterialOmission | null {
  const referencedPaths = new Set([
    manifest.root_checkpoint.path,
    checkpoint.git_state.path,
    ...checkpoint.event_refs.map((reference) => reference.path),
    ...checkpoint.evidence.flatMap((item) =>
      item.source === undefined ? [] : [item.source.path],
    ),
    ...checkpoint.artifacts.map((artifact) => artifact.path),
  ]);
  const details: Record<string, number> = {};
  if (checkpoint.artifacts.length > 0) {
    details.artifact_payloads = checkpoint.artifacts.length;
  }
  const eventPayloads = events.filter(
    ({ event }) =>
      event.payload.inline !== undefined || event.payload.path !== undefined,
  ).length;
  if (eventPayloads > 0) details.event_payloads_not_copied = eventPayloads;
  const unselected = manifest.entries.filter(
    (descriptor) => !referencedPaths.has(descriptor.path),
  ).length;
  if (unselected > 0) details.unselected_archive_entries = unselected;
  const count = Object.values(details).reduce((sum, value) => sum + value, 0);
  return count === 0
    ? null
    : {
        category: "unparsed-content",
        count,
        reason: "policy-boundary",
        details: sortedRecord(details),
      };
}

function deriveEvidenceGaps(
  checkpoint: Checkpoint,
  checkpointPath: string,
): readonly OptionalItem[] {
  const output: OptionalItem[] = [];
  if (checkpoint.evidence.length === 0) {
    output.push({
      id: "gap:no-evidence",
      kind: "gap",
      value: {
        statement: "Checkpoint contains no evidence records.",
        source_paths: [checkpointPath],
      },
    });
  }
  checkpoint.claims.forEach((claim, index) => {
    if (
      !checkpoint.evidence.some(
        (evidence) => evidence.subject_digest === claim.subject_digest,
      )
    ) {
      output.push({
        id: `gap:uncovered-claim:${index}`,
        kind: "gap",
        value: {
          statement: `No evidence record covers claim ${JSON.stringify(claim.claim_id)} with subject ${claim.subject_digest}.`,
          source_paths: [checkpointPath],
        },
      });
    }
  });
  checkpoint.evidence.forEach((evidence, index) => {
    if (evidence.result === "unknown") {
      output.push({
        id: `gap:unknown-evidence:${index}`,
        kind: "gap",
        value: {
          statement: `Evidence ${JSON.stringify(evidence.evidence_id)} reports an unknown result for ${evidence.subject_digest}.`,
          source_paths: uniqueSorted([
            checkpointPath,
            ...(evidence.source === undefined ? [] : [evidence.source.path]),
          ]),
        },
      });
    }
  });
  return output;
}

function eventObjective(event: NormalizedEvent): string | null {
  if (event.event_type !== "session.started") return null;
  const inline = asRecord(event.payload.inline);
  return typeof inline?.objective === "string" ? inline.objective : null;
}

function explicitDecision(event: NormalizedEvent): string | null {
  if (event.event_type !== "human.intervened") return null;
  const inline = asRecord(event.payload.inline);
  return typeof inline?.decision === "string" && inline.decision.length > 0
    ? inline.decision
    : null;
}

function copyExactGitState(
  value: GitState,
  sourcePath: string,
): ResumeExactGitState {
  return {
    schema_version: "0.1",
    repository_id: value.repository_id,
    object_format: value.object_format,
    captured_at: value.captured_at,
    base_commit: value.base_commit,
    head_commit: value.head_commit,
    head_tree: value.head_tree,
    head_ref: value.head_ref,
    worktree: {
      clean: value.worktree.clean,
      ...(value.worktree.patch === undefined
        ? {}
        : {
            patch: {
              path: value.worktree.patch.path,
              digest: value.worktree.patch.digest,
              byte_length: value.worktree.patch.byte_length,
            },
          }),
      untracked: value.worktree.untracked.map((item) => ({
        path: item.path,
        included: item.included,
        digest: item.digest,
        byte_length: item.byte_length,
      })),
    },
    source_paths: [sourcePath],
  };
}

interface StabilizedSerializations {
  readonly bundle: ResumeBundle;
  readonly json: string;
  readonly markdown: string;
  readonly jsonBytes: number;
  readonly markdownBytes: number;
  readonly actualBytes: number;
}

/**
 * Resolve the byte-count fixed point shared by the JSON and Markdown outputs.
 *
 * Both complete serializations contain `actual_utf8_bytes`, so their lengths
 * depend on the decimal width of the value being measured. Starting at zero
 * and feeding the measured maximum back into the bundle reaches the unique
 * stable decimal width. The cycle check makes any future renderer change fail
 * closed instead of returning a false byte count.
 */
function stabilizeSerializationBytes(
  bundle: ResumeBundle,
): StabilizedSerializations {
  let actualBytes = 0;
  const seen = new Set<number>();
  for (let attempt = 0; attempt < 32; attempt += 1) {
    if (seen.has(actualBytes)) break;
    seen.add(actualBytes);
    const candidate: ResumeBundle = {
      ...bundle,
      budget: { ...bundle.budget, actual_utf8_bytes: actualBytes },
    };
    const json = `${JSON.stringify(candidate, null, 2)}\n`;
    const markdown = renderResumeMarkdown(candidate);
    const jsonBytes = Buffer.byteLength(json, "utf8");
    const markdownBytes = Buffer.byteLength(markdown, "utf8");
    const next = Math.max(jsonBytes, markdownBytes);
    if (next === actualBytes) {
      return {
        bundle: candidate,
        json,
        markdown,
        jsonBytes,
        markdownBytes,
        actualBytes,
      };
    }
    actualBytes = next;
  }
  throw new ResumeCompileError(
    "budget_too_small",
    "The complete JSON and Markdown UTF-8 byte count did not stabilize.",
  );
}

function removeLowestPriority(
  items: readonly OptionalItem[],
  selected: Set<string>,
  omitted: OmittedItem[],
  reason: OmittedItem["reason"],
): boolean {
  for (let index = items.length - 1; index >= 0; index -= 1) {
    const item = items[index];
    if (item && selected.delete(item.id)) {
      omitted.push({ item, reason });
      return true;
    }
  }
  return false;
}

function requireDescriptor(
  descriptors: ReadonlyMap<string, ArchiveEntryDescriptor>,
  path: string,
  role: ArchiveEntryDescriptor["role"],
): ArchiveEntryDescriptor {
  const descriptor = descriptors.get(path);
  if (!descriptor || descriptor.role !== role) {
    throw new ResumeCompileError(
      "archive_parse_failure",
      "A required verified normative entry has the wrong role or is missing.",
    );
  }
  return descriptor;
}

function requireEntry(
  entries: ReadonlyMap<string, LogicalArchiveEntry>,
  path: string,
): LogicalArchiveEntry {
  const entry = entries.get(path);
  if (!entry) {
    throw new ResumeCompileError(
      "archive_parse_failure",
      "A required verified normative entry is missing.",
    );
  }
  return entry;
}

function uniqueEntryMap(
  entries: readonly LogicalArchiveEntry[],
): ReadonlyMap<string, LogicalArchiveEntry> {
  const output = new Map<string, LogicalArchiveEntry>();
  for (const entry of entries) output.set(entry.path, entry);
  return output;
}

function parseVerifiedJson<T>(bytes: Uint8Array, label: string): T {
  try {
    const value = parseJsonSafely(bytes, {
      maxDepth: DEFAULT_VERIFIER_LIMITS.maxJsonDepth,
      maxStringBytes: DEFAULT_VERIFIER_LIMITS.maxJsonStringBytes,
    });
    if (asRecord(value) === null) throw new TypeError("not an object");
    return value as T;
  } catch {
    throw new ResumeCompileError(
      "archive_parse_failure",
      `The verified ${label} could not be parsed as bounded JSON.`,
    );
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function sortedRecord(
  source: Readonly<Record<string, number>>,
): Readonly<Record<string, number>> {
  return Object.fromEntries(
    Object.entries(source).sort(([left], [right]) =>
      compareStrings(left, right),
    ),
  );
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareStrings);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function budgetTooSmall(kind: string): ResumeCompileError {
  return new ResumeCompileError(
    "budget_too_small",
    `The ${kind} budget cannot contain the mandatory objective, constraints, exact Git state, exclusions, next action, citations, and omission report.`,
  );
}
