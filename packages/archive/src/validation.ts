import { canonicalJsonBytes } from "./canonical-json.js";
import { sha256 } from "./crypto.js";
import { isSafeArchivePath } from "./path.js";
import type { ArchiveManifest, Digest } from "./types.js";

const CORE_EVENT_TYPES = new Set([
  "session.started",
  "context.declared",
  "tool.observed",
  "artifact.changed",
  "evidence.observed",
  "human.intervened",
  "checkpoint.requested",
  "session.ended",
]);
const EXTENSION_EVENT_TYPE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/;

export interface SchemaProblem {
  readonly location: string;
  readonly message: string;
}

export interface ValidatedEvent {
  readonly eventId: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly previousEventId: string | null;
  readonly payloadPath: string | null;
  readonly payloadDigest: Digest;
  readonly inlinePayload: unknown;
}

export interface PathDigestReference {
  readonly path: string;
  readonly digest: Digest;
}

export interface ValidatedEvidence {
  readonly evidenceId: string;
  readonly kind: string;
  readonly issuer: string;
  readonly subjectDigest: Digest;
  readonly result: "passed" | "failed" | "unknown";
  readonly observedAt: string;
}

export interface ValidatedCheckpointEvidence extends ValidatedEvidence {
  readonly source: PathDigestReference | null;
}

export interface ValidatedCheckpoint {
  readonly checkpointId: string;
  readonly sessionId: string;
  readonly parents: readonly (PathDigestReference & {
    readonly checkpointId: string;
  })[];
  readonly eventRefs: readonly (PathDigestReference & {
    readonly eventId: string;
  })[];
  readonly gitState: PathDigestReference;
  readonly artifactRefs: readonly (PathDigestReference & {
    readonly byteLength: number;
  })[];
  readonly evidence: readonly ValidatedCheckpointEvidence[];
  readonly nextActionSourcePaths: readonly string[];
}

export interface ValidatedGitState {
  readonly patch:
    (PathDigestReference & { readonly byteLength: number }) | null;
  readonly includedUntracked: readonly {
    readonly repositoryPath: string;
    readonly artifact: PathDigestReference & { readonly byteLength: number };
  }[];
}

const UNTRACKED_ARTIFACT_PREFIX = "artifacts/git/untracked/";

export function validateManifest(value: unknown): {
  readonly value: ArchiveManifest | null;
  readonly problems: readonly SchemaProblem[];
  readonly unsupportedVersion: boolean;
} {
  const problems: SchemaProblem[] = [];
  const root = record(value, "$", problems);
  if (!root) return { value: null, problems, unsupportedVersion: false };

  exactKeys(
    root,
    [
      "format",
      "schema_version",
      "archive_id",
      "created_at",
      "root_checkpoint",
      "entries",
      "exclusions",
      "limits",
      "signature",
    ],
    ["extensions"],
    "$",
    problems,
  );
  constant(
    root.format,
    "open-work-commons-portable-archive",
    "$.format",
    problems,
  );
  const unsupportedVersion = root.schema_version !== "0.1";
  constant(root.schema_version, "0.1", "$.schema_version", problems);
  boundedString(root.archive_id, 1, 512, "$.archive_id", problems);
  dateTime(root.created_at, "$.created_at", problems);

  const rootCheckpoint = record(
    root.root_checkpoint,
    "$.root_checkpoint",
    problems,
  );
  if (rootCheckpoint) {
    exactKeys(
      rootCheckpoint,
      ["checkpoint_id", "path", "digest"],
      [],
      "$.root_checkpoint",
      problems,
    );
    boundedString(
      rootCheckpoint.checkpoint_id,
      1,
      512,
      "$.root_checkpoint.checkpoint_id",
      problems,
    );
    safePath(rootCheckpoint.path, "$.root_checkpoint.path", problems);
    digest(rootCheckpoint.digest, "$.root_checkpoint.digest", problems);
  }

  if (!Array.isArray(root.entries) || root.entries.length < 3) {
    problem("$.entries", problems);
  } else {
    let previousPath: string | null = null;
    root.entries.forEach((candidate, index) => {
      const location = `$.entries[${index}]`;
      const entry = record(candidate, location, problems);
      if (!entry) return;
      exactKeys(
        entry,
        ["path", "media_type", "role", "byte_length", "digest"],
        ["required_for_verification"],
        location,
        problems,
      );
      safePath(entry.path, `${location}.path`, problems);
      boundedString(
        entry.media_type,
        1,
        256,
        `${location}.media_type`,
        problems,
      );
      enumeration(
        entry.role,
        [
          "event",
          "git-state",
          "checkpoint",
          "artifact",
          "evidence",
          "extension",
        ],
        `${location}.role`,
        problems,
      );
      nonNegativeInteger(
        entry.byte_length,
        `${location}.byte_length`,
        problems,
      );
      digest(entry.digest, `${location}.digest`, problems);
      if (
        "required_for_verification" in entry &&
        typeof entry.required_for_verification !== "boolean"
      ) {
        problem(`${location}.required_for_verification`, problems);
      }
      if (entry.path === "archive-manifest.json") {
        problem(`${location}.path`, problems);
      }
      if (typeof entry.path === "string") {
        if (previousPath !== null && previousPath > entry.path) {
          problem("$.entries", problems);
        }
        previousPath = entry.path;
      }
    });
  }

  if (!Array.isArray(root.exclusions) || root.exclusions.length < 1) {
    problem("$.exclusions", problems);
  } else {
    root.exclusions.forEach((candidate, index) => {
      validateExclusion(candidate, `$.exclusions[${index}]`, problems);
    });
    if (
      !root.exclusions.some((candidate) => {
        const item = isRecord(candidate) ? candidate : null;
        return (
          item &&
          typeof item.category === "string" &&
          /^raw[-_ ]?transcripts?$/i.test(item.category)
        );
      })
    ) {
      problem("$.exclusions", problems);
    }
  }

  const limits = record(root.limits, "$.limits", problems);
  if (limits) {
    exactKeys(
      limits,
      ["entry_count", "expanded_bytes", "max_entry_bytes"],
      [],
      "$.limits",
      problems,
    );
    positiveInteger(limits.entry_count, "$.limits.entry_count", problems);
    nonNegativeInteger(
      limits.expanded_bytes,
      "$.limits.expanded_bytes",
      problems,
    );
    nonNegativeInteger(
      limits.max_entry_bytes,
      "$.limits.max_entry_bytes",
      problems,
    );
  }

  const signature = record(root.signature, "$.signature", problems);
  if (signature) {
    exactKeys(
      signature,
      [
        "canonicalization",
        "digest_algorithm",
        "signature_algorithm",
        "key_id",
        "public_key",
        "payload_digest",
        "value",
      ],
      [],
      "$.signature",
      problems,
    );
    constant(
      signature.canonicalization,
      "RFC8785",
      "$.signature.canonicalization",
      problems,
    );
    constant(
      signature.digest_algorithm,
      "sha256",
      "$.signature.digest_algorithm",
      problems,
    );
    constant(
      signature.signature_algorithm,
      "ed25519",
      "$.signature.signature_algorithm",
      problems,
    );
    boundedString(signature.key_id, 1, 512, "$.signature.key_id", problems);
    patternString(
      signature.public_key,
      /^[A-Za-z0-9_-]{43}$/,
      "$.signature.public_key",
      problems,
    );
    digest(signature.payload_digest, "$.signature.payload_digest", problems);
    patternString(
      signature.value,
      /^[A-Za-z0-9_-]{86}$/,
      "$.signature.value",
      problems,
    );
  }

  if ("extensions" in root) {
    validateExtensions(root.extensions, "$.extensions", problems);
  }

  return {
    value: problems.length === 0 ? (root as unknown as ArchiveManifest) : null,
    problems,
    unsupportedVersion,
  };
}

export function validateEvent(
  value: unknown,
  location: string,
): {
  readonly value: ValidatedEvent | null;
  readonly problems: readonly SchemaProblem[];
} {
  const problems: SchemaProblem[] = [];
  const root = record(value, location, problems);
  if (!root) return { value: null, problems };
  exactKeys(
    root,
    [
      "schema_version",
      "event_id",
      "event_type",
      "recorded_at",
      "actor",
      "space_id",
      "session_id",
      "sequence",
      "previous_event_id",
      "provider",
      "subject",
      "payload",
      "sensitivity",
      "retention",
    ],
    ["effective_at", "extensions"],
    location,
    problems,
  );
  constant(root.schema_version, "0.1", `${location}.schema_version`, problems);
  patternString(
    root.event_id,
    /^urn:owc:event:[A-Za-z0-9._:-]+$/,
    `${location}.event_id`,
    problems,
    512,
  );
  validateEventType(root.event_type, `${location}.event_type`, problems);
  dateTime(root.recorded_at, `${location}.recorded_at`, problems);
  if ("effective_at" in root && root.effective_at !== null)
    dateTime(root.effective_at, `${location}.effective_at`, problems);
  boundedString(root.space_id, 1, 512, `${location}.space_id`, problems);
  boundedString(root.session_id, 1, 512, `${location}.session_id`, problems);
  nonNegativeInteger(root.sequence, `${location}.sequence`, problems);
  if (root.previous_event_id !== null)
    patternString(
      root.previous_event_id,
      /^urn:owc:event:[A-Za-z0-9._:-]+$/,
      `${location}.previous_event_id`,
      problems,
      512,
    );
  if (root.sequence === 0 && root.previous_event_id !== null)
    problem(`${location}.previous_event_id`, problems);
  if (
    typeof root.sequence === "number" &&
    root.sequence > 0 &&
    typeof root.previous_event_id !== "string"
  )
    problem(`${location}.previous_event_id`, problems);

  const actor = record(root.actor, `${location}.actor`, problems);
  if (actor) {
    exactKeys(
      actor,
      ["id", "kind"],
      ["display_name"],
      `${location}.actor`,
      problems,
    );
    boundedString(actor.id, 1, 512, `${location}.actor.id`, problems);
    enumeration(
      actor.kind,
      ["human", "agent", "service", "device"],
      `${location}.actor.kind`,
      problems,
    );
    if ("display_name" in actor)
      boundedString(
        actor.display_name,
        1,
        256,
        `${location}.actor.display_name`,
        problems,
      );
  }
  validateProvider(root.provider, `${location}.provider`, problems);
  const subject = record(root.subject, `${location}.subject`, problems);
  if (subject) {
    exactKeys(subject, ["kind", "id"], [], `${location}.subject`, problems);
    patternString(
      subject.kind,
      /^[a-z][a-z0-9._-]{0,127}$/,
      `${location}.subject.kind`,
      problems,
    );
    boundedString(subject.id, 1, 512, `${location}.subject.id`, problems);
  }

  let payloadPath: string | null = null;
  let inlinePayload: unknown = undefined;
  let payloadDigest: Digest | null = null;
  const payload = record(root.payload, `${location}.payload`, problems);
  if (payload) {
    exactKeys(
      payload,
      ["media_type", "digest"],
      ["inline", "path"],
      `${location}.payload`,
      problems,
    );
    boundedString(
      payload.media_type,
      1,
      256,
      `${location}.payload.media_type`,
      problems,
    );
    digest(payload.digest, `${location}.payload.digest`, problems);
    const hasInline = "inline" in payload;
    const hasPath = "path" in payload;
    if (hasInline === hasPath) problem(`${location}.payload`, problems);
    if (hasPath) {
      safePath(payload.path, `${location}.payload.path`, problems);
      if (typeof payload.path === "string") payloadPath = payload.path;
    }
    if (hasInline) {
      inlinePayload = payload.inline;
      try {
        if (
          typeof payload.digest === "string" &&
          sha256(canonicalJsonBytes(payload.inline)) !== payload.digest
        ) {
          problem(`${location}.payload.digest`, problems);
        }
      } catch {
        problem(`${location}.payload.inline`, problems);
      }
    }
    if (isDigest(payload.digest)) payloadDigest = payload.digest;
  }
  enumeration(
    root.sensitivity,
    ["public", "internal", "private", "restricted"],
    `${location}.sensitivity`,
    problems,
  );
  validateRetention(root.retention, `${location}.retention`, problems);
  if ("extensions" in root)
    validateExtensions(root.extensions, `${location}.extensions`, problems);

  const valid =
    problems.length === 0 &&
    typeof root.event_id === "string" &&
    typeof root.session_id === "string" &&
    typeof root.sequence === "number" &&
    (typeof root.previous_event_id === "string" ||
      root.previous_event_id === null) &&
    payloadDigest !== null;
  return {
    value: valid
      ? {
          eventId: root.event_id as string,
          sessionId: root.session_id as string,
          sequence: root.sequence as number,
          previousEventId: root.previous_event_id as string | null,
          payloadPath,
          payloadDigest: payloadDigest as Digest,
          inlinePayload,
        }
      : null,
    problems,
  };
}

export function validateGitState(
  value: unknown,
  location: string,
): {
  readonly value: ValidatedGitState | null;
  readonly problems: readonly SchemaProblem[];
} {
  const problems: SchemaProblem[] = [];
  const root = record(value, location, problems);
  if (!root) return { value: null, problems };
  exactKeys(
    root,
    [
      "schema_version",
      "repository_id",
      "object_format",
      "captured_at",
      "base_commit",
      "head_commit",
      "head_tree",
      "head_ref",
      "worktree",
    ],
    ["extensions"],
    location,
    problems,
  );
  constant(root.schema_version, "0.1", `${location}.schema_version`, problems);
  boundedString(
    root.repository_id,
    1,
    512,
    `${location}.repository_id`,
    problems,
  );
  enumeration(
    root.object_format,
    ["sha1", "sha256"],
    `${location}.object_format`,
    problems,
  );
  dateTime(root.captured_at, `${location}.captured_at`, problems);
  const oidPattern =
    root.object_format === "sha256" ? /^[a-f0-9]{64}$/ : /^[a-f0-9]{40}$/;
  patternString(
    root.base_commit,
    oidPattern,
    `${location}.base_commit`,
    problems,
  );
  patternString(
    root.head_commit,
    oidPattern,
    `${location}.head_commit`,
    problems,
  );
  patternString(root.head_tree, oidPattern, `${location}.head_tree`, problems);
  if (root.head_ref !== null)
    boundedString(root.head_ref, 1, 1024, `${location}.head_ref`, problems);

  let patch: ValidatedGitState["patch"] = null;
  const includedUntracked: Array<{
    repositoryPath: string;
    artifact: PathDigestReference & { byteLength: number };
  }> = [];
  const worktree = record(root.worktree, `${location}.worktree`, problems);
  if (worktree) {
    exactKeys(
      worktree,
      ["clean", "untracked"],
      ["patch"],
      `${location}.worktree`,
      problems,
    );
    if (typeof worktree.clean !== "boolean")
      problem(`${location}.worktree.clean`, problems);
    if ("patch" in worktree) {
      const parsed = validateByteReference(
        worktree.patch,
        `${location}.worktree.patch`,
        problems,
      );
      if (parsed) patch = parsed;
    }
    if (!Array.isArray(worktree.untracked)) {
      problem(`${location}.worktree.untracked`, problems);
    } else {
      let previousPath: string | null = null;
      worktree.untracked.forEach((candidate, index) => {
        const itemLocation = `${location}.worktree.untracked[${index}]`;
        const item = record(candidate, itemLocation, problems);
        if (!item) return;
        exactKeys(
          item,
          ["path", "included", "digest", "byte_length"],
          ["artifact"],
          itemLocation,
          problems,
        );
        safePath(item.path, `${itemLocation}.path`, problems);
        digest(item.digest, `${itemLocation}.digest`, problems);
        nonNegativeInteger(
          item.byte_length,
          `${itemLocation}.byte_length`,
          problems,
        );
        if (typeof item.path === "string") {
          if (previousPath !== null && previousPath >= item.path) {
            problem(`${location}.worktree.untracked`, problems);
          }
          previousPath = item.path;
        }
        if (typeof item.included !== "boolean") {
          problem(`${itemLocation}.included`, problems);
        } else if (item.included) {
          if (!("artifact" in item)) {
            problem(`${itemLocation}.artifact`, problems);
            return;
          }
          const artifact = validateByteReference(
            item.artifact,
            `${itemLocation}.artifact`,
            problems,
          );
          if (
            artifact &&
            typeof item.path === "string" &&
            isDigest(item.digest) &&
            typeof item.byte_length === "number" &&
            Number.isSafeInteger(item.byte_length)
          ) {
            if (
              artifact.path !== `${UNTRACKED_ARTIFACT_PREFIX}${item.path}` ||
              artifact.digest !== item.digest ||
              artifact.byteLength !== item.byte_length
            ) {
              problem(`${itemLocation}.artifact`, problems);
              return;
            }
            includedUntracked.push({
              repositoryPath: item.path,
              artifact,
            });
          }
        } else if ("artifact" in item) {
          problem(`${itemLocation}.artifact`, problems);
        }
      });
    }
    if (typeof worktree.clean === "boolean") {
      const hasRepresentedChanges =
        "patch" in worktree ||
        (Array.isArray(worktree.untracked) && worktree.untracked.length > 0);
      if (worktree.clean === hasRepresentedChanges) {
        problem(`${location}.worktree.clean`, problems);
      }
    }
  }
  if ("extensions" in root)
    validateExtensions(root.extensions, `${location}.extensions`, problems);
  return {
    value: problems.length === 0 ? { patch, includedUntracked } : null,
    problems,
  };
}

export function validateCheckpoint(
  value: unknown,
  location: string,
): {
  readonly value: ValidatedCheckpoint | null;
  readonly problems: readonly SchemaProblem[];
} {
  const problems: SchemaProblem[] = [];
  const root = record(value, location, problems);
  if (!root) return { value: null, problems };
  exactKeys(
    root,
    [
      "schema_version",
      "checkpoint_id",
      "created_at",
      "session_id",
      "capture_providers",
      "work",
      "parents",
      "event_refs",
      "git_state",
      "artifacts",
      "claims",
      "evidence",
      "open_questions",
      "exclusions",
      "next_action",
    ],
    ["extensions"],
    location,
    problems,
  );
  constant(root.schema_version, "0.1", `${location}.schema_version`, problems);
  boundedString(
    root.checkpoint_id,
    1,
    512,
    `${location}.checkpoint_id`,
    problems,
  );
  dateTime(root.created_at, `${location}.created_at`, problems);
  boundedString(root.session_id, 1, 512, `${location}.session_id`, problems);

  if (
    !Array.isArray(root.capture_providers) ||
    root.capture_providers.length < 1
  ) {
    problem(`${location}.capture_providers`, problems);
  } else
    root.capture_providers.forEach((provider, index) =>
      validateProvider(
        provider,
        `${location}.capture_providers[${index}]`,
        problems,
        true,
      ),
    );
  validateWork(root.work, `${location}.work`, problems);

  const parents = validateCheckpointRefs(
    root.parents,
    `${location}.parents`,
    problems,
    false,
  );
  const eventRefs = validateEventRefs(
    root.event_refs,
    `${location}.event_refs`,
    problems,
  );
  const gitState = validatePathDigest(
    root.git_state,
    `${location}.git_state`,
    problems,
  );
  const artifactRefs: Array<PathDigestReference & { byteLength: number }> = [];
  if (!Array.isArray(root.artifacts))
    problem(`${location}.artifacts`, problems);
  else
    root.artifacts.forEach((candidate, index) => {
      const itemLocation = `${location}.artifacts[${index}]`;
      const item = record(candidate, itemLocation, problems);
      if (!item) return;
      exactKeys(
        item,
        ["path", "digest", "media_type", "role", "byte_length"],
        [],
        itemLocation,
        problems,
      );
      const reference = validatePathDigest(item, itemLocation, problems, [
        "media_type",
        "role",
        "byte_length",
      ]);
      boundedString(
        item.media_type,
        1,
        256,
        `${itemLocation}.media_type`,
        problems,
      );
      boundedString(item.role, 1, 128, `${itemLocation}.role`, problems);
      nonNegativeInteger(
        item.byte_length,
        `${itemLocation}.byte_length`,
        problems,
      );
      if (reference && typeof item.byte_length === "number")
        artifactRefs.push({ ...reference, byteLength: item.byte_length });
    });
  validateClaims(root.claims, `${location}.claims`, problems);
  const evidence = validateEvidence(
    root.evidence,
    `${location}.evidence`,
    problems,
  );
  validateStringArray(
    root.open_questions,
    `${location}.open_questions`,
    problems,
    4096,
  );
  if (!Array.isArray(root.exclusions) || root.exclusions.length < 1)
    problem(`${location}.exclusions`, problems);
  else {
    root.exclusions.forEach((item, index) =>
      validateExclusion(item, `${location}.exclusions[${index}]`, problems),
    );
    if (
      !root.exclusions.some(
        (candidate) =>
          isRecord(candidate) &&
          typeof candidate.category === "string" &&
          /^raw[-_ ]?transcripts?$/i.test(candidate.category),
      )
    )
      problem(`${location}.exclusions`, problems);
  }
  const nextActionSourcePaths = validateNextAction(
    root.next_action,
    `${location}.next_action`,
    problems,
  );
  if ("extensions" in root)
    validateExtensions(root.extensions, `${location}.extensions`, problems);

  const valid =
    problems.length === 0 &&
    typeof root.checkpoint_id === "string" &&
    typeof root.session_id === "string" &&
    gitState !== null;
  return {
    value: valid
      ? {
          checkpointId: root.checkpoint_id as string,
          sessionId: root.session_id as string,
          parents,
          eventRefs,
          gitState: gitState as PathDigestReference,
          artifactRefs,
          evidence,
          nextActionSourcePaths,
        }
      : null,
    problems,
  };
}

function validateCheckpointRefs(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
  requireOne: boolean,
): Array<PathDigestReference & { checkpointId: string }> {
  const output: Array<PathDigestReference & { checkpointId: string }> = [];
  if (!Array.isArray(value) || (requireOne && value.length < 1)) {
    problem(location, problems);
    return output;
  }
  value.forEach((candidate, index) => {
    const itemLocation = `${location}[${index}]`;
    const item = record(candidate, itemLocation, problems);
    if (!item) return;
    exactKeys(
      item,
      ["checkpoint_id", "path", "digest"],
      [],
      itemLocation,
      problems,
    );
    boundedString(
      item.checkpoint_id,
      1,
      512,
      `${itemLocation}.checkpoint_id`,
      problems,
    );
    const reference = validatePathDigest(item, itemLocation, problems, [
      "checkpoint_id",
    ]);
    if (reference && typeof item.checkpoint_id === "string")
      output.push({ ...reference, checkpointId: item.checkpoint_id });
  });
  rejectDuplicateObjects(
    output,
    (item) => `${item.checkpointId}\0${item.path}\0${item.digest}`,
    location,
    problems,
  );
  return output;
}

function validateEventRefs(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): Array<PathDigestReference & { eventId: string }> {
  const output: Array<PathDigestReference & { eventId: string }> = [];
  if (!Array.isArray(value) || value.length < 1) {
    problem(location, problems);
    return output;
  }
  value.forEach((candidate, index) => {
    const itemLocation = `${location}[${index}]`;
    const item = record(candidate, itemLocation, problems);
    if (!item) return;
    exactKeys(item, ["event_id", "path", "digest"], [], itemLocation, problems);
    patternString(
      item.event_id,
      /^urn:owc:event:[A-Za-z0-9._:-]+$/,
      `${itemLocation}.event_id`,
      problems,
      512,
    );
    const reference = validatePathDigest(item, itemLocation, problems, [
      "event_id",
    ]);
    if (reference && typeof item.event_id === "string")
      output.push({ ...reference, eventId: item.event_id });
  });
  rejectDuplicateObjects(
    output,
    (item) => `${item.eventId}\0${item.path}\0${item.digest}`,
    location,
    problems,
  );
  return output;
}

function validatePathDigest(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
  additionalKeys: readonly string[] = [],
): PathDigestReference | null {
  const item = record(value, location, problems);
  if (!item) return null;
  exactKeys(
    item,
    ["path", "digest", ...additionalKeys],
    [],
    location,
    problems,
  );
  safePath(item.path, `${location}.path`, problems);
  digest(item.digest, `${location}.digest`, problems);
  return typeof item.path === "string" && isDigest(item.digest)
    ? { path: item.path, digest: item.digest }
    : null;
}

function validateByteReference(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): (PathDigestReference & { byteLength: number }) | null {
  const item = record(value, location, problems);
  if (!item) return null;
  exactKeys(item, ["path", "digest", "byte_length"], [], location, problems);
  const reference = validatePathDigest(item, location, problems, [
    "byte_length",
  ]);
  nonNegativeInteger(item.byte_length, `${location}.byte_length`, problems);
  return reference && typeof item.byte_length === "number"
    ? { ...reference, byteLength: item.byte_length }
    : null;
}

function validateProvider(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
  checkpoint = false,
): void {
  const item = record(value, location, problems);
  if (!item) return;
  exactKeys(
    item,
    ["name"],
    checkpoint
      ? ["external_session_id"]
      : [
          "adapter_version",
          "provider_version",
          "external_session_id",
          "external_event_id",
        ],
    location,
    problems,
  );
  patternString(
    item.name,
    /^[a-z0-9][a-z0-9._-]{0,127}$/,
    `${location}.name`,
    problems,
  );
  for (const key of ["adapter_version", "provider_version"] as const)
    if (key in item)
      boundedString(item[key], 1, 128, `${location}.${key}`, problems);
  for (const key of ["external_session_id", "external_event_id"] as const)
    if (key in item)
      boundedString(item[key], 1, 512, `${location}.${key}`, problems);
}

function validateRetention(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  const item = record(value, location, problems);
  if (!item) return;
  exactKeys(item, ["class", "expires_at"], [], location, problems);
  enumeration(
    item.class,
    ["ephemeral", "checkpoint", "archive", "legal-hold"],
    `${location}.class`,
    problems,
  );
  if (item.expires_at !== null)
    dateTime(item.expires_at, `${location}.expires_at`, problems);
}

function validateWork(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  const item = record(value, location, problems);
  if (!item) return;
  exactKeys(
    item,
    ["work_item_id", "title", "objective", "constraints"],
    [],
    location,
    problems,
  );
  boundedString(
    item.work_item_id,
    1,
    512,
    `${location}.work_item_id`,
    problems,
  );
  boundedString(item.title, 1, 512, `${location}.title`, problems);
  boundedString(item.objective, 1, 8192, `${location}.objective`, problems);
  validateStringArray(
    item.constraints,
    `${location}.constraints`,
    problems,
    4096,
  );
}

function validateClaims(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (!Array.isArray(value)) {
    problem(location, problems);
    return;
  }
  value.forEach((candidate, index) => {
    const itemLocation = `${location}[${index}]`;
    const item = record(candidate, itemLocation, problems);
    if (!item) return;
    exactKeys(
      item,
      ["claim_id", "statement", "actor_id", "subject_digest"],
      [],
      itemLocation,
      problems,
    );
    boundedString(item.claim_id, 1, 512, `${itemLocation}.claim_id`, problems);
    boundedString(
      item.statement,
      1,
      8192,
      `${itemLocation}.statement`,
      problems,
    );
    boundedString(item.actor_id, 1, 512, `${itemLocation}.actor_id`, problems);
    digest(item.subject_digest, `${itemLocation}.subject_digest`, problems);
  });
}

function validateEvidence(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): ValidatedCheckpointEvidence[] {
  const output: ValidatedCheckpointEvidence[] = [];
  if (!Array.isArray(value)) {
    problem(location, problems);
    return output;
  }
  value.forEach((candidate, index) => {
    const itemLocation = `${location}[${index}]`;
    const item = record(candidate, itemLocation, problems);
    if (!item) return;
    exactKeys(
      item,
      [
        "evidence_id",
        "kind",
        "issuer",
        "subject_digest",
        "result",
        "observed_at",
      ],
      ["source"],
      itemLocation,
      problems,
    );
    const identity = validateEvidenceFields(item, itemLocation, problems);
    let source: PathDigestReference | null = null;
    if ("source" in item) {
      source = validatePathDigest(
        item.source,
        `${itemLocation}.source`,
        problems,
      );
    }
    if (identity) output.push({ ...identity, source });
  });
  return output;
}

export function validateEvidenceObject(
  value: unknown,
  location: string,
): {
  readonly value: ValidatedEvidence | null;
  readonly problems: readonly SchemaProblem[];
} {
  const problems: SchemaProblem[] = [];
  const root = record(value, location, problems);
  if (!root) return { value: null, problems };
  exactKeys(
    root,
    [
      "schema_version",
      "evidence_id",
      "kind",
      "issuer",
      "subject_digest",
      "result",
      "observed_at",
    ],
    ["extensions"],
    location,
    problems,
  );
  constant(root.schema_version, "0.1", `${location}.schema_version`, problems);
  const identity = validateEvidenceFields(root, location, problems);
  if ("extensions" in root) {
    validateExtensions(root.extensions, `${location}.extensions`, problems);
  }
  return {
    value: problems.length === 0 ? identity : null,
    problems,
  };
}

function validateEvidenceFields(
  item: Record<string, unknown>,
  location: string,
  problems: SchemaProblem[],
): ValidatedEvidence | null {
  const initialProblemCount = problems.length;
  boundedString(item.evidence_id, 1, 512, `${location}.evidence_id`, problems);
  boundedString(item.kind, 1, 128, `${location}.kind`, problems);
  boundedString(item.issuer, 1, 512, `${location}.issuer`, problems);
  digest(item.subject_digest, `${location}.subject_digest`, problems);
  enumeration(
    item.result,
    ["passed", "failed", "unknown"],
    `${location}.result`,
    problems,
  );
  dateTime(item.observed_at, `${location}.observed_at`, problems);
  if (
    problems.length !== initialProblemCount ||
    typeof item.evidence_id !== "string" ||
    typeof item.kind !== "string" ||
    typeof item.issuer !== "string" ||
    !isDigest(item.subject_digest) ||
    (item.result !== "passed" &&
      item.result !== "failed" &&
      item.result !== "unknown") ||
    typeof item.observed_at !== "string"
  ) {
    return null;
  }
  return {
    evidenceId: item.evidence_id,
    kind: item.kind,
    issuer: item.issuer,
    subjectDigest: item.subject_digest,
    result: item.result,
    observedAt: item.observed_at,
  };
}

function validateNextAction(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): string[] {
  const item = record(value, location, problems);
  if (!item) return [];
  exactKeys(item, ["statement", "source_paths"], [], location, problems);
  boundedString(item.statement, 1, 8192, `${location}.statement`, problems);
  if (!Array.isArray(item.source_paths) || item.source_paths.length < 1) {
    problem(`${location}.source_paths`, problems);
    return [];
  }
  const output: string[] = [];
  item.source_paths.forEach((candidate, index) => {
    safePath(candidate, `${location}.source_paths[${index}]`, problems);
    if (typeof candidate === "string") output.push(candidate);
  });
  if (new Set(output).size !== output.length)
    problem(`${location}.source_paths`, problems);
  return output;
}

function validateExclusion(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  const item = record(value, location, problems);
  if (!item) return;
  exactKeys(item, ["category", "reason", "policy"], [], location, problems);
  boundedString(item.category, 1, 128, `${location}.category`, problems);
  boundedString(item.reason, 1, 2048, `${location}.reason`, problems);
  boundedString(item.policy, 1, 256, `${location}.policy`, problems);
}

function validateExtensions(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  const item = record(value, location, problems);
  if (!item) return;
  for (const key of Object.keys(item)) {
    if (!/^[a-z0-9][a-z0-9.-]*\/[A-Za-z0-9._-]+$/.test(key))
      problem(`${location}.${key}`, problems);
  }
}

function validateStringArray(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
  maximum: number,
): void {
  if (!Array.isArray(value)) {
    problem(location, problems);
    return;
  }
  value.forEach((item, index) =>
    boundedString(item, 1, maximum, `${location}[${index}]`, problems),
  );
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  location: string,
  problems: SchemaProblem[],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required)
    if (!(key in value)) problem(`${location}.${key}`, problems);
  for (const key of Object.keys(value))
    if (!allowed.has(key)) problem(location, problems);
}

function record(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): Record<string, unknown> | null {
  if (!isRecord(value)) {
    problem(location, problems);
    return null;
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
}

function constant(
  value: unknown,
  expected: string,
  location: string,
  problems: SchemaProblem[],
): void {
  if (value !== expected) problem(location, problems);
}

function boundedString(
  value: unknown,
  minimum: number,
  maximum: number,
  location: string,
  problems: SchemaProblem[],
): void {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum
  )
    problem(location, problems);
}

function validateEventType(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (
    typeof value !== "string" ||
    value.length > 256 ||
    (!CORE_EVENT_TYPES.has(value) && !EXTENSION_EVENT_TYPE.test(value))
  ) {
    problem(location, problems);
  }
}

function patternString(
  value: unknown,
  pattern: RegExp,
  location: string,
  problems: SchemaProblem[],
  maximum?: number,
): void {
  if (
    typeof value !== "string" ||
    (maximum !== undefined && value.length > maximum) ||
    !pattern.test(value)
  )
    problem(location, problems);
}

function dateTime(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (typeof value !== "string") {
    problem(location, problems);
    return;
  }
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(Z|([+-])(\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) {
    problem(location, problems);
    return;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetSign = match[8] === "-" ? -1 : 1;
  const offsetHour = Number(match[9] ?? 0);
  const offsetMinute = Number(match[10] ?? 0);
  const monthDays = [
    0,
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const validDate =
    month >= 1 && month <= 12 && day >= 1 && day <= (monthDays[month] ?? 0);
  const ordinaryTime = hour <= 23 && minute <= 59 && second < 60;
  const utcMinute = minute - offsetMinute * offsetSign;
  const utcHour = hour - offsetHour * offsetSign - (utcMinute < 0 ? 1 : 0);
  const leapSecond =
    hour <= 23 &&
    minute <= 59 &&
    second >= 60 &&
    (utcHour === 23 || utcHour === -1) &&
    (utcMinute === 59 || utcMinute === -1) &&
    second < 61;
  const validTime =
    offsetHour <= 23 && offsetMinute <= 59 && (ordinaryTime || leapSecond);
  if (!validDate || !validTime) problem(location, problems);
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function enumeration(
  value: unknown,
  allowed: readonly string[],
  location: string,
  problems: SchemaProblem[],
): void {
  if (typeof value !== "string" || !allowed.includes(value))
    problem(location, problems);
}

function positiveInteger(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    problem(location, problems);
}

function nonNegativeInteger(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    problem(location, problems);
}

function safePath(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (!isSafeArchivePath(value)) problem(location, problems);
}

function digest(
  value: unknown,
  location: string,
  problems: SchemaProblem[],
): void {
  if (!isDigest(value)) problem(location, problems);
}

function isDigest(value: unknown): value is Digest {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function rejectDuplicateObjects<T>(
  items: readonly T[],
  key: (item: T) => string,
  location: string,
  problems: SchemaProblem[],
): void {
  const keys = items.map(key);
  if (new Set(keys).size !== keys.length) problem(location, problems);
}

function problem(location: string, problems: SchemaProblem[]): void {
  problems.push({
    location,
    message: "Object does not satisfy the v0 schema.",
  });
}
