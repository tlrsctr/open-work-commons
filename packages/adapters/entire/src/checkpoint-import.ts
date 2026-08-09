export type EntireCheckpointImportDiagnostic =
  | "entire_checkpoint_json_too_large"
  | "entire_checkpoint_json_invalid"
  | "entire_checkpoint_json_duplicate_key"
  | "entire_checkpoint_json_shape_unrecognized"
  | "entire_checkpoint_json_resource_limit"
  | "entire_checkpoint_json_ambiguous";

export interface EntireCheckpointImportOptions {
  readonly providerVersion?: string;
}

export interface UntrustedProviderText {
  readonly value: string;
  readonly trust: "untrusted-provider-assertion";
}

export interface OwcActorCandidate {
  readonly kind: "agent";
  readonly displayName: string;
}

export interface OwcCodeLearningCandidate {
  readonly path: string;
  readonly line: number | null;
  readonly endLine: number | null;
  readonly finding: UntrustedProviderText;
}

export interface OwcSummaryCandidate {
  readonly intent: UntrustedProviderText | null;
  readonly outcome: UntrustedProviderText | null;
  readonly friction: readonly UntrustedProviderText[];
  readonly openItems: readonly UntrustedProviderText[];
  readonly learnings: {
    readonly repository: readonly UntrustedProviderText[];
    readonly code: readonly OwcCodeLearningCandidate[];
    readonly workflow: readonly UntrustedProviderText[];
  };
}

export interface OwcTokenUsageCandidate {
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheCreation: number;
}

export interface OwcSessionCandidate {
  readonly index: number;
  readonly metadataAvailable: boolean;
  readonly externalSessionId: string | null;
  readonly actor: OwcActorCandidate | null;
  readonly providerModel: string | null;
  readonly providerKind: string | null;
  readonly providerTimestamp: string | null;
  readonly providerReportedFiles: readonly string[];
  readonly tokenUsage: OwcTokenUsageCandidate | null;
  readonly providerSummaryClaims: OwcSummaryCandidate | null;
  readonly gaps: readonly OwcCandidateGap[];
}

export type OwcCandidateGap =
  | "authorization_and_redaction_required"
  | "checkpoint_creation_time_unavailable"
  | "checkpoint_detail_not_imported"
  | "checkpoint_lineage_unavailable"
  | "event_history_unavailable"
  | "external_session_id_unavailable"
  | "git_state_unavailable"
  | "next_action_requires_operator"
  | "owc_checkpoint_id_unassigned"
  | "owc_event_id_unassigned"
  | "owc_event_type_unavailable"
  | "payload_digest_unavailable"
  | "previous_event_unavailable"
  | "provider_metadata_partial"
  | "provider_session_metadata_unavailable"
  | "sequence_unavailable"
  | "space_id_unavailable"
  | "work_definition_unavailable";

export interface OwcCheckpointCandidate {
  readonly candidateKind: "checkpoint";
  readonly candidateVersion: "0.1";
  readonly completeness: "listing" | "metadata";
  readonly source: {
    readonly provider: "entire";
    readonly providerVersion: string | null;
    readonly externalCheckpointId: string;
  };
  readonly providerTimestamp: string | null;
  readonly providerBranch: string | null;
  readonly providerStrategy: string | null;
  readonly externalSessionIds: readonly string[];
  readonly actor: OwcActorCandidate | null;
  readonly providerMessage: UntrustedProviderText | null;
  readonly providerReportedFiles: readonly string[];
  readonly sessions: readonly OwcSessionCandidate[];
  readonly exclusions: readonly OwcImportExclusion[];
  readonly gaps: readonly OwcCandidateGap[];
  readonly handling: OwcCandidateHandling;
}

export interface OwcEventCandidate {
  readonly candidateKind: "event";
  readonly candidateVersion: "0.1";
  readonly source: {
    readonly provider: "entire";
    readonly providerVersion: string | null;
    readonly externalCheckpointId: string;
    readonly externalSessionId: string | null;
  };
  readonly proposedEventType: null;
  readonly providerTimestamp: string | null;
  readonly actor: OwcActorCandidate | null;
  readonly subject: {
    readonly kind: "checkpoint";
    readonly externalId: string;
  };
  readonly providerMessage: UntrustedProviderText | null;
  readonly providerReportedFiles: readonly string[];
  readonly providerSummaryClaims: OwcSummaryCandidate | null;
  readonly gaps: readonly OwcCandidateGap[];
  readonly handling: OwcCandidateHandling;
}

export interface OwcImportExclusion {
  readonly category: "raw-transcript" | "unknown-provider-fields";
  readonly reason: string;
  readonly policy: "owc-v0-default-deny";
}

export interface OwcCandidateHandling {
  readonly contentTrust: "untrusted-provider-output";
  readonly authorizationRequiredBeforeDurableWrite: true;
  readonly rawTranscripts: "excluded";
  readonly executable: false;
}

export type EntireCheckpointImportResult =
  | {
      readonly status: "ok";
      readonly sourceFormat:
        "entire-checkpoint-list-v0.9" | "entire-checkpoint-detail-v0.9";
      readonly checkpoints: readonly OwcCheckpointCandidate[];
      readonly events: readonly OwcEventCandidate[];
      readonly diagnostics: readonly [];
    }
  | {
      readonly status: "invalid";
      readonly diagnostic: EntireCheckpointImportDiagnostic;
      readonly checkpoints: readonly [];
      readonly events: readonly [];
    };

type JsonRecord = Record<string, unknown>;

const MAX_JSON_BYTES = 256 * 1024;
const MAX_DEPTH = 64;
const MAX_CHECKPOINTS = 100;
const MAX_SESSIONS = 100;
const MAX_LIST_ITEMS = 512;
const MAX_TEXT_LENGTH = 8192;
const MAX_SHORT_TEXT_LENGTH = 512;
const MAX_PATH_LENGTH = 1024;
const SAFE_EXTERNAL_ID = /^[A-Za-z0-9._:-]+$/;
const SAFE_RELATIVE_PATH =
  /^(?!\/)(?!.*\\)(?!.*(?:^|\/)(?:\.|\.\.)(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

const HANDLING: OwcCandidateHandling = {
  contentTrust: "untrusted-provider-output",
  authorizationRequiredBeforeDurableWrite: true,
  rawTranscripts: "excluded",
  executable: false,
};

const EXCLUSIONS: readonly OwcImportExclusion[] = [
  {
    category: "raw-transcript",
    reason:
      "The adapter never requests or maps transcript, prompt, response, or hidden reasoning fields.",
    policy: "owc-v0-default-deny",
  },
  {
    category: "unknown-provider-fields",
    reason:
      "Only the documented Entire 0.9 metadata allowlist is projected into candidates.",
    policy: "owc-v0-default-deny",
  },
];

const EVENT_GAPS: readonly OwcCandidateGap[] = [
  "authorization_and_redaction_required",
  "owc_event_id_unassigned",
  "owc_event_type_unavailable",
  "space_id_unavailable",
  "sequence_unavailable",
  "previous_event_unavailable",
  "payload_digest_unavailable",
];

const CHECKPOINT_GAPS: readonly OwcCandidateGap[] = [
  "authorization_and_redaction_required",
  "owc_checkpoint_id_unassigned",
  "event_history_unavailable",
  "git_state_unavailable",
  "work_definition_unavailable",
  "checkpoint_lineage_unavailable",
  "next_action_requires_operator",
];

class ImportFailure extends Error {
  constructor(readonly diagnostic: EntireCheckpointImportDiagnostic) {
    super(diagnostic);
  }
}

export function importEntireCheckpointList(
  input: string,
  options: EntireCheckpointImportOptions = {},
): EntireCheckpointImportResult {
  try {
    const parsed = parseProviderJson(input);
    if (!Array.isArray(parsed)) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    if (parsed.length > MAX_CHECKPOINTS) {
      throw new ImportFailure("entire_checkpoint_json_resource_limit");
    }

    const providerVersion = readProviderVersion(options.providerVersion);
    const ids = new Set<string>();
    const checkpoints: OwcCheckpointCandidate[] = [];
    const events: OwcEventCandidate[] = [];

    for (const value of parsed) {
      const record = requireRecord(value);
      const externalCheckpointId = readExternalId(
        record,
        "checkpoint_id",
        true,
      );
      if (ids.has(externalCheckpointId)) {
        throw new ImportFailure("entire_checkpoint_json_ambiguous");
      }
      ids.add(externalCheckpointId);

      const providerTimestamp = readTimestamp(record, "date", true);
      const externalSessionIds = readSessionIds(record);
      const actor = readActor(record.agent);
      const providerMessage = readUntrustedText(record.message, false);
      const gaps = [
        ...CHECKPOINT_GAPS,
        "checkpoint_detail_not_imported" as const,
        ...(externalSessionIds.length === 0
          ? (["external_session_id_unavailable"] as const)
          : []),
      ];

      const checkpoint: OwcCheckpointCandidate = {
        candidateKind: "checkpoint",
        candidateVersion: "0.1",
        completeness: "listing",
        source: {
          provider: "entire",
          providerVersion,
          externalCheckpointId,
        },
        providerTimestamp,
        providerBranch: null,
        providerStrategy: null,
        externalSessionIds,
        actor,
        providerMessage,
        providerReportedFiles: [],
        sessions: [],
        exclusions: EXCLUSIONS,
        gaps,
        handling: HANDLING,
      };
      checkpoints.push(checkpoint);
      events.push(
        createEventCandidate({
          externalCheckpointId,
          externalSessionId: externalSessionIds[0] ?? null,
          providerVersion,
          providerTimestamp,
          actor,
          providerMessage,
          providerReportedFiles: [],
          providerSummaryClaims: null,
        }),
      );
    }

    return {
      status: "ok",
      sourceFormat: "entire-checkpoint-list-v0.9",
      checkpoints,
      events,
      diagnostics: [],
    };
  } catch (error) {
    return invalidResult(readDiagnostic(error));
  }
}

export function importEntireCheckpointDetail(
  input: string,
  options: EntireCheckpointImportOptions = {},
): EntireCheckpointImportResult {
  try {
    const record = requireRecord(parseProviderJson(input));
    const externalCheckpointId = readExternalId(record, "checkpoint_id", true);
    const providerVersion = readProviderVersion(options.providerVersion);
    const sessionCount = readInteger(record, "session_count", true);
    if (sessionCount < 0 || sessionCount > MAX_SESSIONS) {
      throw new ImportFailure("entire_checkpoint_json_resource_limit");
    }
    if (
      !Array.isArray(record.sessions) ||
      record.sessions.length !== sessionCount
    ) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }

    const seenIndexes = new Set<number>();
    const sessions = record.sessions.map((value) => {
      const session = readSessionCandidate(value, sessionCount);
      if (seenIndexes.has(session.index)) {
        throw new ImportFailure("entire_checkpoint_json_ambiguous");
      }
      seenIndexes.add(session.index);
      return session;
    });
    for (let index = 0; index < sessionCount; index += 1) {
      if (!seenIndexes.has(index)) {
        throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
      }
    }
    sessions.sort((left, right) => left.index - right.index);

    const partial = readBoolean(record, "partial", false) ?? false;
    const providerTimestamp = firstTimestamp(sessions);
    const externalSessionIds = uniqueSorted(
      sessions.flatMap((session) =>
        session.externalSessionId === null ? [] : [session.externalSessionId],
      ),
    );
    const providerReportedFiles = uniqueSorted([
      ...readPathArray(record, "files_touched"),
      ...sessions.flatMap((session) => session.providerReportedFiles),
    ]);
    const actor = firstActor(sessions);
    const gaps = [
      ...CHECKPOINT_GAPS,
      ...(providerTimestamp === null
        ? (["checkpoint_creation_time_unavailable"] as const)
        : []),
      ...(externalSessionIds.length === 0
        ? (["external_session_id_unavailable"] as const)
        : []),
      ...(partial || sessions.some((session) => !session.metadataAvailable)
        ? (["provider_metadata_partial"] as const)
        : []),
    ];

    const checkpoint: OwcCheckpointCandidate = {
      candidateKind: "checkpoint",
      candidateVersion: "0.1",
      completeness: "metadata",
      source: {
        provider: "entire",
        providerVersion,
        externalCheckpointId,
      },
      providerTimestamp,
      providerBranch: readOptionalShortString(record, "branch"),
      providerStrategy: readOptionalShortString(record, "strategy"),
      externalSessionIds,
      actor,
      providerMessage: null,
      providerReportedFiles,
      sessions,
      exclusions: EXCLUSIONS,
      gaps,
      handling: HANDLING,
    };

    const events = sessions.length
      ? sessions.map((session) =>
          createEventCandidate({
            externalCheckpointId,
            externalSessionId: session.externalSessionId,
            providerVersion,
            providerTimestamp: session.providerTimestamp,
            actor: session.actor,
            providerMessage: null,
            providerReportedFiles: session.providerReportedFiles,
            providerSummaryClaims: session.providerSummaryClaims,
          }),
        )
      : [
          createEventCandidate({
            externalCheckpointId,
            externalSessionId: null,
            providerVersion,
            providerTimestamp: null,
            actor: null,
            providerMessage: null,
            providerReportedFiles,
            providerSummaryClaims: null,
          }),
        ];

    return {
      status: "ok",
      sourceFormat: "entire-checkpoint-detail-v0.9",
      checkpoints: [checkpoint],
      events,
      diagnostics: [],
    };
  } catch (error) {
    return invalidResult(readDiagnostic(error));
  }
}

interface CreateEventInput {
  readonly externalCheckpointId: string;
  readonly externalSessionId: string | null;
  readonly providerVersion: string | null;
  readonly providerTimestamp: string | null;
  readonly actor: OwcActorCandidate | null;
  readonly providerMessage: UntrustedProviderText | null;
  readonly providerReportedFiles: readonly string[];
  readonly providerSummaryClaims: OwcSummaryCandidate | null;
}

function createEventCandidate(input: CreateEventInput): OwcEventCandidate {
  return {
    candidateKind: "event",
    candidateVersion: "0.1",
    source: {
      provider: "entire",
      providerVersion: input.providerVersion,
      externalCheckpointId: input.externalCheckpointId,
      externalSessionId: input.externalSessionId,
    },
    proposedEventType: null,
    providerTimestamp: input.providerTimestamp,
    actor: input.actor,
    subject: {
      kind: "checkpoint",
      externalId: input.externalCheckpointId,
    },
    providerMessage: input.providerMessage,
    providerReportedFiles: input.providerReportedFiles,
    providerSummaryClaims: input.providerSummaryClaims,
    gaps: [
      ...EVENT_GAPS,
      ...(input.externalSessionId === null
        ? (["external_session_id_unavailable"] as const)
        : []),
    ],
    handling: HANDLING,
  };
}

function readSessionCandidate(
  value: unknown,
  sessionCount: number,
): OwcSessionCandidate {
  const record = requireRecord(value);
  const index = readInteger(record, "index", true);
  if (index < 0 || index >= sessionCount) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }

  if (Object.hasOwn(record, "error")) {
    if (typeof record.error !== "string") {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    return {
      index,
      metadataAvailable: false,
      externalSessionId: null,
      actor: null,
      providerModel: null,
      providerKind: null,
      providerTimestamp: null,
      providerReportedFiles: [],
      tokenUsage: null,
      providerSummaryClaims: null,
      gaps: [
        "provider_session_metadata_unavailable",
        "external_session_id_unavailable",
      ],
    };
  }

  const externalSessionId = readExternalId(record, "session_id", false);
  const providerTimestamp = readTimestamp(record, "created_at", false);
  return {
    index,
    metadataAvailable: true,
    externalSessionId,
    actor: readActor(record.agent),
    providerModel: readNullableShortString(record.model),
    providerKind: readNullableShortString(record.kind),
    providerTimestamp,
    providerReportedFiles: readPathArray(record, "files_touched"),
    tokenUsage: readTokenUsage(record.token_usage),
    providerSummaryClaims: readSummary(record.summary),
    gaps: [
      ...(externalSessionId === null
        ? (["external_session_id_unavailable"] as const)
        : []),
      ...(providerTimestamp === null
        ? (["checkpoint_creation_time_unavailable"] as const)
        : []),
    ],
  };
}

function readSummary(value: unknown): OwcSummaryCandidate | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value);
  const learnings =
    record.learnings === undefined || record.learnings === null
      ? {}
      : requireRecord(record.learnings);
  return {
    intent: readUntrustedText(record.intent, false),
    outcome: readUntrustedText(record.outcome, false),
    friction: readTextArray(record, "friction"),
    openItems: readTextArray(record, "open_items"),
    learnings: {
      repository: readTextArray(learnings, "repo"),
      code: readCodeLearnings(learnings.code),
      workflow: readTextArray(learnings, "workflow"),
    },
  };
}

function readCodeLearnings(
  value: unknown,
): readonly OwcCodeLearningCandidate[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    throw new ImportFailure("entire_checkpoint_json_resource_limit");
  }
  return value.map((item) => {
    const record = requireRecord(item);
    const path = readPath(record.path);
    const finding = readUntrustedText(record.finding, true);
    const line = readOptionalPositiveInteger(record, "line");
    const endLine = readOptionalPositiveInteger(record, "end_line");
    if (line === null && endLine !== null) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    if (line !== null && endLine !== null && endLine < line) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    return { path, line, endLine, finding };
  });
}

function readTokenUsage(value: unknown): OwcTokenUsageCandidate | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value);
  return {
    input: readNonNegativeInteger(record, "input_tokens"),
    output: readNonNegativeInteger(record, "output_tokens"),
    cacheRead: readNonNegativeInteger(record, "cache_read_tokens", 0),
    cacheCreation: readNonNegativeInteger(record, "cache_creation_tokens", 0),
  };
}

function parseProviderJson(input: string): unknown {
  if (Buffer.byteLength(input, "utf8") > MAX_JSON_BYTES) {
    throw new ImportFailure("entire_checkpoint_json_too_large");
  }
  const scanner = new DuplicateKeyScanner(input);
  scanner.scan();
  if (scanner.hasDuplicateKey) {
    throw new ImportFailure("entire_checkpoint_json_duplicate_key");
  }
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new ImportFailure("entire_checkpoint_json_invalid");
  }
}

class DuplicateKeyScanner {
  private offset = 0;
  hasDuplicateKey = false;

  constructor(private readonly input: string) {}

  scan(): void {
    this.skipWhitespace();
    this.scanValue(0);
    this.skipWhitespace();
    if (this.offset !== this.input.length) this.invalid();
  }

  private scanValue(depth: number): void {
    if (depth > MAX_DEPTH) {
      throw new ImportFailure("entire_checkpoint_json_resource_limit");
    }
    const char = this.input[this.offset];
    if (char === "{") return this.scanObject(depth + 1);
    if (char === "[") return this.scanArray(depth + 1);
    if (char === '"') {
      this.scanString();
      return;
    }
    this.scanPrimitive();
  }

  private scanObject(depth: number): void {
    this.offset += 1;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.input[this.offset] === "}") {
      this.offset += 1;
      return;
    }
    while (this.offset < this.input.length) {
      if (this.input[this.offset] !== '"') this.invalid();
      const key = this.scanString();
      if (keys.has(key)) this.hasDuplicateKey = true;
      keys.add(key);
      this.skipWhitespace();
      if (this.input[this.offset] !== ":") this.invalid();
      this.offset += 1;
      this.skipWhitespace();
      this.scanValue(depth);
      this.skipWhitespace();
      const char = this.input[this.offset];
      if (char === "}") {
        this.offset += 1;
        return;
      }
      if (char !== ",") this.invalid();
      this.offset += 1;
      this.skipWhitespace();
    }
    this.invalid();
  }

  private scanArray(depth: number): void {
    this.offset += 1;
    this.skipWhitespace();
    if (this.input[this.offset] === "]") {
      this.offset += 1;
      return;
    }
    while (this.offset < this.input.length) {
      this.scanValue(depth);
      this.skipWhitespace();
      const char = this.input[this.offset];
      if (char === "]") {
        this.offset += 1;
        return;
      }
      if (char !== ",") this.invalid();
      this.offset += 1;
      this.skipWhitespace();
    }
    this.invalid();
  }

  private scanString(): string {
    const start = this.offset;
    this.offset += 1;
    while (this.offset < this.input.length) {
      const char = this.input[this.offset];
      if (char === '"') {
        this.offset += 1;
        const raw = this.input.slice(start, this.offset);
        try {
          return JSON.parse(raw) as string;
        } catch {
          this.invalid();
        }
      }
      if (char === "\\") {
        this.offset += 2;
      } else {
        this.offset += 1;
      }
    }
    this.invalid();
  }

  private scanPrimitive(): void {
    const start = this.offset;
    while (this.offset < this.input.length) {
      const char = this.input[this.offset];
      if (
        char === "," ||
        char === "]" ||
        char === "}" ||
        /\s/.test(char ?? "")
      ) {
        break;
      }
      this.offset += 1;
    }
    if (this.offset === start) this.invalid();
  }

  private skipWhitespace(): void {
    while (/\s/.test(this.input[this.offset] ?? "")) this.offset += 1;
  }

  private invalid(): never {
    throw new ImportFailure("entire_checkpoint_json_invalid");
  }
}

function requireRecord(value: unknown): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value as JsonRecord;
}

function readExternalId(
  record: JsonRecord,
  key: string,
  required: true,
): string;
function readExternalId(
  record: JsonRecord,
  key: string,
  required: false,
): string | null;
function readExternalId(
  record: JsonRecord,
  key: string,
  required: boolean,
): string | null {
  const value = record[key];
  if (value === undefined || value === null || value === "") {
    if (required) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    return null;
  }
  if (
    typeof value !== "string" ||
    value.length > MAX_SHORT_TEXT_LENGTH ||
    !SAFE_EXTERNAL_ID.test(value)
  ) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readSessionIds(record: JsonRecord): readonly string[] {
  const values: string[] = [];
  const sessionId = readExternalId(record, "session_id", false);
  if (sessionId !== null) values.push(sessionId);
  if (record.session_ids !== undefined && record.session_ids !== null) {
    if (
      !Array.isArray(record.session_ids) ||
      record.session_ids.length > MAX_SESSIONS
    ) {
      throw new ImportFailure("entire_checkpoint_json_resource_limit");
    }
    for (const value of record.session_ids) {
      values.push(readExternalId({ value }, "value", true));
    }
  }
  return uniqueSorted(values);
}

function readTimestamp(record: JsonRecord, key: string, required: true): string;
function readTimestamp(
  record: JsonRecord,
  key: string,
  required: false,
): string | null;
function readTimestamp(
  record: JsonRecord,
  key: string,
  required: boolean,
): string | null {
  const value = record[key];
  if (value === undefined || value === null || value === "") {
    if (required) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    return null;
  }
  if (typeof value !== "string" || value.length > 64) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return new Date(milliseconds).toISOString();
}

function readPathArray(record: JsonRecord, key: string): readonly string[] {
  const value = record[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    throw new ImportFailure("entire_checkpoint_json_resource_limit");
  }
  return uniqueSorted(value.map(readPath));
}

function readPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_PATH_LENGTH ||
    !SAFE_RELATIVE_PATH.test(value)
  ) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readUntrustedText(
  value: unknown,
  required: true,
): UntrustedProviderText;
function readUntrustedText(
  value: unknown,
  required: false,
): UntrustedProviderText | null;
function readUntrustedText(
  value: unknown,
  required: boolean,
): UntrustedProviderText | null {
  if (value === undefined || value === null || value === "") {
    if (required) {
      throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
    }
    return null;
  }
  if (typeof value !== "string" || value.length > MAX_TEXT_LENGTH) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return { value, trust: "untrusted-provider-assertion" };
}

function readTextArray(
  record: JsonRecord,
  key: string,
): readonly UntrustedProviderText[] {
  const value = record[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    throw new ImportFailure("entire_checkpoint_json_resource_limit");
  }
  return value.map((item) => readUntrustedText(item, true));
}

function readActor(value: unknown): OwcActorCandidate | null {
  const displayName = readNullableShortString(value);
  return displayName === null ? null : { kind: "agent", displayName };
}

function readNullableShortString(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > MAX_SHORT_TEXT_LENGTH) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readOptionalShortString(
  record: JsonRecord,
  key: string,
): string | null {
  return readNullableShortString(record[key]);
}

function readInteger(
  record: JsonRecord,
  key: string,
  required: boolean,
): number {
  const value = record[key];
  if (value === undefined && !required) return 0;
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readNonNegativeInteger(
  record: JsonRecord,
  key: string,
  fallback?: number,
): number {
  const value = record[key];
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readOptionalPositiveInteger(
  record: JsonRecord,
  key: string,
): number | null {
  const value = record[key];
  if (value === undefined || value === null || value === 0) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readBoolean(
  record: JsonRecord,
  key: string,
  required: boolean,
): boolean | null {
  const value = record[key];
  if (value === undefined && !required) return null;
  if (typeof value !== "boolean") {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function readProviderVersion(value: string | undefined): string | null {
  if (value === undefined) return null;
  if (value.length === 0 || value.length > 128) {
    throw new ImportFailure("entire_checkpoint_json_shape_unrecognized");
  }
  return value;
}

function firstTimestamp(
  sessions: readonly OwcSessionCandidate[],
): string | null {
  const timestamps = sessions
    .flatMap((session) =>
      session.providerTimestamp === null ? [] : [session.providerTimestamp],
    )
    .sort();
  return timestamps[0] ?? null;
}

function firstActor(
  sessions: readonly OwcSessionCandidate[],
): OwcActorCandidate | null {
  for (const session of sessions) {
    if (session.actor !== null) return session.actor;
  }
  return null;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function readDiagnostic(error: unknown): EntireCheckpointImportDiagnostic {
  return error instanceof ImportFailure
    ? error.diagnostic
    : "entire_checkpoint_json_shape_unrecognized";
}

function invalidResult(
  diagnostic: EntireCheckpointImportDiagnostic,
): EntireCheckpointImportResult {
  return {
    status: "invalid",
    diagnostic,
    checkpoints: [],
    events: [],
  };
}
