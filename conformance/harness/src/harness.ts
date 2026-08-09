import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Ajv2020,
  type ErrorObject,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import addFormatsModule, { type FormatsPlugin } from "ajv-formats";

import { canonicalJsonBytes } from "./canonical-json.js";
import { sha256, verifyEd25519 } from "./crypto.js";
import { isSafeArchivePath } from "./path.js";
import { parseJsonSafely } from "./safe-json.js";

const DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema";
const JSON_LIMITS = {
  maxDepth: 128,
  maxStringBytes: 8 * 1024 * 1024,
} as const;

export const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

export const goldenFixtureRoot = resolve(
  repositoryRoot,
  "conformance/valid/minimal",
);

export const schemaFiles = {
  archiveManifest: "archive-manifest.schema.json",
  checkpoint: "checkpoint.schema.json",
  evidence: "evidence.schema.json",
  event: "event.schema.json",
  gitState: "git-state.schema.json",
  resumeBundle: "resume-bundle.schema.json",
} as const;

export type SchemaName = keyof typeof schemaFiles;

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: readonly ErrorObject[];
}

export interface SchemaRegistry {
  readonly schemaIds: Readonly<Record<SchemaName, string>>;
  validate(name: SchemaName, value: unknown): ValidationResult;
  assertValid(name: SchemaName, value: unknown): void;
}

export interface ArchiveEntry {
  readonly path: string;
  readonly media_type: string;
  readonly role:
    | "event"
    | "git-state"
    | "checkpoint"
    | "artifact"
    | "evidence"
    | "extension";
  readonly byte_length: number;
  readonly digest: `sha256:${string}`;
  readonly required_for_verification?: boolean;
}

interface ArchiveManifest {
  readonly format: string;
  readonly schema_version: string;
  readonly archive_id: string;
  readonly created_at: string;
  readonly root_checkpoint: ObjectReference & {
    readonly checkpoint_id: string;
  };
  readonly entries: readonly ArchiveEntry[];
  readonly exclusions: readonly unknown[];
  readonly limits: {
    readonly entry_count: number;
    readonly expanded_bytes: number;
    readonly max_entry_bytes: number;
  };
  readonly signature: {
    readonly canonicalization: string;
    readonly digest_algorithm: string;
    readonly signature_algorithm: string;
    readonly key_id: string;
    readonly public_key: string;
    readonly payload_digest: `sha256:${string}`;
    readonly value: string;
  };
  readonly [key: string]: unknown;
}

export interface ObjectReference {
  readonly path: string;
  readonly digest: `sha256:${string}`;
}

interface EventReference extends ObjectReference {
  readonly event_id: string;
}

interface ArtifactReference extends ObjectReference {
  readonly media_type: string;
  readonly role: string;
  readonly byte_length: number;
}

export interface EvidenceIdentity {
  readonly evidence_id: string;
  readonly kind: string;
  readonly issuer: string;
  readonly subject_digest: `sha256:${string}`;
  readonly result: "passed" | "failed" | "unknown";
  readonly observed_at: string;
}

export interface EvidenceObject extends EvidenceIdentity {
  readonly schema_version: "0.1";
  readonly extensions?: Readonly<Record<string, unknown>>;
}

export interface CheckpointEvidence extends EvidenceIdentity {
  readonly source?: ObjectReference;
}

interface Checkpoint {
  readonly checkpoint_id: string;
  readonly session_id: string;
  readonly event_refs: readonly EventReference[];
  readonly git_state: ObjectReference;
  readonly artifacts: readonly ArtifactReference[];
  readonly evidence: readonly CheckpointEvidence[];
  readonly [key: string]: unknown;
}

interface NormalizedEvent {
  readonly event_id: string;
  readonly session_id: string;
  readonly payload: {
    readonly digest: `sha256:${string}`;
    readonly inline?: unknown;
    readonly path?: string;
  };
  readonly [key: string]: unknown;
}

export interface GoldenFixture {
  readonly root: string;
  readonly manifestBytes: Uint8Array;
  readonly manifest: ArchiveManifest;
  readonly entryBytes: ReadonlyMap<string, Uint8Array>;
  readonly checkpoint: Checkpoint;
  readonly event: NormalizedEvent;
  readonly gitState: Readonly<Record<string, unknown>>;
  readonly resumeBundle: Readonly<Record<string, unknown>>;
}

export interface EntryIntegrityReport {
  readonly checkedEntries: number;
  readonly expandedBytes: number;
  readonly maxEntryBytes: number;
}

export interface SignatureReport {
  readonly canonicalBytes: Uint8Array;
  readonly payloadDigest: `sha256:${string}`;
  readonly signatureValid: boolean;
}

export interface ReferenceReport {
  readonly rootCheckpointPath: string;
  readonly eventPaths: readonly string[];
  readonly gitStatePath: string;
  readonly artifactPaths: readonly string[];
  readonly evidencePaths: readonly string[];
}

export interface GoldenConformanceReport {
  readonly schemaNames: readonly SchemaName[];
  readonly entries: EntryIntegrityReport;
  readonly signature: SignatureReport;
  readonly references: ReferenceReport;
  readonly inlinePayloadDigest: `sha256:${string}`;
}

export class ConformanceFailure extends Error {
  constructor(
    readonly rule: string,
    readonly location: string,
    message: string,
  ) {
    super(message);
    this.name = "ConformanceFailure";
  }
}

export async function compileLocalSchemas(
  root = repositoryRoot,
): Promise<SchemaRegistry> {
  const schemaDirectory = resolve(root, "schemas/v0");
  const loaded = await Promise.all(
    typedEntries(schemaFiles).map(async ([name, filename]) => {
      const bytes = await readFile(resolve(schemaDirectory, filename));
      const schema = toPlainJson(parseJsonSafely(bytes, JSON_LIMITS));
      assertRecord(schema, `schemas/v0/${filename}`);
      if (schema.$schema !== DRAFT_2020_12) {
        throw new ConformanceFailure(
          "schema-draft",
          `schemas/v0/${filename}`,
          "A v0 schema does not declare JSON Schema Draft 2020-12.",
        );
      }
      if (typeof schema.$id !== "string") {
        throw new ConformanceFailure(
          "schema-id",
          `schemas/v0/${filename}`,
          "A v0 schema does not declare a stable identifier.",
        );
      }
      return { name, schema, id: schema.$id };
    }),
  );

  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    // The event schema uses `required` inside `not` to express XOR. Draft
    // 2020-12 permits that form even though Ajv's stricter lint disallows it.
    strictRequired: false,
    validateFormats: true,
  });
  const addFormats = addFormatsModule as unknown as FormatsPlugin;
  addFormats(ajv, { mode: "full" });

  for (const { schema } of loaded) ajv.addSchema(schema);

  const validators = {} as Record<SchemaName, ValidateFunction>;
  const schemaIds = {} as Record<SchemaName, string>;
  for (const { name, id } of loaded) {
    const validator = ajv.getSchema(id);
    if (!validator) {
      throw new ConformanceFailure(
        "schema-compilation",
        id,
        "A bundled v0 schema could not be compiled locally.",
      );
    }
    validators[name] = validator;
    schemaIds[name] = id;
  }

  const validate = (name: SchemaName, value: unknown): ValidationResult => {
    const validator = validators[name];
    const valid = validator(value);
    return { valid, errors: validator.errors ?? [] };
  };
  return {
    schemaIds,
    validate,
    assertValid(name, value) {
      const result = validate(name, value);
      if (!result.valid) {
        const first = result.errors[0];
        const location = first ? `${name}${first.instancePath || "/"}` : name;
        throw new ConformanceFailure(
          "schema-validation",
          location,
          "A golden object does not satisfy its bundled v0 schema.",
        );
      }
    },
  };
}

export async function loadGoldenFixture(
  root = goldenFixtureRoot,
): Promise<GoldenFixture> {
  const manifestBytes = await readFile(resolve(root, "archive-manifest.json"));
  const parsedManifest = toPlainJson(
    parseJsonSafely(manifestBytes, JSON_LIMITS),
  );
  assertRecord(parsedManifest, "archive-manifest.json");
  const manifest = parsedManifest as unknown as ArchiveManifest;
  if (!Array.isArray(manifest.entries)) {
    throw new ConformanceFailure(
      "manifest-entry-list",
      "archive-manifest.json#/entries",
      "The archive manifest does not contain an entry list.",
    );
  }

  const entryBytes = new Map<string, Uint8Array>();
  for (const entry of manifest.entries) {
    assertSafePath(entry.path, "archive-manifest.json#/entries");
    if (entryBytes.has(entry.path)) {
      throw new ConformanceFailure(
        "duplicate-path",
        "archive-manifest.json#/entries",
        "The archive manifest contains a duplicate entry path.",
      );
    }
    entryBytes.set(
      entry.path,
      await readFile(resolveBeneath(root, entry.path)),
    );
  }

  const checkpoint = parseFixtureObject(
    requiredEntryBytes(entryBytes, "checkpoints/checkpoint.json"),
    "checkpoints/checkpoint.json",
  ) as unknown as Checkpoint;
  const event = parseFixtureObject(
    requiredEntryBytes(entryBytes, "events/session-started.json"),
    "events/session-started.json",
  ) as unknown as NormalizedEvent;
  const gitState = parseFixtureObject(
    requiredEntryBytes(entryBytes, "state/git-state.json"),
    "state/git-state.json",
  );
  const resumeBundle = parseFixtureObject(
    await readFile(resolve(root, "resume/resume-bundle.json")),
    "resume/resume-bundle.json",
  );

  return {
    root,
    manifestBytes,
    manifest,
    entryBytes,
    checkpoint,
    event,
    gitState,
    resumeBundle,
  };
}

export function validateGoldenObjects(
  schemas: SchemaRegistry,
  fixture: GoldenFixture,
): void {
  schemas.assertValid("archiveManifest", fixture.manifest);
  schemas.assertValid("checkpoint", fixture.checkpoint);
  schemas.assertValid("event", fixture.event);
  schemas.assertValid("gitState", fixture.gitState);
  schemas.assertValid("resumeBundle", fixture.resumeBundle);
}

export function verifyEntryIntegrity(
  fixture: GoldenFixture,
): EntryIntegrityReport {
  const paths = fixture.manifest.entries.map((entry) => entry.path);
  const sortedPaths = [...paths].sort();
  if (paths.some((path, index) => path !== sortedPaths[index])) {
    throw new ConformanceFailure(
      "entry-order",
      "archive-manifest.json#/entries",
      "Manifest entries are not sorted lexicographically by path.",
    );
  }
  if (new Set(paths).size !== paths.length) {
    throw new ConformanceFailure(
      "duplicate-path",
      "archive-manifest.json#/entries",
      "The archive manifest contains a duplicate entry path.",
    );
  }

  let expandedBytes = 0;
  let maxEntryBytes = 0;
  for (const entry of fixture.manifest.entries) {
    assertSafePath(entry.path, "archive-manifest.json#/entries");
    const bytes = requiredEntryBytes(fixture.entryBytes, entry.path);
    if (bytes.byteLength !== entry.byte_length) {
      throw new ConformanceFailure(
        "entry-byte-length",
        entry.path,
        "An archive entry byte length does not match the signed declaration.",
      );
    }
    if (sha256(bytes) !== entry.digest) {
      throw new ConformanceFailure(
        "entry-digest",
        entry.path,
        "An archive entry digest does not match the signed declaration.",
      );
    }
    expandedBytes += bytes.byteLength;
    maxEntryBytes = Math.max(maxEntryBytes, bytes.byteLength);
  }

  const declared = fixture.manifest.limits;
  if (
    declared.entry_count !== fixture.manifest.entries.length ||
    declared.expanded_bytes !== expandedBytes ||
    declared.max_entry_bytes !== maxEntryBytes
  ) {
    throw new ConformanceFailure(
      "declared-limits",
      "archive-manifest.json#/limits",
      "Declared archive limits do not match the golden entry bytes.",
    );
  }

  return {
    checkedEntries: paths.length,
    expandedBytes,
    maxEntryBytes,
  };
}

export function manifestSigningProjection(
  manifest: ArchiveManifest,
): Readonly<Record<string, unknown>> {
  const projection = structuredClone(manifest) as unknown as Record<
    string,
    unknown
  >;
  const signature = projection.signature;
  assertRecord(signature, "archive-manifest.json#/signature");
  delete signature.payload_digest;
  delete signature.value;
  return projection;
}

export function verifyManifestSignature(
  manifest: ArchiveManifest,
): SignatureReport {
  const canonicalBytes = canonicalJsonBytes(
    manifestSigningProjection(manifest),
  );
  const payloadDigest = sha256(canonicalBytes);
  if (payloadDigest !== manifest.signature.payload_digest) {
    throw new ConformanceFailure(
      "signature-payload-digest",
      "archive-manifest.json#/signature/payload_digest",
      "The manifest signing projection digest does not match.",
    );
  }
  const signatureValid = verifyEd25519(
    canonicalBytes,
    manifest.signature.value,
    manifest.signature.public_key,
  );
  if (!signatureValid) {
    throw new ConformanceFailure(
      "signature",
      "archive-manifest.json#/signature/value",
      "The manifest Ed25519 signature is invalid.",
    );
  }
  return { canonicalBytes, payloadDigest, signatureValid };
}

export function resolveGoldenReferences(
  fixture: GoldenFixture,
): ReferenceReport {
  const descriptors = new Map(
    fixture.manifest.entries.map((entry) => [entry.path, entry] as const),
  );
  const root = fixture.manifest.root_checkpoint;
  const rootDescriptor = resolveObjectReference(
    root,
    "checkpoint",
    descriptors,
    fixture.entryBytes,
  );
  if (
    rootDescriptor.path !== "checkpoints/checkpoint.json" ||
    fixture.checkpoint.checkpoint_id !== root.checkpoint_id
  ) {
    throw new ConformanceFailure(
      "root-checkpoint-identity",
      root.path,
      "The root checkpoint reference does not resolve to the declared checkpoint.",
    );
  }

  const eventPaths = fixture.checkpoint.event_refs.map((reference) => {
    resolveObjectReference(reference, "event", descriptors, fixture.entryBytes);
    if (
      reference.event_id !== fixture.event.event_id ||
      fixture.event.session_id !== fixture.checkpoint.session_id
    ) {
      throw new ConformanceFailure(
        "event-reference-identity",
        reference.path,
        "A checkpoint event reference has inconsistent identity or session data.",
      );
    }
    return reference.path;
  });

  resolveObjectReference(
    fixture.checkpoint.git_state,
    "git-state",
    descriptors,
    fixture.entryBytes,
  );

  const artifactPaths = fixture.checkpoint.artifacts.map((reference) => {
    const descriptor = resolveObjectReference(
      reference,
      "artifact",
      descriptors,
      fixture.entryBytes,
    );
    if (
      reference.byte_length !== descriptor.byte_length ||
      reference.media_type !== descriptor.media_type
    ) {
      throw new ConformanceFailure(
        "artifact-reference-metadata",
        reference.path,
        "A checkpoint artifact reference does not match its manifest metadata.",
      );
    }
    return reference.path;
  });

  const evidencePaths = fixture.checkpoint.evidence.flatMap((evidence) => {
    if (!evidence.source) return [];
    const descriptor = descriptors.get(evidence.source.path);
    const bytes = fixture.entryBytes.get(evidence.source.path);
    if (!descriptor || !bytes) {
      throw new ConformanceFailure(
        "reference-missing",
        evidence.source.path,
        "A checkpoint evidence source does not resolve to a signed entry.",
      );
    }
    const parsed = parseFixtureObject(
      bytes,
      evidence.source.path,
    ) as unknown as EvidenceObject;
    verifyEvidenceReference(evidence, parsed, descriptor, bytes);
    return [evidence.source.path];
  });

  return {
    rootCheckpointPath: root.path,
    eventPaths,
    gitStatePath: fixture.checkpoint.git_state.path,
    artifactPaths,
    evidencePaths,
  };
}

export function verifyEvidenceReference(
  checkpointEvidence: CheckpointEvidence,
  evidenceObject: EvidenceObject,
  descriptor: ArchiveEntry,
  evidenceBytes: Uint8Array,
): string {
  const source = checkpointEvidence.source;
  if (
    !source ||
    descriptor.path !== source.path ||
    descriptor.role !== "evidence" ||
    descriptor.media_type !== "application/json"
  ) {
    throw new ConformanceFailure(
      "evidence-reference-role",
      source?.path ?? "checkpoint-evidence",
      "A checkpoint evidence source does not resolve to a JSON evidence entry.",
    );
  }
  if (
    descriptor.digest !== source.digest ||
    sha256(evidenceBytes) !== source.digest ||
    descriptor.byte_length !== evidenceBytes.byteLength
  ) {
    throw new ConformanceFailure(
      "evidence-reference-digest",
      source.path,
      "A checkpoint evidence source is inconsistent with the signed entry bytes.",
    );
  }
  if (!sameEvidenceIdentity(checkpointEvidence, evidenceObject)) {
    throw new ConformanceFailure(
      "evidence-reference-identity",
      source.path,
      "A checkpoint evidence identity is inconsistent with its source object.",
    );
  }
  return source.path;
}

function sameEvidenceIdentity(
  left: EvidenceIdentity,
  right: EvidenceIdentity,
): boolean {
  return (
    left.evidence_id === right.evidence_id &&
    left.kind === right.kind &&
    left.issuer === right.issuer &&
    left.subject_digest === right.subject_digest &&
    left.result === right.result &&
    left.observed_at === right.observed_at
  );
}

export function verifyInlinePayloadDigest(
  event: NormalizedEvent,
): `sha256:${string}` {
  if (!("inline" in event.payload) || "path" in event.payload) {
    throw new ConformanceFailure(
      "inline-payload-shape",
      "events/session-started.json#/payload",
      "The golden event does not contain exactly one inline payload.",
    );
  }
  const digest = sha256(canonicalJsonBytes(event.payload.inline));
  if (digest !== event.payload.digest) {
    throw new ConformanceFailure(
      "inline-payload-digest",
      "events/session-started.json#/payload/digest",
      "The inline payload digest does not match its RFC 8785 canonical bytes.",
    );
  }
  return digest;
}

export function checkArchivePath(value: unknown): value is string {
  return isSafeArchivePath(value);
}

export async function verifyGoldenConformance(
  root = repositoryRoot,
): Promise<GoldenConformanceReport> {
  const schemas = await compileLocalSchemas(root);
  const fixture = await loadGoldenFixture(
    resolve(root, "conformance/valid/minimal"),
  );
  validateGoldenObjects(schemas, fixture);
  const entries = verifyEntryIntegrity(fixture);
  const signature = verifyManifestSignature(fixture.manifest);
  const references = resolveGoldenReferences(fixture);
  const inlinePayloadDigest = verifyInlinePayloadDigest(fixture.event);
  return {
    schemaNames: typedEntries(schemaFiles).map(([name]) => name),
    entries,
    signature,
    references,
    inlinePayloadDigest,
  };
}

function resolveObjectReference(
  reference: ObjectReference,
  expectedRole: ArchiveEntry["role"],
  descriptors: ReadonlyMap<string, ArchiveEntry>,
  bytesByPath: ReadonlyMap<string, Uint8Array>,
): ArchiveEntry {
  assertSafePath(reference.path, "checkpoint-reference");
  const descriptor = descriptors.get(reference.path);
  if (!descriptor || descriptor.role !== expectedRole) {
    throw new ConformanceFailure(
      "reference-missing",
      reference.path,
      "A checkpoint reference does not resolve to a signed entry of the required role.",
    );
  }
  const bytes = requiredEntryBytes(bytesByPath, reference.path);
  if (
    descriptor.digest !== reference.digest ||
    sha256(bytes) !== reference.digest
  ) {
    throw new ConformanceFailure(
      "reference-digest",
      reference.path,
      "A checkpoint reference digest is inconsistent with the signed entry bytes.",
    );
  }
  return descriptor;
}

function resolveBeneath(root: string, relativePath: string): string {
  assertSafePath(relativePath, "archive-entry");
  const resolvedRoot = resolve(root);
  const candidate = resolve(resolvedRoot, relativePath);
  const pathFromRoot = relative(resolvedRoot, candidate);
  if (
    pathFromRoot === "" ||
    pathFromRoot === ".." ||
    pathFromRoot.startsWith(`..${sep}`) ||
    isAbsolute(pathFromRoot)
  ) {
    throw new ConformanceFailure(
      "unsafe-path",
      "archive-entry",
      "An archive entry path does not resolve beneath the fixture root.",
    );
  }
  return candidate;
}

function assertSafePath(
  value: unknown,
  location: string,
): asserts value is string {
  if (!isSafeArchivePath(value)) {
    throw new ConformanceFailure(
      "unsafe-path",
      location,
      "An archive path violates the v0 path-safety rules.",
    );
  }
}

function parseFixtureObject(
  bytes: Uint8Array,
  location: string,
): Readonly<Record<string, unknown>> {
  const value = toPlainJson(parseJsonSafely(bytes, JSON_LIMITS));
  assertRecord(value, location);
  return value;
}

function toPlainJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(toPlainJson);
  if (typeof value !== "object" || value === null) return value;

  const result: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    Object.defineProperty(result, key, {
      configurable: true,
      enumerable: true,
      value: toPlainJson(child),
      writable: true,
    });
  }
  return result;
}

function requiredEntryBytes(
  entries: ReadonlyMap<string, Uint8Array>,
  path: string,
): Uint8Array {
  const bytes = entries.get(path);
  if (!bytes) {
    throw new ConformanceFailure(
      "missing-entry",
      path,
      "A required golden archive entry is missing.",
    );
  }
  return bytes;
}

function assertRecord(
  value: unknown,
  location: string,
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConformanceFailure(
      "object-shape",
      location,
      "Expected a JSON object.",
    );
  }
}

function typedEntries<T extends Readonly<Record<string, string>>>(
  value: T,
): Array<{ [K in keyof T]: [K, T[K]] }[keyof T]> {
  return Object.entries(value) as Array<
    {
      [K in keyof T]: [K, T[K]];
    }[keyof T]
  >;
}
