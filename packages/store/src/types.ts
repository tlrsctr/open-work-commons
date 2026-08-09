export type Digest = `sha256:${string}`;

export type MaybePromise<T> = T | Promise<T>;

export type PolicyDecision<T> =
  | { readonly decision: "allow"; readonly value: T }
  | { readonly decision: "deny" };

export interface BlobPolicyInput {
  /** A private copy. The policy may return different bytes after redaction. */
  readonly bytes: Uint8Array;
  readonly mediaType: string | null;
}

export interface EventPolicyInput {
  /** A bounded, JSON-only, deeply frozen copy of the proposed event. */
  readonly event: unknown;
}

export type StoreReadRequest =
  | { readonly kind: "blob"; readonly digest: Digest }
  | { readonly kind: "event"; readonly eventId: string };

export interface StorePolicy {
  authorizeAndRedactBlob(
    input: BlobPolicyInput,
  ): MaybePromise<PolicyDecision<Uint8Array>>;
  authorizeAndRedactEvent(
    input: EventPolicyInput,
  ): MaybePromise<PolicyDecision<unknown>>;
  authorizeRead(
    input: StoreReadRequest,
  ): MaybePromise<
    { readonly decision: "allow" } | { readonly decision: "deny" }
  >;
}

export interface StoreLimits {
  readonly maxBlobBytes: number;
  readonly maxEventBytes: number;
  readonly maxJsonDepth: number;
  readonly maxJsonStringBytes: number;
  readonly maxEvents: number;
  readonly maxBlobs: number;
  readonly maxHealthIssues: number;
}

export interface WorkspaceStoreOptions {
  readonly policy: StorePolicy;
  readonly limits?: Partial<StoreLimits>;
}

export interface BlobWriteInput {
  readonly bytes: Uint8Array;
  readonly mediaType?: string;
}

export interface BlobWriteResult {
  readonly digest: Digest;
  readonly byteLength: number;
  readonly relativePath: string;
  readonly disposition: "stored" | "existing";
}

export interface EventAppendResult {
  readonly eventId: string;
  readonly eventDigest: Digest;
  readonly sequence: number;
  readonly disposition: "stored" | "existing";
}

export interface EventActor {
  readonly id: string;
  readonly kind: "human" | "agent" | "service" | "device";
  readonly display_name?: string;
}

export interface EventProvider {
  readonly name: string;
  readonly adapter_version?: string;
  readonly provider_version?: string;
  readonly external_session_id?: string;
  readonly external_event_id?: string;
}

export interface EventSubject {
  readonly kind: string;
  readonly id: string;
}

export interface InlineEventPayload {
  readonly media_type: string;
  readonly digest: Digest;
  readonly inline: unknown;
  readonly path?: never;
}

export interface PathEventPayload {
  readonly media_type: string;
  readonly digest: Digest;
  readonly path: string;
  readonly inline?: never;
}

export interface NormalizedEventEnvelope {
  readonly schema_version: "0.1";
  readonly event_id: string;
  readonly event_type: string;
  readonly recorded_at: string;
  readonly effective_at?: string | null;
  readonly actor: EventActor;
  readonly space_id: string;
  readonly session_id: string;
  readonly sequence: number;
  readonly previous_event_id: string | null;
  readonly provider: EventProvider;
  readonly subject: EventSubject;
  readonly payload: InlineEventPayload | PathEventPayload;
  readonly sensitivity: "public" | "internal" | "private" | "restricted";
  readonly retention: {
    readonly class: "ephemeral" | "checkpoint" | "archive" | "legal-hold";
    readonly expires_at: string | null;
  };
  readonly extensions?: Readonly<Record<string, unknown>>;
}

export type HealthIssueCode =
  | "workspace_layout_invalid"
  | "workspace_permissions_invalid"
  | "store_busy"
  | "unexpected_entry"
  | "special_entry"
  | "resource_limit"
  | "event_invalid"
  | "event_path_mismatch"
  | "event_digest_conflict"
  | "event_chain_invalid"
  | "blob_missing"
  | "blob_path_invalid"
  | "blob_digest_mismatch";

export interface StoreHealthIssue {
  readonly code: HealthIssueCode;
  /** A digest-derived key or fixed structural location, never payload text. */
  readonly location: string;
  readonly message: string;
}

export interface StoreHealthReport {
  readonly ok: boolean;
  readonly checkedEvents: number;
  readonly checkedBlobs: number;
  readonly issues: readonly StoreHealthIssue[];
}
