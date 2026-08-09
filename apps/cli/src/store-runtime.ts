import {
  DEFAULT_STORE_LIMITS,
  LocalWorkspaceStore,
  type StoreHealthReport,
  type StorePolicy,
} from "../../../packages/store/src/index.js";
import {
  createExactHandoffStorePolicy,
  persistApprovedHandoff,
  type HandoffStorePersistenceResult,
  type HandoffStoreWritePlan,
} from "../../../packages/handoff/src/index.js";

export interface WorkspaceStoreRuntime {
  initialize(workspacePath: string): Promise<{ store_path: string }>;
  health(workspacePath: string): Promise<StoreHealthReport>;
  persistApprovedHandoff?(
    workspacePath: string,
    plan: HandoffStoreWritePlan,
  ): Promise<HandoffStorePersistenceResult>;
}

// The archive verifier accepts at most one 64 MiB logical entry. Making this
// store decision explicit avoids silently truncating or dropping an approved
// Git artifact that is larger than the general-purpose 16 MiB store default.
const HANDOFF_STORE_MAX_BLOB_BYTES = 64 * 1024 * 1024;

const denyContentPolicy: StorePolicy = {
  authorizeAndRedactBlob: () => ({ decision: "deny" }),
  authorizeAndRedactEvent: () => ({ decision: "deny" }),
  authorizeRead: () => ({ decision: "deny" }),
};

export function createWorkspaceStoreRuntime(): WorkspaceStoreRuntime {
  return {
    async initialize(workspacePath) {
      const store = await LocalWorkspaceStore.initialize(workspacePath, {
        policy: denyContentPolicy,
      });
      return { store_path: store.storePath };
    },
    async health(workspacePath) {
      const store = await LocalWorkspaceStore.open(workspacePath, {
        policy: denyContentPolicy,
      });
      return store.healthCheck();
    },
    async persistApprovedHandoff(workspacePath, plan) {
      if (
        plan.blobs.some(
          (blob) => blob.byteLength > HANDOFF_STORE_MAX_BLOB_BYTES,
        )
      ) {
        throw new Error("handoff_store_blob_limit");
      }
      const store = await LocalWorkspaceStore.open(workspacePath, {
        policy: createExactHandoffStorePolicy(plan),
        limits: {
          ...DEFAULT_STORE_LIMITS,
          maxBlobBytes: HANDOFF_STORE_MAX_BLOB_BYTES,
        },
      });
      return persistApprovedHandoff(store, plan);
    },
  };
}
