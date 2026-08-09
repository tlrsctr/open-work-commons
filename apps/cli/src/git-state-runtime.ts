import {
  captureGitState,
  createNodeGitCommandRunner,
  verifyExternalGitState,
  type CapturedGitState,
  type ExternalGitStateVerification,
  type GitStateV0,
} from "../../../packages/git-state/src/index.js";
import {
  canonicalJsonBytes,
  sha256,
} from "../../../packages/archive/src/index.js";

export interface GitSnapshotRequest {
  readonly cwd: string;
  readonly capturedAt: string;
  readonly repositoryId?: string;
  readonly includeUntracked: boolean;
}

export interface GitStateRuntime {
  capture(request: GitSnapshotRequest): Promise<CapturedGitState>;
  verify(request: {
    readonly cwd: string;
    readonly declaredState: GitStateV0;
  }): Promise<ExternalGitStateVerification>;
}

/**
 * The CLI's production adapter for exact local Git-state capture.
 *
 * The package runner disables network protocols, hooks, external diff helpers,
 * replacement objects, optional index locks, and interactive prompting. This
 * adapter only supplies the process boundary; it does not persist artifacts.
 */
export function createGitStateRuntime(): GitStateRuntime {
  const runner = createNodeGitCommandRunner();
  return {
    async capture(request) {
      const captured = await captureGitState({
        cwd: request.cwd,
        capturedAt: request.capturedAt,
        runner,
        ...(request.repositoryId === undefined
          ? {}
          : { repositoryId: request.repositoryId }),
        untrackedPolicy: request.includeUntracked ? "include" : "manifest-only",
      });
      // The handoff archive contract binds RFC 8785 state bytes. Normalize the
      // capture package's exact state object at this adapter boundary without
      // changing any Git observation or artifact byte.
      const stateBytes = canonicalJsonBytes(captured.state);
      return {
        ...captured,
        stateBytes,
        stateDigest: sha256(stateBytes),
      };
    },
    verify(request) {
      return verifyExternalGitState({
        cwd: request.cwd,
        declaredState: request.declaredState,
        runner,
      });
    },
  };
}
