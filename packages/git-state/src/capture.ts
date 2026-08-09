import { createHash } from "node:crypto";
import {
  constants as fsConstants,
  lstat,
  open,
  realpath,
  stat,
} from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";

import { encodeGitPatchArtifact } from "./patch-format.js";
import {
  GitStateCaptureError,
  type CapturedGitState,
  type GitCommandResult,
  type GitObjectFormat,
  type GitStateArtifact,
  type GitStateCaptureLimits,
  type GitStateCaptureOptions,
  type GitStateV0,
  type GitUntrackedEntryV0,
  type OwcDigest,
} from "./types.js";

const PATCH_PATH = "artifacts/git/tracked-changes.owc-git-patch";
const PATCH_MEDIA_TYPE = "application/vnd.openworkcommons.git-patch-v1";
const UNTRACKED_ARTIFACT_PREFIX = "artifacts/git/untracked/";
const UNTRACKED_MEDIA_TYPE = "application/octet-stream";
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

const DEFAULT_LIMITS: GitStateCaptureLimits = {
  commandTimeoutMs: 30_000,
  metadataOutputBytes: 1024 * 1024,
  statusOutputBytes: 8 * 1024 * 1024,
  patchSectionBytes: 64 * 1024 * 1024,
  patchArtifactBytes: 128 * 1024 * 1024,
  untrackedEntryCount: 10_000,
  untrackedFileBytes: 64 * 1024 * 1024,
  untrackedTotalBytes: 256 * 1024 * 1024,
};

const HARD_MAXIMUM_LIMITS: GitStateCaptureLimits = {
  commandTimeoutMs: 5 * 60_000,
  metadataOutputBytes: 16 * 1024 * 1024,
  statusOutputBytes: 64 * 1024 * 1024,
  patchSectionBytes: 512 * 1024 * 1024,
  patchArtifactBytes: 1024 * 1024 * 1024,
  untrackedEntryCount: 100_000,
  untrackedFileBytes: 512 * 1024 * 1024,
  untrackedTotalBytes: 2 * 1024 * 1024 * 1024,
};

const COMMON_GIT_ARGS = [
  "--no-pager",
  "--no-optional-locks",
  "--no-replace-objects",
  "-c",
  "color.ui=false",
  "-c",
  "core.attributesFile=",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.quotePath=true",
  "-c",
  "core.untrackedCache=false",
  "-c",
  "diff.algorithm=myers",
  "-c",
  "diff.external=",
  "-c",
  "diff.renames=false",
  "-c",
  "protocol.allow=never",
  "-c",
  "submodule.recurse=false",
] as const;

interface Observation {
  readonly state: GitStateV0;
  readonly statusDigest: OwcDigest;
  readonly patchArtifact: GitStateArtifact | null;
  readonly untrackedArtifacts: readonly GitStateArtifact[];
}

interface UntrackedCapture {
  readonly entries: readonly GitUntrackedEntryV0[];
  readonly artifacts: readonly GitStateArtifact[];
}

export async function captureGitState(
  options: GitStateCaptureOptions,
): Promise<CapturedGitState> {
  validateOptions(options);
  const limits = mergeLimits(options.limits);
  validateCaptureTime(options.capturedAt);
  const cwd = resolve(options.cwd);
  await requireDirectory(cwd);

  await requireInsideWorktree(options, cwd, limits);
  const reportedRepositoryRoot = await resolveRepositoryRoot(
    options,
    cwd,
    limits,
  );
  const repositoryRoot = await realpath(reportedRepositoryRoot);
  const realCwd = await realpath(cwd);
  if (!isPathWithin(repositoryRoot, realCwd)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git reported a repository root inconsistent with the requested directory.",
    );
  }

  const first = await observe(options, repositoryRoot, limits);
  const second = await observe(options, repositoryRoot, limits);
  if (!observationsEqual(first, second)) {
    throw new GitStateCaptureError(
      "REPOSITORY_CHANGED_DURING_CAPTURE",
      "The repository changed while its Git state was being captured.",
    );
  }

  const stateBytes = Buffer.from(JSON.stringify(first.state), "utf8");
  return {
    state: first.state,
    stateBytes,
    stateDigest: digest(stateBytes),
    patchArtifact: first.patchArtifact,
    untrackedArtifacts: first.untrackedArtifacts,
  };
}

async function observe(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  limits: GitStateCaptureLimits,
): Promise<Observation> {
  const objectFormatText = await runText(
    options,
    repositoryRoot,
    ["rev-parse", "--show-object-format"],
    limits.metadataOutputBytes,
    limits,
  );
  if (objectFormatText !== "sha1" && objectFormatText !== "sha256") {
    throw new GitStateCaptureError(
      "UNSUPPORTED_GIT_OBJECT_FORMAT",
      "Git reported an unsupported object format.",
    );
  }
  const objectFormat = objectFormatText;

  const shallowState = await runText(
    options,
    repositoryRoot,
    ["rev-parse", "--is-shallow-repository"],
    limits.metadataOutputBytes,
    limits,
  );
  if (shallowState !== "true" && shallowState !== "false") {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an invalid shallow-repository state.",
    );
  }
  if (shallowState === "true" && options.repositoryId === undefined) {
    throw new GitStateCaptureError(
      "UNSUPPORTED_REPOSITORY_STATE",
      "A shallow history requires an explicit stable repository identifier.",
    );
  }

  const headCommit = await resolveRevision(
    options,
    repositoryRoot,
    "HEAD",
    "commit",
    objectFormat,
    limits,
  );
  const headTree = await resolveRevision(
    options,
    repositoryRoot,
    headCommit,
    "tree",
    objectFormat,
    limits,
  );
  const baseRevision = options.baseRevision ?? headCommit;
  validateRevisionInput(baseRevision);
  const baseCommit = await resolveRevision(
    options,
    repositoryRoot,
    baseRevision,
    "commit",
    objectFormat,
    limits,
  );
  await requireAncestor(
    options,
    repositoryRoot,
    baseCommit,
    headCommit,
    limits,
  );

  const headRef = await resolveHeadRef(options, repositoryRoot, limits);
  const repositoryId =
    options.repositoryId ??
    (await deriveRepositoryId(
      options,
      repositoryRoot,
      objectFormat,
      headCommit,
      limits,
    ));
  validateRepositoryId(repositoryId);

  const unmerged = await runBytes(
    options,
    repositoryRoot,
    ["ls-files", "--unmerged", "-z"],
    limits.statusOutputBytes,
    limits,
  );
  if (unmerged.byteLength > 0) {
    throw new GitStateCaptureError(
      "UNSUPPORTED_REPOSITORY_STATE",
      "An unmerged index cannot be represented by the v0 Git-state object.",
    );
  }

  const gitlinks = await runBytes(
    options,
    repositoryRoot,
    ["ls-files", "--stage", "-z"],
    limits.statusOutputBytes,
    limits,
  );
  if (containsGitlink(gitlinks)) {
    throw new GitStateCaptureError(
      "UNSUPPORTED_REPOSITORY_STATE",
      "Submodule worktrees are outside the exact v0 capture boundary.",
    );
  }

  const indexFlags = await runBytes(
    options,
    repositoryRoot,
    ["ls-files", "-v", "-z"],
    limits.statusOutputBytes,
    limits,
  );
  if (containsHiddenIndexEntry(indexFlags)) {
    throw new GitStateCaptureError(
      "UNSUPPORTED_REPOSITORY_STATE",
      "Assume-unchanged and skip-worktree index entries are outside exact v0 capture.",
    );
  }

  await assertNoConfiguredContentFilters(options, repositoryRoot, limits);

  const status = await runBytes(
    options,
    repositoryRoot,
    [
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
      "--ignored=no",
      "--ignore-submodules=none",
    ],
    limits.statusOutputBytes,
    limits,
  );
  const indexPatch = await runBytes(
    options,
    repositoryRoot,
    [
      "diff",
      "--cached",
      "--binary",
      "--full-index",
      "--no-color",
      "--no-ext-diff",
      "--no-renames",
      "--no-textconv",
      "--no-indent-heuristic",
      "--inter-hunk-context=0",
      "--unified=3",
      "--src-prefix=a/",
      "--dst-prefix=b/",
      headCommit,
      "--",
    ],
    limits.patchSectionBytes,
    limits,
  );
  const worktreePatch = await runBytes(
    options,
    repositoryRoot,
    [
      "diff",
      "--binary",
      "--full-index",
      "--no-color",
      "--no-ext-diff",
      "--no-renames",
      "--no-textconv",
      "--no-indent-heuristic",
      "--inter-hunk-context=0",
      "--unified=3",
      "--src-prefix=a/",
      "--dst-prefix=b/",
      "--",
    ],
    limits.patchSectionBytes,
    limits,
  );
  const untracked = await captureUntracked(options, repositoryRoot, limits);

  const representedDirty =
    indexPatch.byteLength > 0 ||
    worktreePatch.byteLength > 0 ||
    untracked.entries.length > 0;
  if (status.byteLength > 0 !== representedDirty) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git status reported changes not represented by the v0 capture.",
    );
  }

  const patchBytes =
    indexPatch.byteLength > 0 || worktreePatch.byteLength > 0
      ? encodeGitPatchArtifact(
          { index: indexPatch, worktree: worktreePatch },
          limits.patchArtifactBytes,
        )
      : null;
  const patchArtifact = patchBytes
    ? artifact(PATCH_PATH, PATCH_MEDIA_TYPE, patchBytes)
    : null;

  const worktree: GitStateV0["worktree"] = patchArtifact
    ? {
        clean: false,
        patch: {
          path: patchArtifact.path,
          digest: patchArtifact.digest,
          byte_length: patchArtifact.byteLength,
        },
        untracked: untracked.entries,
      }
    : {
        clean: !representedDirty,
        untracked: untracked.entries,
      };

  return {
    state: {
      schema_version: "0.1",
      repository_id: repositoryId,
      object_format: objectFormat,
      captured_at: options.capturedAt,
      base_commit: baseCommit,
      head_commit: headCommit,
      head_tree: headTree,
      head_ref: headRef,
      worktree,
    },
    statusDigest: digest(status),
    patchArtifact,
    untrackedArtifacts: untracked.artifacts,
  };
}

async function captureUntracked(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  limits: GitStateCaptureLimits,
): Promise<UntrackedCapture> {
  const listing = await runBytes(
    options,
    repositoryRoot,
    ["ls-files", "--others", "--exclude-standard", "-z"],
    limits.statusOutputBytes,
    limits,
  );
  const paths = parseNulPaths(listing);
  if (paths.length > limits.untrackedEntryCount) {
    throw new GitStateCaptureError(
      "OUTPUT_LIMIT_EXCEEDED",
      "The untracked manifest exceeded the configured entry limit.",
    );
  }

  paths.sort(compareUtf8);
  const entries: GitUntrackedEntryV0[] = [];
  const artifacts: GitStateArtifact[] = [];
  let totalBytes = 0;
  for (const path of paths) {
    validateUntrackedPath(path);
    let bytes: Uint8Array;
    try {
      bytes = await readSafeUntrackedFile(
        repositoryRoot,
        path,
        limits.untrackedFileBytes,
      );
    } catch (error) {
      if (error instanceof GitStateCaptureError) throw error;
      throw new GitStateCaptureError(
        "REPOSITORY_CHANGED_DURING_CAPTURE",
        "An untracked file became unavailable during capture.",
      );
    }
    totalBytes += bytes.byteLength;
    if (totalBytes > limits.untrackedTotalBytes) {
      throw new GitStateCaptureError(
        "OUTPUT_LIMIT_EXCEEDED",
        "Untracked files exceeded the configured aggregate byte limit.",
      );
    }
    const fileDigest = digest(bytes);
    const commitment = {
      path,
      digest: fileDigest,
      byte_length: bytes.byteLength,
    } as const;
    if (options.untrackedPolicy === "include") {
      const capturedArtifact = artifact(
        untrackedArtifactPath(path),
        UNTRACKED_MEDIA_TYPE,
        bytes,
      );
      artifacts.push(capturedArtifact);
      entries.push({
        ...commitment,
        included: true,
        artifact: {
          path: capturedArtifact.path,
          digest: capturedArtifact.digest,
          byte_length: capturedArtifact.byteLength,
        },
      });
    } else {
      entries.push({ ...commitment, included: false });
    }
  }
  return { entries, artifacts };
}

async function assertNoConfiguredContentFilters(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  limits: GitStateCaptureLimits,
): Promise<void> {
  const result = await runGit(
    options,
    repositoryRoot,
    [
      "config",
      "--null",
      "--name-only",
      "--get-regexp",
      "^filter\\..*\\.(clean|smudge|process)$",
    ],
    limits.metadataOutputBytes,
    limits,
    [0, 1],
  );
  if (result.stdout.byteLength > 0) {
    throw new GitStateCaptureError(
      "UNSUPPORTED_REPOSITORY_STATE",
      "Configured Git content filters are outside the exact v0 capture boundary.",
    );
  }
  if (result.exitCode !== 1) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an ambiguous content-filter configuration result.",
    );
  }
}

async function readSafeUntrackedFile(
  repositoryRoot: string,
  relativePath: string,
  maximumBytes: number,
): Promise<Uint8Array> {
  const segments = relativePath.split("/");
  let cursor = repositoryRoot;
  for (const segment of segments.slice(0, -1)) {
    cursor = resolve(cursor, segment);
    const metadata = await lstat(cursor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new GitStateCaptureError(
        "UNSAFE_UNTRACKED_PATH",
        "An untracked path traverses a non-directory or symbolic link.",
      );
    }
  }

  const absolutePath = resolve(repositoryRoot, relativePath);
  if (!isPathWithin(repositoryRoot, absolutePath)) {
    throw new GitStateCaptureError(
      "UNSAFE_UNTRACKED_PATH",
      "An untracked path escapes the repository root.",
    );
  }

  let handle;
  try {
    handle = await open(
      absolutePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
  } catch {
    throw new GitStateCaptureError(
      "UNSAFE_UNTRACKED_PATH",
      "An untracked file could not be opened without following links.",
    );
  }

  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maximumBytes) {
      throw new GitStateCaptureError(
        before.size > maximumBytes
          ? "OUTPUT_LIMIT_EXCEEDED"
          : "UNSAFE_UNTRACKED_PATH",
        before.size > maximumBytes
          ? "An untracked file exceeded the configured byte limit."
          : "Only regular untracked files can be captured.",
      );
    }
    const resolvedFile = await realpath(absolutePath);
    if (!isPathWithin(repositoryRoot, resolvedFile)) {
      throw new GitStateCaptureError(
        "UNSAFE_UNTRACKED_PATH",
        "An untracked file resolves outside the repository root.",
      );
    }
    const bytes = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const read = await handle.read(
        bytes,
        offset,
        bytes.byteLength - offset,
        offset,
      );
      if (read.bytesRead === 0) break;
      offset += read.bytesRead;
    }
    if (offset !== bytes.byteLength) {
      throw new GitStateCaptureError(
        "REPOSITORY_CHANGED_DURING_CAPTURE",
        "An untracked file changed while it was being read.",
      );
    }
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new GitStateCaptureError(
        "REPOSITORY_CHANGED_DURING_CAPTURE",
        "An untracked file changed while it was being read.",
      );
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function requireInsideWorktree(
  options: GitStateCaptureOptions,
  cwd: string,
  limits: GitStateCaptureLimits,
): Promise<void> {
  let commandResult: GitCommandResult;
  try {
    commandResult = await options.runner.run({
      args: [...COMMON_GIT_ARGS, "rev-parse", "--is-inside-work-tree"],
      cwd,
      maxStdoutBytes: limits.metadataOutputBytes,
      timeoutMs: limits.commandTimeoutMs,
    });
  } catch (error) {
    if (error instanceof GitStateCaptureError) throw error;
    throw new GitStateCaptureError(
      "SUBPROCESS_ERROR",
      "Git could not inspect the requested working directory.",
    );
  }
  if (commandResult.stdout.byteLength > limits.metadataOutputBytes) {
    throw new GitStateCaptureError(
      "OUTPUT_LIMIT_EXCEEDED",
      "The Git worktree probe exceeded its byte limit.",
    );
  }
  if (commandResult.exitCode === null || commandResult.signal !== null) {
    throw new GitStateCaptureError(
      "SUBPROCESS_ERROR",
      "The Git worktree probe did not exit normally.",
    );
  }
  if (commandResult.exitCode !== 0) {
    throw new GitStateCaptureError(
      "NOT_A_GIT_WORKTREE",
      "The requested directory is not inside a Git worktree.",
    );
  }
  if (commandResult.stderr.byteLength > 0) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "The Git worktree probe emitted unexpected diagnostic output.",
    );
  }
  const result = decodeSingleLine(commandResult.stdout);
  if (result !== "true") {
    throw new GitStateCaptureError(
      "NOT_A_GIT_WORKTREE",
      "The requested directory is not inside a Git worktree.",
    );
  }
}

async function resolveRepositoryRoot(
  options: GitStateCaptureOptions,
  cwd: string,
  limits: GitStateCaptureLimits,
): Promise<string> {
  const output = await runText(
    options,
    cwd,
    ["rev-parse", "--path-format=absolute", "--show-toplevel"],
    limits.metadataOutputBytes,
    limits,
  );
  if (!isAbsolute(output)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git did not report an absolute worktree root.",
    );
  }
  return resolve(output);
}

async function resolveRevision(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  revision: string,
  kind: "commit" | "tree",
  objectFormat: GitObjectFormat,
  limits: GitStateCaptureLimits,
): Promise<string> {
  let output: string;
  try {
    output = await runText(
      options,
      repositoryRoot,
      ["rev-parse", "--verify", "--end-of-options", `${revision}^{${kind}}`],
      limits.metadataOutputBytes,
      limits,
    );
  } catch (error) {
    if (error instanceof GitStateCaptureError) {
      throw new GitStateCaptureError(
        "UNRESOLVED_REVISION",
        `The selected ${kind} revision could not be resolved.`,
      );
    }
    throw error;
  }
  const oidLength = objectFormat === "sha1" ? 40 : 64;
  if (!new RegExp(`^[a-f0-9]{${oidLength}}$`).test(output)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      `Git returned an invalid ${kind} object identifier.`,
    );
  }
  return output;
}

async function requireAncestor(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  baseCommit: string,
  headCommit: string,
  limits: GitStateCaptureLimits,
): Promise<void> {
  const result = await runGit(
    options,
    repositoryRoot,
    ["merge-base", "--is-ancestor", baseCommit, headCommit],
    limits.metadataOutputBytes,
    limits,
    [0, 1],
  );
  if (result.exitCode === 1) {
    throw new GitStateCaptureError(
      "BASE_NOT_ANCESTOR",
      "The selected base commit is not an ancestor of HEAD.",
    );
  }
}

async function resolveHeadRef(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  limits: GitStateCaptureLimits,
): Promise<string | null> {
  const result = await runGit(
    options,
    repositoryRoot,
    ["symbolic-ref", "--quiet", "HEAD"],
    limits.metadataOutputBytes,
    limits,
    [0, 1],
  );
  if (result.exitCode === 1) return null;
  const value = decodeSingleLine(result.stdout);
  if (
    !value.startsWith("refs/") ||
    value.length > 1024 ||
    /[\0-\x1f\x7f]/.test(value)
  ) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an invalid symbolic HEAD.",
    );
  }
  return value;
}

async function deriveRepositoryId(
  options: GitStateCaptureOptions,
  repositoryRoot: string,
  objectFormat: GitObjectFormat,
  headCommit: string,
  limits: GitStateCaptureLimits,
): Promise<string> {
  const output = await runBytes(
    options,
    repositoryRoot,
    ["rev-list", "--max-parents=0", headCommit, "--"],
    limits.metadataOutputBytes,
    limits,
  );
  const oidLength = objectFormat === "sha1" ? 40 : 64;
  const roots = decodeLineList(output).sort();
  if (
    roots.length === 0 ||
    roots.some((root) => !new RegExp(`^[a-f0-9]{${oidLength}}$`).test(root)) ||
    new Set(roots).size !== roots.length
  ) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an invalid root-commit set.",
    );
  }
  const identityDigest = createHash("sha256")
    .update(Buffer.from(roots.join("\0"), "ascii"))
    .digest("hex");
  return `urn:owc:repository:git:${objectFormat}:${identityDigest}`;
}

async function runText(
  options: GitStateCaptureOptions,
  cwd: string,
  args: readonly string[],
  maximumBytes: number,
  limits: GitStateCaptureLimits,
): Promise<string> {
  const bytes = await runBytes(options, cwd, args, maximumBytes, limits);
  return decodeSingleLine(bytes);
}

async function runBytes(
  options: GitStateCaptureOptions,
  cwd: string,
  args: readonly string[],
  maximumBytes: number,
  limits: GitStateCaptureLimits,
): Promise<Uint8Array> {
  const result = await runGit(options, cwd, args, maximumBytes, limits, [0]);
  return result.stdout;
}

async function runGit(
  options: GitStateCaptureOptions,
  cwd: string,
  args: readonly string[],
  maximumBytes: number,
  limits: GitStateCaptureLimits,
  acceptedExitCodes: readonly number[],
): Promise<GitCommandResult> {
  let result: GitCommandResult;
  try {
    result = await options.runner.run({
      args: [...COMMON_GIT_ARGS, ...args],
      cwd,
      maxStdoutBytes: maximumBytes,
      timeoutMs: limits.commandTimeoutMs,
    });
  } catch (error) {
    if (error instanceof GitStateCaptureError) throw error;
    throw new GitStateCaptureError(
      "SUBPROCESS_ERROR",
      "A Git command failed before returning a result.",
    );
  }
  if (
    result.exitCode === null ||
    !acceptedExitCodes.includes(result.exitCode) ||
    result.signal !== null
  ) {
    throw new GitStateCaptureError(
      "SUBPROCESS_ERROR",
      "A Git command returned an unsuccessful result.",
    );
  }
  if (result.stdout.byteLength > maximumBytes) {
    throw new GitStateCaptureError(
      "OUTPUT_LIMIT_EXCEEDED",
      "A Git command returned more bytes than permitted.",
    );
  }
  if (result.stderr.byteLength > 0) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "A Git command emitted unexpected diagnostic output.",
    );
  }
  return result;
}

function decodeSingleLine(bytes: Uint8Array): string {
  let decoded: string;
  try {
    decoded = STRICT_UTF8.decode(bytes);
  } catch {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned non-UTF-8 metadata.",
    );
  }
  const value = decoded.endsWith("\n") ? decoded.slice(0, -1) : decoded;
  if (value.length === 0 || /[\r\n\0]/.test(value)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned ambiguous line-oriented metadata.",
    );
  }
  return value;
}

function decodeLineList(bytes: Uint8Array): string[] {
  let decoded: string;
  try {
    decoded = STRICT_UTF8.decode(bytes);
  } catch {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned non-UTF-8 line-oriented metadata.",
    );
  }
  if (!decoded.endsWith("\n") || /\r|\0/.test(decoded)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned ambiguous line-oriented metadata.",
    );
  }
  const lines = decoded.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an empty line-oriented metadata record.",
    );
  }
  return lines;
}

function parseNulPaths(bytes: Uint8Array): string[] {
  if (bytes.byteLength === 0) return [];
  if (bytes[bytes.byteLength - 1] !== 0) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned an unterminated untracked-path list.",
    );
  }
  const paths: string[] = [];
  let start = 0;
  for (let index = 0; index < bytes.byteLength; index++) {
    if (bytes[index] !== 0) continue;
    if (index === start) {
      throw new GitStateCaptureError(
        "AMBIGUOUS_GIT_OUTPUT",
        "Git returned an empty untracked path.",
      );
    }
    try {
      paths.push(STRICT_UTF8.decode(bytes.slice(start, index)));
    } catch {
      throw new GitStateCaptureError(
        "UNSAFE_UNTRACKED_PATH",
        "An untracked path is not valid UTF-8.",
      );
    }
    start = index + 1;
  }
  if (new Set(paths).size !== paths.length) {
    throw new GitStateCaptureError(
      "AMBIGUOUS_GIT_OUTPUT",
      "Git returned duplicate untracked paths.",
    );
  }
  return paths;
}

function containsGitlink(bytes: Uint8Array): boolean {
  const records = Buffer.from(bytes).toString("binary").split("\0");
  records.pop();
  return records.some((record) => record.startsWith("160000 "));
}

function containsHiddenIndexEntry(bytes: Uint8Array): boolean {
  const records = Buffer.from(bytes).toString("binary").split("\0");
  records.pop();
  return records.some((record) => {
    const tag = record.charAt(0);
    return tag === "S" || /^[a-z]$/.test(tag);
  });
}

function validateUntrackedPath(path: string): void {
  if (
    path.length > 1024 - UNTRACKED_ARTIFACT_PREFIX.length ||
    !/^(?!\/)(?!.*\\)(?!.*(?:^|\/)(?:\.|\.\.)(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(
      path,
    )
  ) {
    throw new GitStateCaptureError(
      "UNSAFE_UNTRACKED_PATH",
      "An untracked path is outside the v0 safe relative-path profile.",
    );
  }
}

function untrackedArtifactPath(repositoryPath: string): string {
  return `${UNTRACKED_ARTIFACT_PREFIX}${repositoryPath}`;
}

function validateRevisionInput(revision: string): void {
  if (
    revision.length === 0 ||
    revision.length > 1024 ||
    revision.startsWith("-") ||
    /[\0-\x20\x7f]/.test(revision)
  ) {
    throw new GitStateCaptureError(
      "INVALID_INPUT",
      "The selected base revision is invalid.",
    );
  }
}

function validateRepositoryId(repositoryId: string): void {
  if (
    repositoryId.length === 0 ||
    repositoryId.length > 512 ||
    /[\0-\x1f\x7f]/.test(repositoryId)
  ) {
    throw new GitStateCaptureError(
      "INVALID_INPUT",
      "The repository identifier is invalid.",
    );
  }
}

function validateCaptureTime(capturedAt: string): void {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(
      capturedAt,
    );
  if (!match) {
    throw new GitStateCaptureError(
      "INVALID_CAPTURE_TIME",
      "capturedAt must be an explicit RFC 3339 timestamp.",
    );
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = Number(match[7] ?? 0);
  const offsetMinute = Number(match[8] ?? 0);
  const daysInMonth = [
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
  ][month - 1];
  if (
    daysInMonth === undefined ||
    day < 1 ||
    day > daysInMonth ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new GitStateCaptureError(
      "INVALID_CAPTURE_TIME",
      "capturedAt must be a real RFC 3339 calendar timestamp.",
    );
  }
}

function validateOptions(options: GitStateCaptureOptions): void {
  if (
    typeof options !== "object" ||
    options === null ||
    typeof options.cwd !== "string" ||
    typeof options.capturedAt !== "string" ||
    typeof options.runner !== "object" ||
    options.runner === null ||
    typeof options.runner.run !== "function" ||
    (options.untrackedPolicy !== undefined &&
      options.untrackedPolicy !== "manifest-only" &&
      options.untrackedPolicy !== "include")
  ) {
    throw new GitStateCaptureError(
      "INVALID_INPUT",
      "Git-state capture options are invalid.",
    );
  }
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function mergeLimits(
  requested: Partial<GitStateCaptureLimits> | undefined,
): GitStateCaptureLimits {
  const knownNames = new Set(Object.keys(DEFAULT_LIMITS));
  if (
    requested &&
    Object.keys(requested).some((name) => !knownNames.has(name))
  ) {
    throw new GitStateCaptureError(
      "INVALID_INPUT",
      "The capture limits contain an unknown field.",
    );
  }
  const limits = { ...DEFAULT_LIMITS, ...requested };
  for (const [name, value] of Object.entries(limits)) {
    const maximum = HARD_MAXIMUM_LIMITS[name as keyof GitStateCaptureLimits];
    if (
      !Number.isSafeInteger(value) ||
      value <= 0 ||
      maximum === undefined ||
      value > maximum
    ) {
      throw new GitStateCaptureError(
        "INVALID_INPUT",
        `The ${name} capture limit is outside the accepted safe range.`,
      );
    }
  }
  return limits;
}

async function requireDirectory(path: string): Promise<void> {
  try {
    const metadata = await stat(path);
    if (!metadata.isDirectory()) throw new Error("not a directory");
  } catch {
    throw new GitStateCaptureError(
      "INVALID_INPUT",
      "The capture working directory does not exist or is not a directory.",
    );
  }
}

function observationsEqual(left: Observation, right: Observation): boolean {
  if (JSON.stringify(left.state) !== JSON.stringify(right.state)) return false;
  if (left.statusDigest !== right.statusDigest) return false;
  if (!artifactsEqual(left.patchArtifact, right.patchArtifact)) return false;
  if (left.untrackedArtifacts.length !== right.untrackedArtifacts.length) {
    return false;
  }
  return left.untrackedArtifacts.every((artifact, index) =>
    artifactsEqual(artifact, right.untrackedArtifacts[index] ?? null),
  );
}

function artifactsEqual(
  left: GitStateArtifact | null,
  right: GitStateArtifact | null,
): boolean {
  if (left === null || right === null) return left === right;
  return (
    left.path === right.path &&
    left.mediaType === right.mediaType &&
    left.digest === right.digest &&
    left.byteLength === right.byteLength &&
    Buffer.from(left.bytes).equals(Buffer.from(right.bytes))
  );
}

function artifact(
  path: string,
  mediaType: string,
  bytes: Uint8Array,
): GitStateArtifact {
  return {
    path,
    mediaType,
    bytes,
    digest: digest(bytes),
    byteLength: bytes.byteLength,
  };
}

function digest(bytes: Uint8Array): OwcDigest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function isPathWithin(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return (
    pathFromRoot === "" ||
    (!pathFromRoot.startsWith(`..${sep}`) &&
      pathFromRoot !== ".." &&
      !isAbsolute(pathFromRoot))
  );
}
