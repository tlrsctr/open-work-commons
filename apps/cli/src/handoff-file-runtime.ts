import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rmdir,
  rm,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { TextDecoder } from "node:util";

import {
  DEFAULT_VERIFIER_LIMITS,
  isSafeArchivePath,
  parseJsonSafely,
  verifyLogicalArchive,
  type LogicalArchive,
} from "../../../packages/archive/src/index.js";
import type { OperatorHandoffPlan } from "../../../packages/handoff/src/index.js";

const MAX_PLAN_BYTES = 256 * 1024;
const MAX_ENTIRE_DETAIL_BYTES = 256 * 1024;
const INPUT_JSON_LIMITS = {
  maxDepth: 64,
  maxStringBytes: 128 * 1024,
} as const;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

export type HandoffFileErrorCode =
  | "input_unavailable"
  | "input_resource_limit"
  | "plan_invalid"
  | "output_exists"
  | "output_unsafe"
  | "archive_invalid"
  | "archive_publish_failed";

export class HandoffFileError extends Error {
  constructor(readonly code: HandoffFileErrorCode) {
    super(code);
    this.name = "HandoffFileError";
  }
}

export interface PublishedArchiveSummary {
  readonly entryCount: number;
  readonly totalBytes: number;
}

export interface HandoffFileRuntime {
  readPlan(path: string): Promise<OperatorHandoffPlan>;
  readEntireCheckpointDetail(path: string): Promise<string>;
  assertOutputAvailable(path: string): Promise<void>;
  publishArchive(
    path: string,
    archive: LogicalArchive,
  ): Promise<PublishedArchiveSummary>;
}

export function createHandoffFileRuntime(
  protectedWorkspacePath?: string,
): HandoffFileRuntime {
  return {
    async readPlan(path) {
      const bytes = await readBoundedRegularFile(path, MAX_PLAN_BYTES);
      try {
        const parsed = parseJsonSafely(bytes, INPUT_JSON_LIMITS);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new TypeError("invalid plan");
        }
        return parsed as unknown as OperatorHandoffPlan;
      } catch {
        throw new HandoffFileError("plan_invalid");
      }
    },
    async readEntireCheckpointDetail(path) {
      const bytes = await readBoundedRegularFile(path, MAX_ENTIRE_DETAIL_BYTES);
      try {
        return STRICT_UTF8.decode(bytes);
      } catch {
        throw new HandoffFileError("input_unavailable");
      }
    },
    async assertOutputAvailable(path) {
      const target = await resolveOutputTarget(path);
      await assertOutsidePrivateStore(target, protectedWorkspacePath);
      if (await pathExistsNoFollow(target)) {
        throw new HandoffFileError("output_exists");
      }
    },
    async publishArchive(path, archive) {
      const target = await resolveOutputTarget(path);
      await assertOutsidePrivateStore(target, protectedWorkspacePath);
      return publishArchiveDirectory(target, archive);
    },
  };
}

async function readBoundedRegularFile(
  path: string,
  maximumBytes: number,
): Promise<Uint8Array> {
  let handle;
  try {
    handle = await open(
      resolve(path),
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new HandoffFileError("input_unavailable");
    if (metadata.size > maximumBytes) {
      throw new HandoffFileError("input_resource_limit");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > maximumBytes) {
      throw new HandoffFileError("input_resource_limit");
    }
    return new Uint8Array(bytes);
  } catch (error) {
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("input_unavailable");
  } finally {
    await handle?.close();
  }
}

async function publishArchiveDirectory(
  outputPath: string,
  archive: LogicalArchive,
): Promise<PublishedArchiveSummary> {
  assertPublishableArchive(archive);
  const target = await resolveOutputTarget(outputPath);
  if (await pathExistsNoFollow(target)) {
    throw new HandoffFileError("output_exists");
  }
  const parent = dirname(target);
  const reservation = await reserveOutputTarget(target);
  let staging: string | null = null;
  let published = false;
  try {
    staging = await mkdtemp(join(parent, ".owc-handoff-staging-"));
    await chmod(staging, 0o700);
    await writePrivateFile(
      staging,
      "archive-manifest.json",
      archive.manifestBytes,
    );
    for (const entry of [...archive.entries].sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
    )) {
      await writePrivateFile(staging, entry.path, entry.bytes);
    }

    // The empty directory was claimed with one exclusive mkdir before any
    // archive write. Requiring the same inode to remain empty prevents two CLI
    // publishers from racing and makes the following replacement ours alone.
    await assertOwnedEmptyReservation(target, reservation);
    try {
      await rename(staging, target);
      published = true;
    } catch {
      throw new HandoffFileError("archive_publish_failed");
    }

    return {
      entryCount: archive.entries.length,
      totalBytes:
        archive.manifestBytes.byteLength +
        archive.entries.reduce(
          (total, entry) => total + entry.bytes.byteLength,
          0,
        ),
    };
  } catch (error) {
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("archive_publish_failed");
  } finally {
    if (!published && staging !== null) {
      await rm(staging, { recursive: true, force: true }).catch(
        () => undefined,
      );
    }
    if (!published) {
      await releaseOwnedEmptyReservation(target, reservation);
    }
  }
}

async function assertOutsidePrivateStore(
  target: string,
  workspacePath: string | undefined,
): Promise<void> {
  if (workspacePath === undefined) return;
  try {
    const workspace = await realpath(resolve(workspacePath));
    const privateStore = join(workspace, ".owc");
    const child = relative(privateStore, target);
    if (
      child === "" ||
      (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))
    ) {
      throw new HandoffFileError("output_unsafe");
    }
  } catch (error) {
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("output_unsafe");
  }
}

interface OutputReservation {
  readonly device: number;
  readonly inode: number;
}

async function reserveOutputTarget(target: string): Promise<OutputReservation> {
  try {
    await mkdir(target, { mode: 0o700 });
  } catch (error) {
    if (isAlreadyExists(error)) throw new HandoffFileError("output_exists");
    throw new HandoffFileError("output_unsafe");
  }
  try {
    await chmod(target, 0o700);
    const metadata = await lstat(target);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new HandoffFileError("output_unsafe");
    }
    return { device: metadata.dev, inode: metadata.ino };
  } catch (error) {
    await rmdir(target).catch(() => undefined);
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("output_unsafe");
  }
}

async function assertOwnedEmptyReservation(
  target: string,
  reservation: OutputReservation,
): Promise<void> {
  try {
    const metadata = await lstat(target);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      metadata.dev !== reservation.device ||
      metadata.ino !== reservation.inode ||
      (await readdir(target)).length !== 0
    ) {
      throw new HandoffFileError("output_unsafe");
    }
  } catch (error) {
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("output_unsafe");
  }
}

async function releaseOwnedEmptyReservation(
  target: string,
  reservation: OutputReservation,
): Promise<void> {
  try {
    await assertOwnedEmptyReservation(target, reservation);
    await rmdir(target);
  } catch {
    // Never remove a destination that changed identity or acquired content.
  }
}

function assertPublishableArchive(archive: LogicalArchive): void {
  if (
    !archive ||
    !(archive.manifestBytes instanceof Uint8Array) ||
    archive.manifestBytes.byteLength >
      DEFAULT_VERIFIER_LIMITS.maxManifestBytes ||
    !Array.isArray(archive.entries) ||
    archive.entries.length > DEFAULT_VERIFIER_LIMITS.maxEntryCount
  ) {
    throw new HandoffFileError("archive_invalid");
  }
  const seen = new Set<string>();
  let expandedBytes = 0;
  for (const entry of archive.entries) {
    if (
      !entry ||
      !isSafeArchivePath(entry.path) ||
      seen.has(entry.path) ||
      !(entry.bytes instanceof Uint8Array) ||
      (entry.kind !== undefined && entry.kind !== "file") ||
      entry.bytes.byteLength > DEFAULT_VERIFIER_LIMITS.maxEntryBytes
    ) {
      throw new HandoffFileError("archive_invalid");
    }
    seen.add(entry.path);
    expandedBytes += entry.bytes.byteLength;
    if (expandedBytes > DEFAULT_VERIFIER_LIMITS.maxExpandedBytes) {
      throw new HandoffFileError("archive_invalid");
    }
  }
  const verification = verifyLogicalArchive(archive);
  if (!verification.integrity.valid || !verification.signer.signatureValid) {
    throw new HandoffFileError("archive_invalid");
  }
}

async function writePrivateFile(
  root: string,
  archivePath: string,
  bytes: Uint8Array,
): Promise<void> {
  if (!isSafeArchivePath(archivePath)) {
    throw new HandoffFileError("archive_invalid");
  }
  const segments = archivePath.split("/");
  const fileName = segments.pop();
  if (!fileName) throw new HandoffFileError("archive_invalid");
  let directory = root;
  for (const segment of segments) {
    directory = join(directory, segment);
    await mkdir(directory, { mode: 0o700 }).catch(async (error) => {
      if (!isAlreadyExists(error)) throw error;
      const metadata = await lstat(directory);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw error;
    });
    await chmod(directory, 0o700);
    assertBeneath(root, directory);
  }
  const target = join(directory, fileName);
  assertBeneath(root, target);
  let handle;
  try {
    handle = await open(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.chmod(0o600);
  } finally {
    await handle?.close();
  }
}

async function resolveOutputTarget(path: string): Promise<string> {
  try {
    const requested = resolve(path);
    const name = basename(requested);
    if (!name || name === "." || name === "..") {
      throw new HandoffFileError("output_unsafe");
    }
    const parent = await realpath(dirname(requested));
    const metadata = await lstat(parent);
    if (!metadata.isDirectory()) {
      throw new HandoffFileError("output_unsafe");
    }
    const target = join(parent, name);
    assertBeneath(parent, target);
    return target;
  } catch (error) {
    if (error instanceof HandoffFileError) throw error;
    throw new HandoffFileError("output_unsafe");
  }
}

function assertBeneath(root: string, candidate: string): void {
  const child = relative(root, candidate);
  if (
    child === "" ||
    isAbsolute(child) ||
    child === ".." ||
    child.startsWith(`..${sep}`)
  ) {
    throw new HandoffFileError("output_unsafe");
  }
}

async function pathExistsNoFollow(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw new HandoffFileError("output_unsafe");
  }
}

function isMissing(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function isAlreadyExists(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "EEXIST"
  );
}
