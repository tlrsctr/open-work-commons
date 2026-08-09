import { randomBytes } from "node:crypto";
import { constants, type Dirent, type Stats } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { LocalStoreError, asSafeStoreError } from "./errors.js";

export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

const NO_FOLLOW = constants.O_NOFOLLOW;

export type PrivateEntrySafety =
  "safe" | "missing" | "unsafe_entry" | "unsafe_permissions";

/**
 * The local-file adapter deliberately refuses platforms where it cannot
 * enforce the same owner/mode/no-follow contract as the device identity store.
 */
export function assertSupportedLocalStorePlatform(): void {
  if (
    process.platform === "win32" ||
    typeof process.getuid !== "function" ||
    typeof NO_FOLLOW !== "number"
  ) {
    throw new LocalStoreError("unsupported_platform");
  }
}

/** Pure ownership/mode predicate, exported for non-privileged adversarial tests. */
export function hasExpectedPosixOwnerAndMode(
  status: Pick<Stats, "mode" | "uid">,
  expectedMode: number,
  expectedUid: number,
): boolean {
  return (status.mode & 0o7777) === expectedMode && status.uid === expectedUid;
}

export async function ensurePrivateDirectory(path: string): Promise<void> {
  assertSupportedLocalStorePlatform();
  let created = false;
  try {
    await mkdir(path, { mode: PRIVATE_DIRECTORY_MODE });
    created = true;
  } catch (error) {
    if (!isNodeError(error, "EEXIST")) {
      throw new LocalStoreError("invalid_workspace");
    }
  }

  try {
    // chmod is only a creation-time umask correction. Existing weak or
    // foreign-owned directories are rejected rather than silently repaired.
    if (created) await chmod(path, PRIVATE_DIRECTORY_MODE);
    await privateDirectoryStatus(path);
  } catch (error) {
    throw asSafeStoreError(error, "invalid_workspace");
  }
}

export async function assertPrivateDirectory(path: string): Promise<void> {
  assertSupportedLocalStorePlatform();
  try {
    await privateDirectoryStatus(path);
  } catch (error) {
    throw asSafeStoreError(error, "invalid_workspace");
  }
}

export async function inspectPrivateDirectory(
  path: string,
): Promise<PrivateEntrySafety> {
  assertSupportedLocalStorePlatform();
  try {
    const status = await lstat(path);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      return "unsafe_entry";
    }
    return ownerAndModeArePrivate(status, PRIVATE_DIRECTORY_MODE)
      ? "safe"
      : "unsafe_permissions";
  } catch (error) {
    return isNodeError(error, "ENOENT") ? "missing" : "unsafe_entry";
  }
}

export async function inspectPrivateRegularFile(
  path: string,
): Promise<PrivateEntrySafety> {
  assertSupportedLocalStorePlatform();
  try {
    const status = await lstat(path);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
      return "unsafe_entry";
    }
    return ownerAndModeArePrivate(status, PRIVATE_FILE_MODE)
      ? "safe"
      : "unsafe_permissions";
  } catch (error) {
    return isNodeError(error, "ENOENT") ? "missing" : "unsafe_entry";
  }
}

export async function pathExists(path: string): Promise<boolean> {
  assertSupportedLocalStorePlatform();
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return false;
    throw new LocalStoreError("integrity_failure");
  }
}

export async function readRegularFileBounded(
  path: string,
  maxBytes: number,
): Promise<Uint8Array> {
  assertSupportedLocalStorePlatform();
  let handle: FileHandle | undefined;
  try {
    const before = await privateRegularFileStatus(path);
    if (before.size > maxBytes) {
      throw new LocalStoreError("resource_limit");
    }
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    const opened = await handle.stat();
    assertPrivateRegularFileStatus(opened);
    if (!sameFile(before, opened) || opened.size !== before.size) {
      throw new LocalStoreError("integrity_failure");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    assertPrivateRegularFileStatus(after);
    if (
      !sameFile(opened, after) ||
      after.size !== opened.size ||
      bytes.byteLength !== opened.size
    ) {
      throw new LocalStoreError("integrity_failure");
    }
    if (bytes.byteLength > maxBytes) {
      throw new LocalStoreError("resource_limit");
    }
    return new Uint8Array(bytes);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new LocalStoreError("not_found");
    }
    throw asSafeStoreError(error, "integrity_failure");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function atomicWritePrivateFile(
  targetPath: string,
  bytes: Uint8Array,
): Promise<void> {
  assertSupportedLocalStorePlatform();
  const parent = dirname(targetPath);
  const temporaryPath = join(
    parent,
    `.${basename(targetPath)}.tmp-${randomBytes(16).toString("hex")}`,
  );
  let handle: FileHandle | undefined;
  let temporaryRemoved = false;
  try {
    const parentBefore = await privateDirectoryStatus(parent);
    handle = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | NO_FOLLOW,
      PRIVATE_FILE_MODE,
    );
    await handle.chmod(PRIVATE_FILE_MODE);
    const created = await handle.stat();
    assertPrivateRegularFileStatus(created);
    await handle.writeFile(bytes);
    await handle.sync();
    const written = await handle.stat();
    assertPrivateRegularFileStatus(written);
    if (!sameFile(created, written) || written.size !== bytes.byteLength) {
      throw new LocalStoreError("integrity_failure");
    }

    const parentBeforePublish = await privateDirectoryStatus(parent);
    if (!sameFile(parentBefore, parentBeforePublish)) {
      throw new LocalStoreError("integrity_failure");
    }
    const namedTemporary = await privateRegularFileStatus(temporaryPath);
    if (!sameFile(written, namedTemporary)) {
      throw new LocalStoreError("integrity_failure");
    }

    // link is an atomic, no-replace publication primitive on the supported
    // POSIX adapter. The transient second link is removed before success; a
    // crash in between leaves a fail-closed nlink/temporary-entry condition.
    await link(temporaryPath, targetPath);
    const linkedTarget = await lstat(targetPath);
    assertOwnedPrivateRegularFile(linkedTarget, 2);
    if (!sameFile(written, linkedTarget)) {
      throw new LocalStoreError("integrity_failure");
    }
    await unlink(temporaryPath);
    temporaryRemoved = true;

    const published = await privateRegularFileStatus(targetPath);
    const stillOpened = await handle.stat();
    assertPrivateRegularFileStatus(stillOpened);
    if (
      !sameFile(written, published) ||
      !sameFile(written, stillOpened) ||
      published.size !== bytes.byteLength
    ) {
      throw new LocalStoreError("integrity_failure");
    }
    await syncDirectory(parent);
  } catch (error) {
    throw asSafeStoreError(error, "integrity_failure");
  } finally {
    await handle?.close().catch(() => undefined);
    if (!temporaryRemoved) await unlink(temporaryPath).catch(() => undefined);
  }
}

export async function withExclusiveWriteLock<T>(
  storeRoot: string,
  operation: () => Promise<T>,
): Promise<T> {
  assertSupportedLocalStorePlatform();
  await assertPrivateDirectory(storeRoot);
  const lockPath = join(storeRoot, "write.lock");
  let handle: FileHandle | undefined;
  let lockStatus: Stats | undefined;
  try {
    handle = await open(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | NO_FOLLOW,
      PRIVATE_FILE_MODE,
    );
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.sync();
    lockStatus = await handle.stat();
    assertPrivateRegularFileStatus(lockStatus);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (isNodeError(error, "EEXIST")) {
      const safety = await inspectPrivateRegularFile(lockPath);
      if (safety === "safe") throw new LocalStoreError("store_busy");
    }
    throw new LocalStoreError("integrity_failure");
  }

  if (!handle || !lockStatus) throw new LocalStoreError("integrity_failure");
  try {
    return await operation();
  } finally {
    try {
      const opened = await handle.stat();
      assertPrivateRegularFileStatus(opened);
      const named = await privateRegularFileStatus(lockPath);
      if (!sameFile(lockStatus, opened) || !sameFile(opened, named)) {
        throw new LocalStoreError("integrity_failure");
      }
      await unlink(lockPath);
      await syncDirectory(storeRoot);
    } catch (error) {
      throw asSafeStoreError(error, "integrity_failure");
    } finally {
      await handle.close().catch(() => undefined);
    }
  }
}

export async function listDirectory(path: string): Promise<readonly Dirent[]> {
  assertSupportedLocalStorePlatform();
  try {
    const before = await privateDirectoryStatus(path);
    const entries = await readdir(path, { withFileTypes: true });
    const after = await privateDirectoryStatus(path);
    if (!sameFile(before, after)) {
      throw new LocalStoreError("integrity_failure");
    }
    return entries;
  } catch (error) {
    throw asSafeStoreError(error, "integrity_failure");
  }
}

export async function syncDirectory(path: string): Promise<void> {
  assertSupportedLocalStorePlatform();
  let handle: FileHandle | undefined;
  try {
    const before = await privateDirectoryStatus(path);
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    const opened = await handle.stat();
    assertPrivateDirectoryStatus(opened);
    if (!sameFile(before, opened)) {
      throw new LocalStoreError("integrity_failure");
    }
    await handle.sync();
  } catch (error) {
    if (
      isNodeError(error, "EINVAL") ||
      isNodeError(error, "ENOTSUP") ||
      isNodeError(error, "EBADF") ||
      isNodeError(error, "EISDIR")
    ) {
      return;
    }
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function privateDirectoryStatus(path: string): Promise<Stats> {
  const status = await lstat(path);
  assertPrivateDirectoryStatus(status);
  return status;
}

async function privateRegularFileStatus(path: string): Promise<Stats> {
  const status = await lstat(path);
  assertPrivateRegularFileStatus(status);
  return status;
}

function assertPrivateDirectoryStatus(status: Stats): void {
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new LocalStoreError("invalid_workspace");
  }
  if (!ownerAndModeArePrivate(status, PRIVATE_DIRECTORY_MODE)) {
    throw new LocalStoreError("invalid_workspace");
  }
}

function assertPrivateRegularFileStatus(status: Stats): void {
  assertOwnedPrivateRegularFile(status, 1);
}

function assertOwnedPrivateRegularFile(
  status: Stats,
  expectedLinkCount: number,
): void {
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== expectedLinkCount
  ) {
    throw new LocalStoreError("integrity_failure");
  }
  if (!ownerAndModeArePrivate(status, PRIVATE_FILE_MODE)) {
    throw new LocalStoreError("integrity_failure");
  }
}

function ownerAndModeArePrivate(status: Stats, expectedMode: number): boolean {
  const currentUid = process.getuid?.();
  return (
    currentUid !== undefined &&
    hasExpectedPosixOwnerAndMode(status, expectedMode, currentUid)
  );
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

export function isNodeError(
  error: unknown,
  code: string,
): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}
