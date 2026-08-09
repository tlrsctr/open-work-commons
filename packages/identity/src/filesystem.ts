import { randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rmdir,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { join } from "node:path";

import {
  DeviceIdentityError,
  asSafeDeviceIdentityError,
  type DeviceIdentityErrorCode,
} from "./errors.js";

export const IDENTITY_DIRECTORY = "device";
export const METADATA_FILE = "identity.json";
export const PRIVATE_KEY_FILE = "private-key.pk8";
export const PUBLIC_KEY_FILE = "public-key.spki";

const CREATION_LOCK = ".device.create.lock";
const STAGING_PREFIX = ".device.tmp-";
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const EXPECTED_FILES = Object.freeze([
  METADATA_FILE,
  PRIVATE_KEY_FILE,
  PUBLIC_KEY_FILE,
]);
const SORTED_EXPECTED_FILES = Object.freeze([...EXPECTED_FILES].sort());

export interface IdentityFileSet {
  readonly metadata: Uint8Array;
  readonly privateKeyPkcs8: Uint8Array;
  readonly publicKeySpki: Uint8Array;
}

export function assertSupportedLocalFilePlatform(): void {
  if (process.platform === "win32" || typeof process.getuid !== "function") {
    throw new DeviceIdentityError("unsupported_platform");
  }
}

export async function ensurePrivateRoot(root: string): Promise<void> {
  assertSupportedLocalFilePlatform();
  let created = false;
  try {
    await mkdir(root, { mode: DIRECTORY_MODE });
    created = true;
  } catch (error) {
    if (!isNodeError(error, "EEXIST")) {
      throw asSafeDeviceIdentityError(error, "unsafe_storage");
    }
  }

  if (created) {
    try {
      await chmod(root, DIRECTORY_MODE);
    } catch (error) {
      throw asSafeDeviceIdentityError(error, "unsafe_permissions");
    }
  }
  await assertPrivateDirectory(root, "unsafe_storage");
}

export async function assertPrivateRoot(root: string): Promise<void> {
  assertSupportedLocalFilePlatform();
  await assertPrivateDirectory(root, "not_found");
}

export async function identityExists(root: string): Promise<boolean> {
  return pathExists(join(root, IDENTITY_DIRECTORY));
}

export async function readIdentityFiles(
  root: string,
): Promise<IdentityFileSet> {
  await assertPrivateRoot(root);
  const identityPath = join(root, IDENTITY_DIRECTORY);
  await assertPrivateDirectory(identityPath, "integrity_failure");

  let entries: readonly string[];
  try {
    entries = (await readdir(identityPath)).sort();
  } catch (error) {
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  }
  if (
    entries.length !== EXPECTED_FILES.length ||
    entries.some((entry, index) => entry !== SORTED_EXPECTED_FILES[index])
  ) {
    throw new DeviceIdentityError("unsafe_storage");
  }

  const metadata = await readPrivateRegularFile(
    join(identityPath, METADATA_FILE),
    4096,
  );
  const privateKeyPkcs8 = await readPrivateRegularFile(
    join(identityPath, PRIVATE_KEY_FILE),
    512,
  );
  const publicKeySpki = await readPrivateRegularFile(
    join(identityPath, PUBLIC_KEY_FILE),
    512,
  );
  return { metadata, privateKeyPkcs8, publicKeySpki };
}

/**
 * Publishes a complete identity directory under an exclusive creation lock.
 * The caller owns the supplied byte arrays and should clear private bytes after
 * this call. Existing identity bytes are never replaced.
 */
export async function publishIdentityFiles(
  root: string,
  files: IdentityFileSet,
): Promise<void> {
  await ensurePrivateRoot(root);
  if (await identityExists(root)) return;

  const lock = await acquireCreationLock(root);
  if (!lock) return;

  try {
    if (await identityExists(root)) return;
    await publishStagedDirectory(root, files);
  } finally {
    await releaseCreationLock(root, lock);
  }
}

async function acquireCreationLock(root: string): Promise<FileHandle | null> {
  const lockPath = join(root, CREATION_LOCK);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        lockPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | NO_FOLLOW,
        FILE_MODE,
      );
      await handle.chmod(FILE_MODE);
      await handle.sync();
      return handle;
    } catch (error) {
      await handle?.close().catch(() => undefined);
      if (handle) await unlink(lockPath).catch(() => undefined);
      if (!isNodeError(error, "EEXIST")) {
        throw asSafeDeviceIdentityError(error, "integrity_failure");
      }
      if (await identityExists(root)) return null;
      await assertSafeCreationLock(lockPath);
      await delay(10);
    }
  }
  throw new DeviceIdentityError("identity_busy");
}

async function assertSafeCreationLock(lockPath: string): Promise<void> {
  try {
    const status = await lstat(lockPath);
    assertRegularFile(status);
    assertOwnerAndMode(status, FILE_MODE);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return;
    throw asSafeDeviceIdentityError(error, "unsafe_storage");
  }
}

async function releaseCreationLock(
  root: string,
  handle: FileHandle,
): Promise<void> {
  await unlink(join(root, CREATION_LOCK)).catch(() => undefined);
  await handle.close().catch(() => undefined);
  await syncDirectory(root).catch(() => undefined);
}

async function publishStagedDirectory(
  root: string,
  files: IdentityFileSet,
): Promise<void> {
  const stagingPath = join(
    root,
    `${STAGING_PREFIX}${randomBytes(32).toString("hex")}`,
  );
  let staged = false;
  let published = false;

  try {
    await mkdir(stagingPath, { mode: DIRECTORY_MODE });
    staged = true;
    await chmod(stagingPath, DIRECTORY_MODE);
    await assertPrivateDirectory(stagingPath, "unsafe_storage");
    await writePrivateFileExclusive(
      join(stagingPath, PRIVATE_KEY_FILE),
      files.privateKeyPkcs8,
    );
    await writePrivateFileExclusive(
      join(stagingPath, PUBLIC_KEY_FILE),
      files.publicKeySpki,
    );
    await writePrivateFileExclusive(
      join(stagingPath, METADATA_FILE),
      files.metadata,
    );
    await syncDirectory(stagingPath);

    // The lock serializes cooperating creators. This final check also refuses
    // an externally introduced symlink, special entry, or existing identity.
    if (await identityExists(root)) return;
    await rename(stagingPath, join(root, IDENTITY_DIRECTORY));
    published = true;
    await syncDirectory(root);
  } catch (error) {
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  } finally {
    if (staged && !published) await removeStagingDirectory(stagingPath);
  }
}

async function writePrivateFileExclusive(
  path: string,
  bytes: Uint8Array,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | NO_FOLLOW,
      FILE_MODE,
    );
    await handle.chmod(FILE_MODE);
    await handle.writeFile(bytes);
    await handle.sync();
    const status = await handle.stat();
    assertRegularFile(status);
    assertOwnerAndMode(status, FILE_MODE);
  } catch (error) {
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readPrivateRegularFile(
  path: string,
  maxBytes: number,
): Promise<Uint8Array> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(path);
    assertRegularFile(before);
    assertOwnerAndMode(before, FILE_MODE);
    if (before.size <= 0 || before.size > maxBytes) {
      throw new DeviceIdentityError("integrity_failure");
    }

    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    const opened = await handle.stat();
    assertRegularFile(opened);
    assertOwnerAndMode(opened, FILE_MODE);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      throw new DeviceIdentityError("integrity_failure");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size || bytes.byteLength > maxBytes) {
      throw new DeviceIdentityError("integrity_failure");
    }
    return new Uint8Array(bytes);
  } catch (error) {
    if (isNodeError(error, "ENOENT"))
      throw new DeviceIdentityError("integrity_failure");
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function assertPrivateDirectory(
  path: string,
  missingCode: DeviceIdentityErrorCode,
): Promise<void> {
  try {
    const status = await lstat(path);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new DeviceIdentityError("unsafe_storage");
    }
    assertOwnerAndMode(status, DIRECTORY_MODE);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new DeviceIdentityError(missingCode);
    }
    throw asSafeDeviceIdentityError(error, "unsafe_storage");
  }
}

function assertRegularFile(status: Stats): void {
  if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
    throw new DeviceIdentityError("unsafe_storage");
  }
}

function assertOwnerAndMode(status: Stats, expectedMode: number): void {
  if (
    (status.mode & 0o7777) !== expectedMode ||
    status.uid !== process.getuid!()
  ) {
    throw new DeviceIdentityError("unsafe_permissions");
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return false;
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  }
}

async function removeStagingDirectory(path: string): Promise<void> {
  let entries: readonly string[] = [];
  try {
    entries = await readdir(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return;
  }
  for (const entry of entries) {
    if (EXPECTED_FILES.includes(entry)) {
      await unlink(join(path, entry)).catch(() => undefined);
    }
  }
  await rmdir(path).catch(() => undefined);
}

async function syncDirectory(path: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
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

function isNodeError(
  error: unknown,
  code: string,
): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
