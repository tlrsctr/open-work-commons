import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  DEFAULT_VERIFIER_LIMITS,
  isSafeArchivePath,
  parseJsonSafely,
  type LogicalArchive,
  type LogicalArchiveEntry,
} from "../../../packages/archive/src/index.js";

export interface ArchiveLoader {
  load(directory: string): Promise<LogicalArchive>;
}

export class ArchiveDirectoryError extends Error {
  constructor(readonly code: "invalid_archive_directory" | "resource_limit") {
    super(code);
    this.name = "ArchiveDirectoryError";
  }
}

type ManifestShape = {
  entries: Array<{ path: string }>;
};

export function createDirectoryArchiveLoader(): ArchiveLoader {
  return {
    async load(directory) {
      const root = await resolveArchiveRoot(directory);
      const manifestEntry = await readEntry(
        root,
        "archive-manifest.json",
        DEFAULT_VERIFIER_LIMITS.maxManifestBytes,
      );
      if (!manifestEntry || manifestEntry.kind !== "file") {
        throw new ArchiveDirectoryError("invalid_archive_directory");
      }

      let parsed: unknown;
      try {
        parsed = parseJsonSafely(manifestEntry.bytes, {
          maxDepth: DEFAULT_VERIFIER_LIMITS.maxJsonDepth,
          maxStringBytes: DEFAULT_VERIFIER_LIMITS.maxJsonStringBytes,
        });
      } catch {
        // The verifier will produce the stable JSON diagnostic. The loader only
        // needs enough structure to determine which files may be read.
        return { manifestBytes: manifestEntry.bytes, entries: [] };
      }
      if (!isManifestShape(parsed)) {
        return { manifestBytes: manifestEntry.bytes, entries: [] };
      }
      if (parsed.entries.length > DEFAULT_VERIFIER_LIMITS.maxEntryCount) {
        throw new ArchiveDirectoryError("resource_limit");
      }

      const entries: LogicalArchiveEntry[] = [];
      let expandedBytes = 0;
      for (const descriptor of parsed.entries) {
        if (!isSafeArchivePath(descriptor.path)) {
          // Preserve no attacker-controlled path in the result. An empty entry
          // list lets the verifier report the unsafe manifest path itself.
          return { manifestBytes: manifestEntry.bytes, entries: [] };
        }
        const entry = await readEntry(
          root,
          descriptor.path,
          DEFAULT_VERIFIER_LIMITS.maxEntryBytes,
        );
        if (entry) {
          expandedBytes += entry.bytes.byteLength;
          if (expandedBytes > DEFAULT_VERIFIER_LIMITS.maxExpandedBytes) {
            throw new ArchiveDirectoryError("resource_limit");
          }
          entries.push(entry);
        }
      }
      return { manifestBytes: manifestEntry.bytes, entries };
    },
  };
}

async function resolveArchiveRoot(directory: string): Promise<string> {
  try {
    const root = await realpath(resolve(directory));
    const metadata = await lstat(root);
    if (!metadata.isDirectory()) {
      throw new ArchiveDirectoryError("invalid_archive_directory");
    }
    return root;
  } catch (error) {
    if (error instanceof ArchiveDirectoryError) throw error;
    throw new ArchiveDirectoryError("invalid_archive_directory");
  }
}

async function readEntry(
  root: string,
  archivePath: string,
  maxBytes: number,
): Promise<LogicalArchiveEntry | null> {
  const segments = archivePath.split("/");
  let current = root;
  try {
    for (const [index, segment] of segments.entries()) {
      current = join(current, segment);
      const metadata = await lstat(current);
      if (metadata.isSymbolicLink()) {
        return { path: archivePath, bytes: new Uint8Array(), kind: "symlink" };
      }
      if (index < segments.length - 1 && !metadata.isDirectory()) {
        return { path: archivePath, bytes: new Uint8Array(), kind: "special" };
      }
      if (index === segments.length - 1 && !metadata.isFile()) {
        return { path: archivePath, bytes: new Uint8Array(), kind: "special" };
      }
    }
  } catch (error) {
    if (isMissing(error)) return null;
    throw new ArchiveDirectoryError("invalid_archive_directory");
  }

  assertBeneath(root, current);
  let handle;
  try {
    handle = await open(current, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      return { path: archivePath, bytes: new Uint8Array(), kind: "special" };
    }
    if (metadata.size > maxBytes) {
      throw new ArchiveDirectoryError("resource_limit");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > maxBytes) {
      throw new ArchiveDirectoryError("resource_limit");
    }
    return { path: archivePath, bytes, kind: "file" };
  } catch (error) {
    if (error instanceof ArchiveDirectoryError) throw error;
    if (isMissing(error)) return null;
    throw new ArchiveDirectoryError("invalid_archive_directory");
  } finally {
    await handle?.close();
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
    throw new ArchiveDirectoryError("invalid_archive_directory");
  }
}

function isManifestShape(value: unknown): value is ManifestShape {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as { entries?: unknown }).entries) &&
    (value as { entries: unknown[] }).entries.every(
      (entry) =>
        typeof entry === "object" &&
        entry !== null &&
        typeof (entry as { path?: unknown }).path === "string",
    )
  );
}

function isMissing(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}
