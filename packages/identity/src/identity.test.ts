import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLogicalArchive } from "../../archive/src/index.js";

import { DeviceIdentityError, LocalFileDeviceIdentityStore } from "./index.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test("creates one owner-only Ed25519 identity and exposes public metadata only", async (context) => {
  if (process.platform === "win32") {
    context.skip("The POSIX local-file adapter deliberately refuses Windows.");
    return;
  }
  const root = await temporaryIdentityRoot();
  const identity = await new LocalFileDeviceIdentityStore(root).openOrCreate();

  assert.equal((await stat(root)).mode & 0o7777, 0o700);
  assert.equal((await stat(join(root, "device"))).mode & 0o7777, 0o700);
  assert.deepEqual((await readdir(join(root, "device"))).sort(), [
    "identity.json",
    "private-key.pk8",
    "public-key.spki",
  ]);
  for (const name of ["identity.json", "private-key.pk8", "public-key.spki"]) {
    assert.equal((await stat(join(root, "device", name))).mode & 0o7777, 0o600);
  }

  assert.equal(identity.publicIdentity.algorithm, "ed25519");
  assert.match(identity.publicIdentity.public_key, /^[A-Za-z0-9_-]{43}$/);
  assert.match(identity.publicIdentity.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    identity.publicIdentity.key_id,
    `urn:owc:key:ed25519:${identity.publicIdentity.fingerprint.slice(7)}`,
  );
  assert.deepEqual(Object.keys(identity).sort(), ["publicIdentity"]);
});

test("reopens idempotently without rotating the device fingerprint", async () => {
  const root = await temporaryIdentityRoot();
  const store = new LocalFileDeviceIdentityStore(root);
  const created = await store.openOrCreate();
  const privateBefore = await readFile(join(root, "device", "private-key.pk8"));

  const reopened = await store.openOrCreate();
  const opened = await store.open();
  assert.equal(
    reopened.publicIdentity.fingerprint,
    created.publicIdentity.fingerprint,
  );
  assert.equal(
    opened.publicIdentity.fingerprint,
    created.publicIdentity.fingerprint,
  );
  assert.deepEqual(
    await readFile(join(root, "device", "private-key.pk8")),
    privateBefore,
  );
});

test("signs a portable archive that the archive API verifies offline", async () => {
  const root = await temporaryIdentityRoot();
  const identity = await new LocalFileDeviceIdentityStore(root).openOrCreate();
  const fixture = await readMinimalArchiveObjects();
  const archive = identity.createSignedArchive({
    archiveId: "urn:owc:archive:identity-test",
    createdAt: "2026-08-07T10:00:00Z",
    rootCheckpoint: {
      checkpointId: "urn:owc:checkpoint:fixture-001",
      path: "checkpoints/checkpoint.json",
    },
    entries: [
      {
        path: "events/session-started.json",
        mediaType: "application/json",
        role: "event",
        bytes: fixture.event,
      },
      {
        path: "state/git-state.json",
        mediaType: "application/json",
        role: "git-state",
        bytes: fixture.gitState,
      },
      {
        path: "checkpoints/checkpoint.json",
        mediaType: "application/json",
        role: "checkpoint",
        bytes: fixture.checkpoint,
      },
    ],
    exclusions: [
      {
        category: "raw-transcript",
        reason:
          "Raw provider transcripts are excluded by the v0 default policy.",
        policy: "owc-v0-default-private",
      },
    ],
  });

  const result = verifyLogicalArchive(archive, {
    trustedSignerFingerprints: [identity.publicIdentity.fingerprint],
  });
  assert.equal(result.integrity.valid, true);
  assert.equal(result.signer.signatureValid, true);
  assert.equal(result.signer.trusted, true);
  assert.equal(result.signer.keyId, identity.publicIdentity.key_id);
  assert.equal(result.signer.fingerprint, identity.publicIdentity.fingerprint);
});

test("fails closed when private key, public key, or key identifier is tampered", async () => {
  for (const target of ["private-key.pk8", "public-key.spki"] as const) {
    const root = await temporaryIdentityRoot();
    const store = new LocalFileDeviceIdentityStore(root);
    await store.openOrCreate();
    const path = join(root, "device", target);
    const bytes = await readFile(path);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0x01;
    await writeFile(path, bytes);
    await assert.rejects(store.open(), identityError("integrity_failure"));
  }

  const root = await temporaryIdentityRoot();
  const store = new LocalFileDeviceIdentityStore(root);
  await store.openOrCreate();
  const metadataPath = join(root, "device", "identity.json");
  const metadata = JSON.parse(await readFile(metadataPath, "utf8")) as Record<
    string,
    unknown
  >;
  metadata.key_id = `urn:owc:key:ed25519:${"0".repeat(64)}`;
  await writeFile(metadataPath, `${JSON.stringify(metadata)}\n`);
  await assert.rejects(store.open(), identityError("integrity_failure"));
});

test("rejects symlinks and special entries at every identity boundary", async () => {
  const root = await temporaryIdentityRoot();
  await mkdir(root, { mode: 0o700 });
  const outside = await temporaryIdentityRoot();
  await mkdir(outside, { mode: 0o700 });
  await symlink(outside, join(root, "device"));
  await assert.rejects(
    new LocalFileDeviceIdentityStore(root).open(),
    identityError("unsafe_storage"),
  );

  const regularRoot = await temporaryIdentityRoot();
  const store = new LocalFileDeviceIdentityStore(regularRoot);
  await store.openOrCreate();
  await rm(join(regularRoot, "device", "public-key.spki"));
  await mkdir(join(regularRoot, "device", "public-key.spki"), { mode: 0o700 });
  await assert.rejects(store.open(), identityError("unsafe_storage"));
});

test("rejects weak directory and file permissions instead of repairing them", async () => {
  const weakFileRoot = await temporaryIdentityRoot();
  const weakFileStore = new LocalFileDeviceIdentityStore(weakFileRoot);
  await weakFileStore.openOrCreate();
  const privatePath = join(weakFileRoot, "device", "private-key.pk8");
  await chmod(privatePath, 0o644);
  await assert.rejects(
    weakFileStore.open(),
    identityError("unsafe_permissions"),
  );
  assert.equal((await stat(privatePath)).mode & 0o7777, 0o644);

  const weakRoot = await temporaryIdentityRoot();
  const weakRootStore = new LocalFileDeviceIdentityStore(weakRoot);
  await weakRootStore.openOrCreate();
  await chmod(weakRoot, 0o755);
  const diagnostic = await weakRootStore.diagnose();
  assert.deepEqual(diagnostic, {
    ok: false,
    code: "unsafe_permissions",
    identity: null,
    message: "The local device identity storage permissions are unsafe.",
  });
  assert.equal((await stat(weakRoot)).mode & 0o7777, 0o755);
});

test("concurrent creators converge on one key without overwriting it", async () => {
  const root = await temporaryIdentityRoot();
  const identities = await Promise.all(
    Array.from({ length: 12 }, () =>
      new LocalFileDeviceIdentityStore(root).openOrCreate(),
    ),
  );
  const fingerprints = new Set(
    identities.map((identity) => identity.publicIdentity.fingerprint),
  );
  assert.equal(fingerprints.size, 1);
  assert.deepEqual((await readdir(root)).sort(), ["device"]);

  const privateBefore = await readFile(join(root, "device", "private-key.pk8"));
  const reopened = await new LocalFileDeviceIdentityStore(root).openOrCreate();
  assert.equal(
    reopened.publicIdentity.fingerprint,
    identities[0]?.publicIdentity.fingerprint,
  );
  assert.deepEqual(
    await readFile(join(root, "device", "private-key.pk8")),
    privateBefore,
  );
});

test("public metadata, thrown errors, and diagnostics never reveal private material", async () => {
  const root = await temporaryIdentityRoot();
  const store = new LocalFileDeviceIdentityStore(root);
  const identity = await store.openOrCreate();
  const privateBytes = await readFile(join(root, "device", "private-key.pk8"));
  const privateBase64 = privateBytes.toString("base64url");
  const privateHex = privateBytes.toString("hex");
  const publicSurface = JSON.stringify(identity);
  const storedMetadata = await readFile(
    join(root, "device", "identity.json"),
    "utf8",
  );
  assert.equal(publicSurface.includes(privateBase64), false);
  assert.equal(publicSurface.includes(privateHex), false);
  assert.equal(storedMetadata.includes(privateBase64), false);
  assert.equal(storedMetadata.includes(privateHex), false);

  const canary = `PRIVATE-CANARY-${privateBase64}`;
  await writeFile(join(root, "device", "identity.json"), canary, {
    mode: 0o600,
  });
  let thrown: unknown;
  try {
    await store.open();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown instanceof DeviceIdentityError);
  assert.equal(String(thrown).includes("PRIVATE-CANARY"), false);
  assert.equal(String(thrown).includes(privateBase64), false);

  const diagnostic = await store.diagnose();
  const diagnosticText = JSON.stringify(diagnostic);
  assert.equal(diagnosticText.includes("PRIVATE-CANARY"), false);
  assert.equal(diagnosticText.includes(privateBase64), false);
  assert.equal(diagnosticText.includes(privateHex), false);
  assert.deepEqual(diagnostic, {
    ok: false,
    code: "integrity_failure",
    identity: null,
    message: "The local device identity integrity check failed.",
  });
});

async function temporaryIdentityRoot(): Promise<string> {
  const parent = await mkdtemp(join(tmpdir(), "owc-identity-test-"));
  temporaryDirectories.push(parent);
  return join(parent, "identity-root");
}

function identityError(
  code: DeviceIdentityError["code"],
): (error: unknown) => boolean {
  return (error) => error instanceof DeviceIdentityError && error.code === code;
}

async function readMinimalArchiveObjects(): Promise<{
  readonly event: Uint8Array;
  readonly gitState: Uint8Array;
  readonly checkpoint: Uint8Array;
}> {
  const base = join(repositoryRoot, "conformance", "valid", "minimal");
  const [event, gitState, checkpoint] = await Promise.all([
    readFile(join(base, "events", "session-started.json")),
    readFile(join(base, "state", "git-state.json")),
    readFile(join(base, "checkpoints", "checkpoint.json")),
  ]);
  return {
    event,
    gitState,
    checkpoint,
  };
}
