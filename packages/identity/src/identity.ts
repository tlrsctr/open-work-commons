import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { resolve } from "node:path";

import {
  createSignedArchive,
  type Digest,
  type LogicalArchive,
} from "../../archive/src/index.js";

import { DeviceIdentityError, asSafeDeviceIdentityError } from "./errors.js";
import {
  assertPrivateRoot,
  assertSupportedLocalFilePlatform,
  identityExists,
  publishIdentityFiles,
  readIdentityFiles,
} from "./filesystem.js";
import type {
  DeviceIdentityDiagnostic,
  DeviceIdentityStore,
  DeviceSigningIdentity,
  PublicDeviceIdentity,
  UnsignedArchiveInput,
} from "./types.js";

const READY_MESSAGE = "The local device identity is ready." as const;
const encoder = new TextEncoder();

export class LocalFileDeviceIdentityStore implements DeviceIdentityStore {
  readonly #privateDirectory: string;

  constructor(privateDirectory: string) {
    this.#privateDirectory = resolve(privateDirectory);
  }

  async open(): Promise<DeviceSigningIdentity> {
    assertSupportedLocalFilePlatform();
    await assertPrivateRoot(this.#privateDirectory);
    if (!(await identityExists(this.#privateDirectory))) {
      throw new DeviceIdentityError("not_found");
    }
    return loadIdentity(this.#privateDirectory);
  }

  async openOrCreate(): Promise<DeviceSigningIdentity> {
    assertSupportedLocalFilePlatform();
    try {
      return await this.open();
    } catch (error) {
      if (
        !(error instanceof DeviceIdentityError) ||
        error.code !== "not_found"
      ) {
        throw error;
      }
    }

    const generated = generateIdentityFiles();
    try {
      await publishIdentityFiles(this.#privateDirectory, generated.files);
    } finally {
      generated.privateKeyPkcs8.fill(0);
    }
    return loadIdentity(this.#privateDirectory);
  }

  async diagnose(): Promise<DeviceIdentityDiagnostic> {
    try {
      const identity = await this.open();
      return Object.freeze({
        ok: true,
        code: "ready",
        identity: identity.publicIdentity,
        message: READY_MESSAGE,
      });
    } catch (error) {
      const safe = asSafeDeviceIdentityError(error, "integrity_failure");
      return Object.freeze({
        ok: false,
        code: safe.code,
        identity: null,
        message: safe.message,
      });
    }
  }
}

class LocalFileDeviceSigningIdentity implements DeviceSigningIdentity {
  readonly publicIdentity: PublicDeviceIdentity;
  readonly #privateKey: KeyObject;

  constructor(publicIdentity: PublicDeviceIdentity, privateKey: KeyObject) {
    this.publicIdentity = Object.freeze({ ...publicIdentity });
    this.#privateKey = privateKey;
  }

  sign(payload: Uint8Array): string {
    try {
      return signBytes(null, Buffer.from(payload), this.#privateKey).toString(
        "base64url",
      );
    } catch {
      throw new DeviceIdentityError("signing_failure");
    }
  }

  createSignedArchive(input: UnsignedArchiveInput): LogicalArchive {
    return createSignedArchive({
      ...input,
      signingKey: {
        keyId: this.publicIdentity.key_id,
        privateKey: this.#privateKey,
      },
    });
  }
}

async function loadIdentity(root: string): Promise<DeviceSigningIdentity> {
  try {
    const files = await readIdentityFiles(root);
    const privateKey = parsePrivateKey(files.privateKeyPkcs8);
    const storedPublicKey = parsePublicKey(files.publicKeySpki);
    const derivedPublicKey = createPublicKey(privateKey);
    const canonicalPrivate = exportPrivatePkcs8(privateKey);
    const canonicalStoredPublic = exportPublicSpki(storedPublicKey);
    const canonicalDerivedPublic = exportPublicSpki(derivedPublicKey);

    if (
      !canonicalPrivate.equals(Buffer.from(files.privateKeyPkcs8)) ||
      !canonicalStoredPublic.equals(Buffer.from(files.publicKeySpki)) ||
      !canonicalDerivedPublic.equals(canonicalStoredPublic)
    ) {
      throw new DeviceIdentityError("integrity_failure");
    }

    const publicIdentity = publicIdentityFor(derivedPublicKey);
    const expectedMetadata = encodeMetadata(publicIdentity);
    if (!expectedMetadata.equals(Buffer.from(files.metadata))) {
      throw new DeviceIdentityError("integrity_failure");
    }
    return new LocalFileDeviceSigningIdentity(publicIdentity, privateKey);
  } catch (error) {
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  }
}

function generateIdentityFiles(): {
  readonly files: {
    readonly metadata: Uint8Array;
    readonly privateKeyPkcs8: Uint8Array;
    readonly publicKeySpki: Uint8Array;
  };
  readonly privateKeyPkcs8: Buffer;
} {
  try {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPkcs8 = exportPrivatePkcs8(privateKey);
    const publicKeySpki = exportPublicSpki(publicKey);
    const publicIdentity = publicIdentityFor(publicKey);
    return {
      files: {
        metadata: encodeMetadata(publicIdentity),
        privateKeyPkcs8,
        publicKeySpki,
      },
      privateKeyPkcs8,
    };
  } catch (error) {
    throw asSafeDeviceIdentityError(error, "integrity_failure");
  }
}

function parsePrivateKey(bytes: Uint8Array): KeyObject {
  const key = createPrivateKey({
    key: Buffer.from(bytes),
    format: "der",
    type: "pkcs8",
  });
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new DeviceIdentityError("integrity_failure");
  }
  return key;
}

function parsePublicKey(bytes: Uint8Array): KeyObject {
  const key = createPublicKey({
    key: Buffer.from(bytes),
    format: "der",
    type: "spki",
  });
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new DeviceIdentityError("integrity_failure");
  }
  return key;
}

function exportPrivatePkcs8(key: KeyObject): Buffer {
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new DeviceIdentityError("integrity_failure");
  }
  const exported = key.export({ format: "der", type: "pkcs8" });
  if (!Buffer.isBuffer(exported)) {
    throw new DeviceIdentityError("integrity_failure");
  }
  return Buffer.from(exported);
}

function exportPublicSpki(key: KeyObject): Buffer {
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new DeviceIdentityError("integrity_failure");
  }
  const exported = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) {
    throw new DeviceIdentityError("integrity_failure");
  }
  return Buffer.from(exported);
}

function publicIdentityFor(publicKey: KeyObject): PublicDeviceIdentity {
  const jwk = publicKey.export({ format: "jwk" });
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
  ) {
    throw new DeviceIdentityError("integrity_failure");
  }
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.byteLength !== 32) {
    throw new DeviceIdentityError("integrity_failure");
  }
  const fingerprint = sha256(raw);
  return Object.freeze({
    format: "open-work-commons-device-identity",
    schema_version: "0.1",
    algorithm: "ed25519",
    key_id: `urn:owc:key:ed25519:${fingerprint.slice("sha256:".length)}`,
    fingerprint,
    public_key: jwk.x,
    public_key_spki: exportPublicSpki(publicKey).toString("base64url"),
  });
}

function sha256(bytes: Uint8Array): Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function encodeMetadata(identity: PublicDeviceIdentity): Buffer {
  return Buffer.from(
    encoder.encode(
      `${JSON.stringify({
        format: identity.format,
        schema_version: identity.schema_version,
        algorithm: identity.algorithm,
        key_id: identity.key_id,
        fingerprint: identity.fingerprint,
        public_key: identity.public_key,
        public_key_spki: identity.public_key_spki,
      })}\n`,
    ),
  );
}
