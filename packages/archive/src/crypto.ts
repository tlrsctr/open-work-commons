import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import type { Digest, GeneratedSigningKey } from "./types.js";

export function sha256(bytes: Uint8Array): Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function publicKeyBase64Url(publicKey: KeyObject): string {
  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError("Expected an Ed25519 public key.");
  }
  const jwk = publicKey.export({ format: "jwk" });
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
  ) {
    throw new TypeError("Could not export a raw Ed25519 public key.");
  }
  return jwk.x;
}

export function publicKeyFromBase64Url(value: string): KeyObject {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError("Invalid raw Ed25519 public key encoding.");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 32) {
    throw new TypeError("Invalid raw Ed25519 public key length.");
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: value },
    format: "jwk",
  });
}

export function signerFingerprint(publicKeyValue: string): Digest {
  const raw = Buffer.from(publicKeyValue, "base64url");
  if (raw.byteLength !== 32) {
    throw new TypeError("Invalid raw Ed25519 public key length.");
  }
  return sha256(raw);
}

export function signEd25519(
  payload: Uint8Array,
  privateKey: KeyObject,
): string {
  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError("Expected an Ed25519 private key.");
  }
  return sign(null, payload, privateKey).toString("base64url");
}

export function verifyEd25519(
  payload: Uint8Array,
  signature: string,
  publicKeyValue: string,
): boolean {
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  const signatureBytes = Buffer.from(signature, "base64url");
  if (signatureBytes.byteLength !== 64) return false;
  try {
    return verify(
      null,
      payload,
      publicKeyFromBase64Url(publicKeyValue),
      signatureBytes,
    );
  } catch {
    return false;
  }
}

export function generateArchiveSigningKey(keyId?: string): GeneratedSigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = publicKeyBase64Url(publicKey);
  const fingerprint = signerFingerprint(rawPublicKey);
  return {
    keyId:
      keyId ?? `urn:owc:key:ed25519:${fingerprint.slice("sha256:".length)}`,
    privateKey,
    publicKey,
    publicKeyBase64Url: rawPublicKey,
    fingerprint,
  };
}

export function publicKeyForPrivateKey(privateKey: KeyObject): KeyObject {
  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError("Expected an Ed25519 private key.");
  }
  return createPublicKey(privateKey);
}
