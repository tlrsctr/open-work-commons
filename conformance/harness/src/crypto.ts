import { createHash, createPublicKey, verify } from "node:crypto";

export type Digest = `sha256:${string}`;

export function sha256(bytes: Uint8Array): Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function verifyEd25519(
  payload: Uint8Array,
  signature: string,
  publicKey: string,
): boolean {
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(publicKey)) return false;

  const signatureBytes = Buffer.from(signature, "base64url");
  const publicKeyBytes = Buffer.from(publicKey, "base64url");
  if (signatureBytes.byteLength !== 64 || publicKeyBytes.byteLength !== 32) {
    return false;
  }

  try {
    const key = createPublicKey({
      format: "jwk",
      key: { crv: "Ed25519", kty: "OKP", x: publicKey },
    });
    return verify(null, payload, key, signatureBytes);
  } catch {
    return false;
  }
}
