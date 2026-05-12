import type _sodium from "libsodium-wrappers-sumo";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

let sodiumInstance: typeof _sodium | null = null;

/**
 * Lazily initializes and caches the libsodium library.
 */
export async function initSodium(): Promise<typeof _sodium> {
  if (sodiumInstance !== null) {
    return sodiumInstance;
  }
  const _sodiumModule = await import("libsodium-wrappers-sumo");
  const sodium = _sodiumModule.default;
  await sodium.ready;
  sodiumInstance = sodium;
  return sodium;
}

/**
 * Derives a 256-bit master key from a Solana ed25519 secret key and an
 * instance identifier.
 *
 * Pipeline:
 *   ed25519 secret (64 B) -> x25519 secret (32 B)
 *     -> HKDF-SHA256(ikm=x25519_secret, salt="supaba-master-key", info=instanceId)
 *     -> 32-byte master key
 *
 * @param solanaSecretKey - 64-byte Solana keypair secret key (ed25519)
 * @param instanceId      - unique instance identifier used as HKDF info
 * @returns 32-byte (256-bit) master key
 */
export async function deriveMasterKey(
  solanaSecretKey: Uint8Array,
  instanceId: string,
): Promise<Uint8Array> {
  if (!(solanaSecretKey instanceof Uint8Array)) {
    throw new TypeError("solanaSecretKey must be a Uint8Array");
  }
  if (solanaSecretKey.length !== 64) {
    throw new RangeError(
      `solanaSecretKey must be 64 bytes, got ${solanaSecretKey.length}`,
    );
  }
  if (typeof instanceId !== "string" || instanceId.length === 0) {
    throw new TypeError("instanceId must be a non-empty string");
  }

  const sodium = await initSodium();
  const x25519Secret = sodium.crypto_sign_ed25519_sk_to_curve25519(
    solanaSecretKey,
  );

  const salt = new TextEncoder().encode("supaba-master-key");
  const info = new TextEncoder().encode(instanceId);

  const masterKey = hkdf(sha256, new Uint8Array(x25519Secret), salt, info, 32);

  // Zero out intermediate x25519 secret
  x25519Secret.fill(0);

  return new Uint8Array(masterKey);
}

/**
 * General purpose key derivation using HKDF-SHA256.
 *
 * @param seed    - input key material (any length)
 * @param context - context string used as HKDF info
 * @returns 32-byte derived key
 */
export function deriveEncryptionKeyFromSeed(
  seed: Uint8Array,
  context: string,
): Uint8Array {
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be a Uint8Array");
  }
  if (seed.length === 0) {
    throw new RangeError("seed must not be empty");
  }
  if (typeof context !== "string" || context.length === 0) {
    throw new TypeError("context must be a non-empty string");
  }

  const salt = new TextEncoder().encode("supaba-derive");
  const info = new TextEncoder().encode(context);

  return new Uint8Array(hkdf(sha256, seed, salt, info, 32));
}

/**
 * Converts an ed25519 keypair (as used by Solana) to x25519 keypair
 * for Diffie-Hellman key exchange.
 *
 * @param ed25519SecretKey - 64-byte ed25519 secret key (contains both
 *                           secret and public halves)
 * @returns x25519 public key (32 bytes) and secret key (32 bytes)
 */
export async function solanaKeypairToX25519(
  ed25519SecretKey: Uint8Array,
): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  if (!(ed25519SecretKey instanceof Uint8Array)) {
    throw new TypeError("ed25519SecretKey must be a Uint8Array");
  }
  if (ed25519SecretKey.length !== 64) {
    throw new RangeError(
      `ed25519SecretKey must be 64 bytes, got ${ed25519SecretKey.length}`,
    );
  }

  const sodium = await initSodium();

  // The ed25519 secret key in Solana is 64 bytes: first 32 bytes are the
  // seed/secret scalar, last 32 bytes are the public key.
  const x25519Secret = sodium.crypto_sign_ed25519_sk_to_curve25519(
    ed25519SecretKey,
  );

  // Extract the ed25519 public key (last 32 bytes of the 64-byte secret key)
  const ed25519PublicKey = ed25519SecretKey.subarray(32, 64);
  const x25519Public = sodium.crypto_sign_ed25519_pk_to_curve25519(
    ed25519PublicKey,
  );

  return {
    publicKey: new Uint8Array(x25519Public),
    secretKey: new Uint8Array(x25519Secret),
  };
}
