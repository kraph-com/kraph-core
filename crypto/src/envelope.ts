import { initSodium } from "./keys.js";

/**
 * XChaCha20-Poly1305 constants.
 * We use XChaCha instead of AES-GCM because libsodium's pure JS/WASM build
 * does not guarantee AES-GCM availability, and XChaCha is faster in WASM.
 */
const NONCE_BYTES = 24; // XChaCha20-Poly1305 nonce length
const TAG_BYTES = 16; // Poly1305 authentication tag length
const KEY_BYTES = 32; // 256-bit key

/**
 * Generates a random 256-bit Data Encryption Key (DEK).
 *
 * @returns 32-byte random key
 */
export async function generateDEK(): Promise<Uint8Array> {
  const sodium = await initSodium();
  return new Uint8Array(sodium.randombytes_buf(KEY_BYTES));
}

function validateKey(key: Uint8Array, name: string): void {
  if (!(key instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (key.length !== KEY_BYTES) {
    throw new RangeError(
      `${name} must be ${KEY_BYTES} bytes, got ${key.length}`,
    );
  }
}

/**
 * Encrypts a DEK with the master key using XChaCha20-Poly1305.
 *
 * Output layout: [nonce (24 B) | ciphertext + tag]
 *
 * @param masterKey - 32-byte master key
 * @param dek       - 32-byte DEK to encrypt
 * @returns nonce || ciphertext || tag concatenated
 */
export async function encryptDEK(
  masterKey: Uint8Array,
  dek: Uint8Array,
): Promise<Uint8Array> {
  validateKey(masterKey, "masterKey");
  validateKey(dek, "dek");

  const sodium = await initSodium();

  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ciphertextWithTag =
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      dek,
      null, // no additional data
      null, // nsec (unused, must be null)
      nonce,
      masterKey,
    );

  const result = new Uint8Array(NONCE_BYTES + ciphertextWithTag.length);
  result.set(nonce, 0);
  result.set(ciphertextWithTag, NONCE_BYTES);
  return result;
}

/**
 * Decrypts a DEK that was encrypted with {@link encryptDEK}.
 *
 * @param masterKey    - 32-byte master key
 * @param encryptedDek - output of encryptDEK (nonce || ciphertext || tag)
 * @returns 32-byte DEK plaintext
 */
export async function decryptDEK(
  masterKey: Uint8Array,
  encryptedDek: Uint8Array,
): Promise<Uint8Array> {
  validateKey(masterKey, "masterKey");

  if (!(encryptedDek instanceof Uint8Array)) {
    throw new TypeError("encryptedDek must be a Uint8Array");
  }
  const minLen = NONCE_BYTES + TAG_BYTES + 1; // at least 1 byte of ciphertext
  if (encryptedDek.length < minLen) {
    throw new RangeError(
      `encryptedDek too short: expected at least ${minLen} bytes, got ${encryptedDek.length}`,
    );
  }

  const sodium = await initSodium();

  const nonce = encryptedDek.subarray(0, NONCE_BYTES);
  const ciphertextWithTag = encryptedDek.subarray(NONCE_BYTES);

  try {
    const plaintext =
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, // nsec (unused)
        ciphertextWithTag,
        null, // no additional data
        nonce,
        masterKey,
      );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("DEK decryption failed: authentication tag mismatch");
  }
}

/**
 * General-purpose XChaCha20-Poly1305 encryption.
 *
 * Output layout: [nonce (24 B) | ciphertext + tag]
 *
 * @param dek       - 32-byte data encryption key
 * @param plaintext - data to encrypt
 * @returns nonce || ciphertext || tag
 */
export async function encryptData(
  dek: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  validateKey(dek, "dek");
  if (!(plaintext instanceof Uint8Array)) {
    throw new TypeError("plaintext must be a Uint8Array");
  }

  const sodium = await initSodium();

  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ciphertextWithTag =
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      null,
      null,
      nonce,
      dek,
    );

  const result = new Uint8Array(NONCE_BYTES + ciphertextWithTag.length);
  result.set(nonce, 0);
  result.set(ciphertextWithTag, NONCE_BYTES);
  return result;
}

/**
 * General-purpose XChaCha20-Poly1305 decryption.
 *
 * @param dek        - 32-byte data encryption key
 * @param ciphertext - output of encryptData (nonce || ciphertext || tag)
 * @returns decrypted plaintext
 */
export async function decryptData(
  dek: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  validateKey(dek, "dek");
  if (!(ciphertext instanceof Uint8Array)) {
    throw new TypeError("ciphertext must be a Uint8Array");
  }
  if (ciphertext.length < NONCE_BYTES + TAG_BYTES) {
    throw new RangeError(
      `ciphertext too short: expected at least ${NONCE_BYTES + TAG_BYTES} bytes, got ${ciphertext.length}`,
    );
  }

  const sodium = await initSodium();

  const nonce = ciphertext.subarray(0, NONCE_BYTES);
  const ciphertextWithTag = ciphertext.subarray(NONCE_BYTES);

  try {
    const plaintext =
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertextWithTag,
        null,
        nonce,
        dek,
      );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("Decryption failed: authentication tag mismatch");
  }
}
