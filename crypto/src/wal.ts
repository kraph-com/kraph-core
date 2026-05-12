import { sha256 } from "@noble/hashes/sha256";
import { initSodium } from "./keys.js";

const CHUNK_SIZE = 65536; // 64 KB
const STREAMING_THRESHOLD = 1048576; // 1 MB
const NONCE_BYTES = 24; // XChaCha20-Poly1305 nonce
const TAG_BYTES = 16; // Poly1305 tag
const KEY_BYTES = 32;

// Header layout:
//   [4 bytes chunk size (LE)]
//   [8 bytes total chunks (LE, as two 32-bit words)]
//   [24 bytes base nonce]

const HEADER_SIZE = 4 + 8 + NONCE_BYTES; // 36 bytes

/**
 * Derives a per-chunk nonce from a base nonce and chunk index.
 * XORs the chunk index (as little-endian 8 bytes) into the last 8 bytes
 * of the base nonce. This ensures each chunk gets a unique nonce.
 */
function deriveChunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
  const nonce = new Uint8Array(baseNonce);
  // XOR chunk index into the last 8 bytes of the nonce
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  // Read current value at offset 16 (last 8 bytes), XOR with index
  const low = view.getUint32(16, true);
  view.setUint32(16, (low ^ chunkIndex) >>> 0, true);
  return nonce;
}

/**
 * Encrypts a WAL segment using XChaCha20-Poly1305.
 *
 * For segments > 1 MB, uses chunked encryption with 64 KB chunks.
 * For segments <= 1 MB, encrypts as a single chunk.
 *
 * Output format:
 *   [4 bytes chunk size (LE)]
 *   [8 bytes total chunks (LE)]
 *   [24 bytes base nonce]
 *   [encrypted chunk 0]
 *   [encrypted chunk 1]
 *   ...
 *
 * Each encrypted chunk is: ciphertext + tag (no per-chunk nonce stored,
 * since nonces are derived from base nonce + chunk index).
 *
 * @param dek     - 32-byte data encryption key
 * @param segment - raw WAL segment data
 * @returns encrypted WAL segment with header
 */
export async function encryptWALSegment(
  dek: Uint8Array,
  segment: Uint8Array,
): Promise<Uint8Array> {
  if (!(dek instanceof Uint8Array) || dek.length !== KEY_BYTES) {
    throw new RangeError(`dek must be ${KEY_BYTES} bytes`);
  }
  if (!(segment instanceof Uint8Array)) {
    throw new TypeError("segment must be a Uint8Array");
  }

  const sodium = await initSodium();

  const chunkSize =
    segment.length > STREAMING_THRESHOLD ? CHUNK_SIZE : segment.length;
  const totalChunks =
    segment.length === 0
      ? 0
      : Math.ceil(segment.length / chunkSize);

  const baseNonce = new Uint8Array(sodium.randombytes_buf(NONCE_BYTES));

  // Pre-compute total output size
  // Each encrypted chunk = original chunk data size + TAG_BYTES
  let totalEncryptedSize = HEADER_SIZE;
  for (let i = 0; i < totalChunks; i++) {
    const offset = i * chunkSize;
    const end = Math.min(offset + chunkSize, segment.length);
    const plainChunkLen = end - offset;
    totalEncryptedSize += plainChunkLen + TAG_BYTES;
  }

  const output = new Uint8Array(totalEncryptedSize);
  const headerView = new DataView(output.buffer, 0, HEADER_SIZE);

  // Write header
  headerView.setUint32(0, chunkSize, true);
  // Write total chunks as 8 bytes LE (two 32-bit words)
  headerView.setUint32(4, totalChunks, true);
  headerView.setUint32(8, 0, true); // high 32 bits (always 0 for practical sizes)
  output.set(baseNonce, 12);

  let writeOffset = HEADER_SIZE;

  for (let i = 0; i < totalChunks; i++) {
    const chunkStart = i * chunkSize;
    const chunkEnd = Math.min(chunkStart + chunkSize, segment.length);
    const plainChunk = segment.subarray(chunkStart, chunkEnd);

    const nonce = deriveChunkNonce(baseNonce, i);

    const ciphertextWithTag =
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plainChunk,
        null,
        null,
        nonce,
        dek,
      );

    output.set(ciphertextWithTag, writeOffset);
    writeOffset += ciphertextWithTag.length;
  }

  return output;
}

/**
 * Decrypts a WAL segment that was encrypted with {@link encryptWALSegment}.
 *
 * @param dek       - 32-byte data encryption key
 * @param encrypted - encrypted WAL segment (with header)
 * @returns decrypted WAL segment data
 */
export async function decryptWALSegment(
  dek: Uint8Array,
  encrypted: Uint8Array,
): Promise<Uint8Array> {
  if (!(dek instanceof Uint8Array) || dek.length !== KEY_BYTES) {
    throw new RangeError(`dek must be ${KEY_BYTES} bytes`);
  }
  if (!(encrypted instanceof Uint8Array)) {
    throw new TypeError("encrypted must be a Uint8Array");
  }
  if (encrypted.length < HEADER_SIZE) {
    throw new RangeError(
      `encrypted data too short: expected at least ${HEADER_SIZE} bytes, got ${encrypted.length}`,
    );
  }

  const sodium = await initSodium();

  const headerView = new DataView(
    encrypted.buffer,
    encrypted.byteOffset,
    HEADER_SIZE,
  );

  const chunkSize = headerView.getUint32(0, true);
  const totalChunks = headerView.getUint32(4, true);
  // high 32 bits at offset 8 ignored (always 0)
  const baseNonce = encrypted.subarray(12, 12 + NONCE_BYTES);

  if (totalChunks === 0) {
    return new Uint8Array(0);
  }

  // Collect decrypted chunks
  const decryptedChunks: Uint8Array[] = [];
  let readOffset = HEADER_SIZE;

  for (let i = 0; i < totalChunks; i++) {
    // Determine expected ciphertext size for this chunk
    // For the last chunk, it may be smaller than chunkSize
    const isLastChunk = i === totalChunks - 1;

    // We need to figure out the encrypted chunk length.
    // All chunks except possibly the last have chunkSize plaintext bytes.
    // Encrypted size = plaintext size + TAG_BYTES.
    // For the last chunk, we consume whatever remains.
    let encryptedChunkLen: number;
    if (isLastChunk) {
      encryptedChunkLen = encrypted.length - readOffset;
    } else {
      encryptedChunkLen = chunkSize + TAG_BYTES;
    }

    if (readOffset + encryptedChunkLen > encrypted.length) {
      throw new Error(
        `Encrypted WAL data truncated at chunk ${i}`,
      );
    }

    const ciphertextWithTag = encrypted.subarray(
      readOffset,
      readOffset + encryptedChunkLen,
    );
    readOffset += encryptedChunkLen;

    const nonce = deriveChunkNonce(baseNonce, i);

    try {
      const plaintext =
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          ciphertextWithTag,
          null,
          nonce,
          dek,
        );
      decryptedChunks.push(new Uint8Array(plaintext));
    } catch {
      throw new Error(
        `WAL chunk ${i} decryption failed: authentication tag mismatch`,
      );
    }
  }

  // Concatenate all decrypted chunks
  const totalLen = decryptedChunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of decryptedChunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Computes the WAL hash chain entry: SHA-256(previousHash || segment).
 * If previousHash is null, computes SHA-256(segment) alone.
 *
 * @param segment      - raw WAL segment data
 * @param previousHash - 32-byte hash of the previous chain entry, or null
 * @returns 32-byte SHA-256 hash
 */
export function computeWALHash(
  segment: Uint8Array,
  previousHash: Uint8Array | null,
): Uint8Array {
  if (!(segment instanceof Uint8Array)) {
    throw new TypeError("segment must be a Uint8Array");
  }
  if (previousHash !== null) {
    if (!(previousHash instanceof Uint8Array) || previousHash.length !== 32) {
      throw new RangeError("previousHash must be 32 bytes or null");
    }
    const combined = new Uint8Array(previousHash.length + segment.length);
    combined.set(previousHash, 0);
    combined.set(segment, previousHash.length);
    return new Uint8Array(sha256(combined));
  }

  return new Uint8Array(sha256(segment));
}

/**
 * Verifies an entire WAL hash chain.
 *
 * Each entry's hash must equal SHA-256(previousHash || data), where
 * previousHash is null for the first segment.
 *
 * @param segments - ordered array of {data, hash} entries
 * @returns true if the entire chain is valid
 */
export function verifyWALChain(
  segments: Array<{ data: Uint8Array; hash: Uint8Array }>,
): boolean {
  if (!Array.isArray(segments) || segments.length === 0) {
    return true; // empty chain is trivially valid
  }

  let previousHash: Uint8Array | null = null;

  for (let i = 0; i < segments.length; i++) {
    const entry = segments[i]!;

    if (
      !(entry.data instanceof Uint8Array) ||
      !(entry.hash instanceof Uint8Array) ||
      entry.hash.length !== 32
    ) {
      return false;
    }

    const expectedHash = computeWALHash(entry.data, previousHash);

    if (!constantTimeEqual(expectedHash, entry.hash)) {
      return false;
    }

    previousHash = entry.hash;
  }

  return true;
}

/**
 * Constant-time comparison for two equal-length Uint8Arrays.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
