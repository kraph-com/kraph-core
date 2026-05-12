// Key derivation
export {
  initSodium,
  deriveMasterKey,
  deriveEncryptionKeyFromSeed,
  solanaKeypairToX25519,
} from "./keys.js";

// Envelope encryption (DEK + master key)
export {
  generateDEK,
  encryptDEK,
  decryptDEK,
  encryptData,
  decryptData,
} from "./envelope.js";

// WAL segment encryption and hash chain
export {
  encryptWALSegment,
  decryptWALSegment,
  computeWALHash,
  verifyWALChain,
} from "./wal.js";

// Merkle tree for state commitments
export { MerkleTree } from "./merkle.js";
export type { MerkleProof } from "./merkle.js";
