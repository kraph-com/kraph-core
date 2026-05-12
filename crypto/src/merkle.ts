import { sha256 } from "@noble/hashes/sha256";

/**
 * A Merkle inclusion proof: an array of sibling hashes with their
 * positions relative to the path from leaf to root.
 */
export type MerkleProof = Array<{ hash: Uint8Array; position: "left" | "right" }>;

/**
 * An incremental Merkle tree for database state commitments.
 *
 * Leaves are stored in a Map keyed by primary key string. The tree is
 * rebuilt on demand when the root or a proof is requested. For
 * incremental updates, only insert/remove mutate the leaf set; the
 * binary tree is computed lazily.
 *
 * Internal nodes are SHA-256(left || right). Leaves are sorted by key
 * before building the binary tree so the root is deterministic
 * regardless of insertion order. When a level has an odd number of
 * nodes, the last node is promoted to the next level unchanged.
 */
export class MerkleTree {
  private leaves: Map<string, Uint8Array>;

  /** Cached sorted keys (invalidated on mutation). */
  private sortedKeys: string[] | null = null;

  constructor() {
    this.leaves = new Map();
  }

  /**
   * Number of leaves in the tree.
   */
  get size(): number {
    return this.leaves.size;
  }

  /**
   * Add or update a leaf. The key is the primary key string, the value
   * is the SHA-256 hash of the row data.
   *
   * @param key   - primary key string
   * @param value - 32-byte SHA-256 hash of the row data
   */
  insert(key: string, value: Uint8Array): void {
    if (typeof key !== "string" || key.length === 0) {
      throw new TypeError("key must be a non-empty string");
    }
    if (!(value instanceof Uint8Array) || value.length !== 32) {
      throw new RangeError("value must be a 32-byte Uint8Array");
    }
    this.leaves.set(key, new Uint8Array(value));
    this.sortedKeys = null; // invalidate cache
  }

  /**
   * Remove a leaf by key.
   *
   * @param key - primary key string
   */
  remove(key: string): void {
    if (this.leaves.delete(key)) {
      this.sortedKeys = null; // invalidate cache
    }
  }

  /**
   * Compute the Merkle root.
   *
   * Sorts leaves by key, then builds a binary tree bottom-up.
   * SHA-256(left || right) for internal nodes. Odd-count levels
   * promote the last node.
   *
   * @returns 32-byte Merkle root, or a zero hash if the tree is empty.
   */
  getRoot(): Uint8Array {
    if (this.leaves.size === 0) {
      return new Uint8Array(32); // zero hash for empty tree
    }

    const keys = this.getSortedKeys();
    let level: Uint8Array[] = keys.map((k) => this.leaves.get(k)!);

    while (level.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          next.push(hashPair(level[i]!, level[i + 1]!));
        } else {
          // Odd node: promote unchanged
          next.push(level[i]!);
        }
      }
      level = next;
    }

    return new Uint8Array(level[0]!);
  }

  /**
   * Generate a Merkle inclusion proof for a specific key.
   *
   * @param key - primary key string that must exist in the tree
   * @returns array of {hash, position} entries from leaf to root
   */
  getProof(key: string): MerkleProof {
    if (!this.leaves.has(key)) {
      throw new Error(`Key "${key}" not found in tree`);
    }
    if (this.leaves.size === 1) {
      return []; // single leaf is the root; no siblings needed
    }

    const keys = this.getSortedKeys();
    const leafIndex = keys.indexOf(key);

    let level: Uint8Array[] = keys.map((k) => this.leaves.get(k)!);
    let targetIdx = leafIndex;
    const proof: MerkleProof = [];

    while (level.length > 1) {
      const next: Uint8Array[] = [];
      let nextTargetIdx = -1;

      for (let i = 0; i < level.length; i += 2) {
        const pairIdx = Math.floor(i / 2);

        if (i + 1 < level.length) {
          // Full pair
          if (i === targetIdx) {
            // Target is the left child; sibling is on the right
            proof.push({ hash: new Uint8Array(level[i + 1]!), position: "right" });
            nextTargetIdx = pairIdx;
          } else if (i + 1 === targetIdx) {
            // Target is the right child; sibling is on the left
            proof.push({ hash: new Uint8Array(level[i]!), position: "left" });
            nextTargetIdx = pairIdx;
          }
          next.push(hashPair(level[i]!, level[i + 1]!));
        } else {
          // Odd node promoted: no sibling
          if (i === targetIdx) {
            nextTargetIdx = pairIdx;
            // No proof entry needed for promotion
          }
          next.push(level[i]!);
        }
      }

      level = next;
      targetIdx = nextTargetIdx;
    }

    return proof;
  }

  /**
   * Verify a Merkle inclusion proof against a root.
   *
   * @param leaf  - 32-byte leaf hash
   * @param proof - Merkle proof from getProof()
   * @param root  - expected 32-byte Merkle root
   * @returns true if the proof is valid
   */
  static verifyProof(
    leaf: Uint8Array,
    proof: MerkleProof,
    root: Uint8Array,
  ): boolean {
    if (!(leaf instanceof Uint8Array) || leaf.length !== 32) {
      throw new Error("leaf must be a 32-byte Uint8Array");
    }
    if (!(root instanceof Uint8Array) || root.length !== 32) {
      throw new Error("root must be a 32-byte Uint8Array");
    }

    let current = leaf;

    for (const step of proof) {
      if (step.position === "left") {
        current = hashPair(step.hash, current);
      } else {
        current = hashPair(current, step.hash);
      }
    }

    return constantTimeEqual(current, root);
  }

  /**
   * Returns sorted keys, caching the result.
   */
  private getSortedKeys(): string[] {
    if (this.sortedKeys === null) {
      this.sortedKeys = Array.from(this.leaves.keys()).sort();
    }
    return this.sortedKeys;
  }
}

/**
 * Hashes two 32-byte child nodes: SHA-256(left || right).
 */
function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(64);
  combined.set(left, 0);
  combined.set(right, 32);
  return new Uint8Array(sha256(combined));
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
