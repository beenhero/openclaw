/**
 * Durable, cross-process-safe proof/audit ledger for capability approval.
 *
 * Replaces the in-memory proof registry's TOCTOU-prone two-op consume
 * (assertProofFresh + recordAndConsumeProof) with a single atomic consumeOnce
 * under a proper-lockfile advisory lock on the index file.
 *
 * Two implementations:
 *   - InMemoryProofLedger: in-process only, for tests and single-process use
 *   - FileProofLedger: durable, cross-process-safe, mirroring auth-storage.ts
 *
 * BYTE-PARITY GUARANTEE: both implementations run through ONE parametrized test
 * suite and must produce identical LedgerConsumeResult values for identical call
 * sequences. Any divergence is a bug.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { acquireLockSyncWithRetry } from "../agents/sessions/storage-lock.js";
import { replaceFileAtomicSync } from "../infra/replace-file.js";

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type LedgerConsumeResult =
  | { ok: true }
  | { ok: false; reason: "already_consumed" | "replayed" | "invalid_identifier" };

export interface ProofLedger {
  /**
   * CONSUME half — single-use + replay gate.
   * Folds assertProofFresh + recordAndConsumeProof into ONE atomic op under ONE lock.
   *
   * Decision logic (6 steps):
   *  1. Guard falsy requestId/paramsDigest → invalid_identifier
   *  2. Guard empty-string proof → invalid_identifier
   *  3. Parse state (empty/undefined → fresh)
   *  4. Replay check (proof !== undefined && seen → replayed)
   *  5. Single-use check (consumed.has(key) → already_consumed)
   *  6. Success: record + return ok:true
   *
   * undefined proof is NOT single-shotted (absent-proof providers not penalized).
   */
  consumeOnce(
    proof: string | undefined,
    requestId: string,
    paramsDigest: string,
    outcome: "allow" | "deny",
  ): LedgerConsumeResult;
}

// ---------------------------------------------------------------------------
// Shared types for ProofRecord (used by both implementations)
// ---------------------------------------------------------------------------

type ProofRecord = {
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  proof?: string;
  consumedAt: number;
};

// ---------------------------------------------------------------------------
// proofKey — injective encoding, shared between implementations and on-disk format
// ---------------------------------------------------------------------------

/**
 * Produces a unique composite key for a {requestId, paramsDigest} pair.
 * Length-prefix + null-byte encoding prevents ambiguity:
 *   proofKey('a b','c') !== proofKey('a','b c')
 */
export function proofKey(requestId: string, paramsDigest: string): string {
  return `${requestId.length}:${requestId}\0${paramsDigest}`;
}

// ---------------------------------------------------------------------------
// InMemoryProofLedger
// ---------------------------------------------------------------------------

/**
 * In-process proof ledger. Identical decision logic to FileProofLedger but
 * backed by Map + Set instead of a lock-protected JSON file.
 *
 * Suitable for tests (inject via opts.ledger) and single-process use.
 * NOT cross-process safe; no durability across restarts.
 */
export class InMemoryProofLedger implements ProofLedger {
  private consumed = new Map<string, ProofRecord>();
  private seen = new Set<string>();

  consumeOnce(
    proof: string | undefined,
    requestId: string,
    paramsDigest: string,
    outcome: "allow" | "deny",
  ): LedgerConsumeResult {
    // Step 1: Guard falsy identifiers
    if (!requestId || !paramsDigest) {
      return { ok: false, reason: "invalid_identifier" };
    }
    // Step 2: Guard empty-string proof
    if (proof === "") {
      return { ok: false, reason: "invalid_identifier" };
    }
    // Step 4: Replay check (skip if proof===undefined)
    if (proof !== undefined && this.seen.has(proof)) {
      return { ok: false, reason: "replayed" };
    }
    // Step 5: Single-use check
    const key = proofKey(requestId, paramsDigest);
    if (this.consumed.has(key)) {
      return { ok: false, reason: "already_consumed" };
    }
    // Step 6: Success
    if (proof !== undefined) {
      this.seen.add(proof);
    }
    this.consumed.set(key, {
      requestId,
      paramsDigest,
      outcome,
      ...(proof !== undefined ? { proof } : {}),
      consumedAt: Date.now(),
    });
    return { ok: true };
  }

  /** Clears all state. Test-only. */
  clear(): void {
    this.consumed.clear();
    this.seen.clear();
  }
}

// ---------------------------------------------------------------------------
// FileProofLedger — on-disk format
// ---------------------------------------------------------------------------

/**
 * On-disk index shape (v1, versioned for forward-compat):
 * {
 *   "v": 1,
 *   "records": {
 *     "<proofKey>": { requestId, paramsDigest, outcome, proof?, consumedAt }
 *   },
 *   "seenProofs": ["<proof-string>", ...]
 * }
 */
type ProofIndex = {
  v: 1;
  records: Record<string, ProofRecord>;
  seenProofs: string[];
};

function freshIndex(): ProofIndex {
  return { v: 1, records: {}, seenProofs: [] };
}

type LockResult<T> = {
  result: T;
  next?: string;
};

/**
 * Durable, cross-process-safe proof ledger.
 *
 * Mirrors FileAuthStorageBackend.withLock (auth-storage.ts:100-115) verbatim:
 * - ensureParentDir (mode 0o700)
 * - ensureFileExists (index seeded '{}' mode 0o600)
 * - acquireLockSyncWithRetry(indexPath)
 * - readFileSync current content inside lock
 * - fn parses + decides + returns next index JSON
 * - replaceFileAtomicSync ONLY if next is defined
 * - release in finally
 *
 * consumeOnce runs the same 6-step decision logic as InMemoryProofLedger
 * inside the lock so read+write is one indivisible critical section.
 */
export class FileProofLedger implements ProofLedger {
  private dir: string;
  private indexPath: string;

  constructor(dir: string) {
    this.dir = dir;
    this.indexPath = join(dir, "proof-index.json");
    this.ensureDir();
    this.ensureIndex();
  }

  private ensureDir(): void {
    if (!existsSync(this.dir)) {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    }
  }

  private ensureIndex(): void {
    if (!existsSync(this.indexPath)) {
      writeFileSync(this.indexPath, "{}", "utf-8");
      chmodSync(this.indexPath, 0o600);
    }
  }

  private replaceIndexAtomic(content: string): void {
    const dirMode = statSync(this.dir).mode & 0o7777;
    replaceFileAtomicSync({
      filePath: this.indexPath,
      content,
      dirMode,
      mode: 0o600,
      tempPrefix: "proof-index.json",
      syncTempFile: true,
      syncParentDir: true,
    });
  }

  private withLock<T>(fn: (current: string | undefined) => LockResult<T>): T {
    this.ensureDir();
    this.ensureIndex();

    const release = acquireLockSyncWithRetry(this.indexPath);
    try {
      const current = existsSync(this.indexPath)
        ? readFileSync(this.indexPath, "utf-8")
        : undefined;
      const { result, next } = fn(current);
      if (next !== undefined) {
        this.replaceIndexAtomic(next);
      }
      return result;
    } finally {
      release();
    }
  }

  consumeOnce(
    proof: string | undefined,
    requestId: string,
    paramsDigest: string,
    outcome: "allow" | "deny",
  ): LedgerConsumeResult {
    return this.withLock<LedgerConsumeResult>((current) => {
      // Step 1: Guard falsy identifiers (read-only, no write)
      if (!requestId || !paramsDigest) {
        return { result: { ok: false as const, reason: "invalid_identifier" as const } };
      }
      // Step 2: Guard empty-string proof (read-only, no write)
      if (proof === "") {
        return { result: { ok: false as const, reason: "invalid_identifier" as const } };
      }

      // Step 3: Parse index (empty/undefined → fresh empty index)
      // NOTE: JSON.parse throws on corrupt content — do NOT catch (fail-closed, no amnesty)
      const index: ProofIndex =
        current && current.trim() !== "" && current.trim() !== "{}"
          ? (JSON.parse(current) as ProofIndex)
          : freshIndex();

      const consumed = new Map<string, ProofRecord>(Object.entries(index.records ?? {}));
      const seen = new Set<string>(index.seenProofs ?? []);

      // Step 4: Replay check (skip if proof===undefined)
      if (proof !== undefined && seen.has(proof)) {
        return { result: { ok: false as const, reason: "replayed" as const } };
      }

      // Step 5: Single-use check
      const key = proofKey(requestId, paramsDigest);
      if (consumed.has(key)) {
        return { result: { ok: false as const, reason: "already_consumed" as const } };
      }

      // Step 6: Success — build updated index and return next
      if (proof !== undefined) {
        seen.add(proof);
      }
      const record: ProofRecord = {
        requestId,
        paramsDigest,
        outcome,
        ...(proof !== undefined ? { proof } : {}),
        consumedAt: Date.now(),
      };
      consumed.set(key, record);

      const updatedIndex: ProofIndex = {
        v: 1,
        records: Object.fromEntries(consumed),
        seenProofs: Array.from(seen),
      };

      return {
        result: { ok: true as const },
        next: JSON.stringify(updatedIndex),
      };
    });
  }
}
