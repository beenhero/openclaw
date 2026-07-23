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

import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { acquireLockSyncWithRetry } from "../agents/sessions/storage-lock.js";
import { replaceFileAtomicSync } from "../infra/replace-file.js";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function sha256hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

type AuditDecision = "consumed" | "replayed" | "already_consumed" | "invalid_identifier";

type AuditEntry = {
  ts: number;
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  proofHash: string | null;
  decision: AuditDecision;
};

/**
 * Ensure the JSONL audit file exists with mode 0o600.
 * Called once at the start of each consumeOnce critical section.
 */
function ensureJsonlFile(jsonlPath: string): void {
  if (!existsSync(jsonlPath)) {
    // Open with 'a' flag and mode 0o600 — creates the file if absent
    const fd = openSync(jsonlPath, "a", 0o600);
    closeSync(fd);
    chmodSync(jsonlPath, 0o600);
  }
}

/**
 * Append one audit line to the JSONL file, then fsync for durability.
 * Throws on any I/O error — callers must NOT catch (fail-closed invariant).
 */
function appendAuditLine(jsonlPath: string, entry: AuditEntry): void {
  const line = `${JSON.stringify(entry)}\n`;
  appendFileSync(jsonlPath, line, "utf-8");
  // fsync so the line is on-disk before the lock releases
  const fd = openSync(jsonlPath, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

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
  private jsonlPath: string;

  constructor(dir: string) {
    this.dir = dir;
    this.indexPath = join(dir, "proof-index.json");
    this.jsonlPath = join(dir, "proof-ledger.jsonl");
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
    const jsonlPath = this.jsonlPath;

    return this.withLock<LedgerConsumeResult>((current) => {
      // Ensure JSONL file exists with correct permissions (first-use creation)
      ensureJsonlFile(jsonlPath);

      const proofHash = proof !== undefined ? sha256hex(proof) : null;

      // Step 1: Guard falsy identifiers (read-only, no write)
      if (!requestId || !paramsDigest) {
        // Audit line BEFORE returning (audit even for early-return legs)
        appendAuditLine(jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "invalid_identifier",
        });
        return { result: { ok: false as const, reason: "invalid_identifier" as const } };
      }
      // Step 2: Guard empty-string proof (read-only, no write)
      if (proof === "") {
        // Audit line BEFORE returning
        appendAuditLine(jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash: null,
          decision: "invalid_identifier",
        });
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
        // Audit BEFORE returning — no index mutation
        appendAuditLine(jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "replayed",
        });
        return { result: { ok: false as const, reason: "replayed" as const } };
      }

      // Step 5: Single-use check
      const key = proofKey(requestId, paramsDigest);
      if (consumed.has(key)) {
        // Audit BEFORE returning — no index mutation
        appendAuditLine(jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "already_consumed",
        });
        return { result: { ok: false as const, reason: "already_consumed" as const } };
      }

      // Step 6: Success — audit FIRST, then build updated index
      // Audit append precedes index mutation: if append throws, index is NOT written
      appendAuditLine(jsonlPath, {
        ts: Date.now(),
        requestId,
        paramsDigest,
        outcome,
        proofHash,
        decision: "consumed",
      });

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
