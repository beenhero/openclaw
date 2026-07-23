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
 * Append one audit line to the JSONL file, then fsync file + parent dir for durability.
 * Throws on any I/O error — callers must NOT catch (fail-closed invariant).
 *
 * DURABILITY / TORN-LINE GUARANTEE (Defect 7): this JSONL is a best-effort,
 * append-only, tamper-evident supplementary trail — NOT the single-use/replay
 * authority (the index is). A short-write on ENOSPC/crash-mid-write can leave a
 * non-newline-terminated partial line; the next append concatenates after it.
 * Any downstream reader MUST tolerate a trailing partial line (skip/repair it)
 * — never assume every physical line is a complete JSON object. The gate is
 * unaffected because no decision path reads this file.
 *
 * Defect 6: we fsync `dir` (the parent) as well as the file, so a first-ever-creation
 * of the JSONL on a REJECT leg (which does NOT write the index and therefore does NOT
 * otherwise fsync the parent dir) has a durable directory entry too.
 */
function appendAuditLine(dir: string, jsonlPath: string, entry: AuditEntry): void {
  const line = `${JSON.stringify(entry)}\n`;
  appendFileSync(jsonlPath, line, "utf-8");
  // fsync the file so the line's data/inode is on-disk before the lock releases
  const fd = openSync(jsonlPath, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  // Defect 6: fsync the parent dir so a first-creation dir entry is durable on reject legs
  const dirFd = openSync(dir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type LedgerConsumeResult =
  | { ok: true }
  | { ok: false; reason: "already_consumed" | "replayed" | "invalid_identifier" };

/**
 * A non-repudiable audit record returned by getAuditRecord.
 *
 * Intentionally does NOT carry the raw proof (L2 secret-at-rest invariant:
 * the raw proof is a reusable secret and must never leave the ledger).
 * Contains only the data needed to correlate a requestId to its disposition.
 */
export type ProofAuditRecord = {
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  consumedAt: number;
};

export interface ProofLedger {
  /**
   * CONSUME half — single-use + replay gate.
   * Folds assertProofFresh + recordAndConsumeProof into ONE atomic op under ONE lock.
   *
   * Decision logic (6 steps):
   *  1. Guard falsy requestId/paramsDigest → invalid_identifier
   *  2. Guard empty-string proof → invalid_identifier
   *  3. Read + parse state (absent file → fresh; present-but-malformed → THROW, no amnesty)
   *  4. Replay check (proof !== undefined && sha256(proof) seen → replayed)
   *  5. Single-use check (consumed.has(key) → already_consumed)
   *  6. Success: commit index FIRST, then append audit → return ok:true
   *
   * undefined proof is NOT single-shotted (absent-proof providers not penalized).
   */
  consumeOnce(
    proof: string | undefined,
    requestId: string,
    paramsDigest: string,
    outcome: "allow" | "deny",
  ): LedgerConsumeResult;

  /**
   * RETAIN query half — retrieve non-repudiable audit record(s) by requestId.
   *
   * Returns all retained ProofAuditRecord entries whose requestId matches.
   * In normal operation there is exactly ONE record per requestId (single-use
   * constraint), but the return type is an array for forward-compatibility.
   *
   * Properties:
   *   - READ-ONLY: never consumes, never mutates, never throws (returns [] on
   *     missing requestId, missing ledger, or any I/O error).
   *   - NO raw proof: ProofAuditRecord intentionally omits the raw proof
   *     (L2 secret-at-rest invariant). The caller receives only the disposition.
   *   - DISTINCT from consumeOnce: calling getAuditRecord does NOT burn the proof.
   *   - DURABLE for FileProofLedger: survives process restart; reads the index.
   *
   * This makes the RETAIN half of the ledger QUERYABLE — closes the
   * #97152 "retrievable non-repudiable record" requirement.
   */
  getAuditRecord(requestId: string): ProofAuditRecord[];
}

// ---------------------------------------------------------------------------
// Shared types for ProofRecord (used by both implementations)
// ---------------------------------------------------------------------------

type ProofRecord = {
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  consumedAt: number;
};
// Defect 3 (secret-at-rest): ProofRecord carries NO raw `proof` field. The raw proof
// is a reusable secret and is never read by any decision path (single-use is keyed by
// proofKey; replay is a membership test over sha256(proof)), so it is never persisted.

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
  // Defect 3: membership is keyed by sha256(proof), NEVER the raw proof — decision-parity
  // with FileProofLedger, which stores only hashes at rest.
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
    const proofHash = proof !== undefined ? sha256hex(proof) : undefined;
    // Step 4: Replay check (skip if proof===undefined) — membership over the hash
    if (proofHash !== undefined && this.seen.has(proofHash)) {
      return { ok: false, reason: "replayed" };
    }
    // Step 5: Single-use check
    const key = proofKey(requestId, paramsDigest);
    if (this.consumed.has(key)) {
      return { ok: false, reason: "already_consumed" };
    }
    // Step 6: Success
    if (proofHash !== undefined) {
      this.seen.add(proofHash);
    }
    this.consumed.set(key, {
      requestId,
      paramsDigest,
      outcome,
      consumedAt: Date.now(),
    });
    return { ok: true };
  }

  /**
   * RETAIN query: scan the consumed Map for entries whose requestId matches.
   * Returns the matching ProofAuditRecord(s) — never throws, returns [] when
   * the requestId is unknown or has not been consumed yet.
   *
   * READ-ONLY. Does NOT burn the proof or mutate any state.
   * The raw proof is NEVER returned (L2 secret-at-rest invariant: ProofRecord
   * and ProofAuditRecord carry no raw proof field — only the disposition).
   */
  getAuditRecord(requestId: string): ProofAuditRecord[] {
    if (!requestId) return [];
    const results: ProofAuditRecord[] = [];
    for (const record of this.consumed.values()) {
      if (record.requestId === requestId) {
        results.push({
          requestId: record.requestId,
          paramsDigest: record.paramsDigest,
          outcome: record.outcome,
          consumedAt: record.consumedAt,
        });
      }
    }
    return results;
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
 *     "<proofKey>": { requestId, paramsDigest, outcome, consumedAt }
 *   },
 *   "seenProofHashes": ["<sha256hex(proof)>", ...]
 * }
 *
 * Defect 3 (secret-at-rest): the on-disk field is `seenProofHashes` — sha256(proof) hex,
 * NOT the raw reusable proof secret. records[] carry NO `proof` field either. Neither
 * decision path needs the raw value (single-use is keyed by proofKey; replay is membership
 * over the hash), so the raw proof never touches disk (nor the atomic-replace temp file,
 * nor a JSON.parse-error byte-leak channel).
 */
type ProofIndex = {
  v: 1;
  records: Record<string, ProofRecord>;
  seenProofHashes: string[];
};

/** The canonical fresh/empty index — seeded on file creation and used for absent files. */
function freshIndex(): ProofIndex {
  return { v: 1, records: {}, seenProofHashes: [] };
}

/** Serialized fresh index — written verbatim by ensureIndex so an empty ledger parses valid. */
const FRESH_INDEX_JSON = JSON.stringify(freshIndex());

/**
 * Defect 1 (fail-closed shape validation): assert the parsed index is EXACTLY the v1 shape.
 * Throws (never resets-to-empty) on ANY mismatch — a valid-JSON-but-wrong-shape index
 * (`{"v":1}`, `[]`, `123`, `true`, `"x"`, records-as-array, wrong `v`, etc.) would otherwise
 * silently amnesty every prior consumed proof. Called BEFORE any decision is made.
 *
 * Per-element deep validation (seenProofHashes elements + records values) is defense-in-depth
 * given the presence-only decision logic — the gate does not read record field values at
 * decision time, but rejecting corrupt payloads early is cheaper than chasing subtle bugs.
 */
function assertProofIndexShape(idx: unknown): asserts idx is ProofIndex {
  const bad =
    idx === null ||
    typeof idx !== "object" ||
    Array.isArray(idx) ||
    (idx as ProofIndex).v !== 1 ||
    typeof (idx as ProofIndex).records !== "object" ||
    (idx as ProofIndex).records === null ||
    Array.isArray((idx as ProofIndex).records) ||
    !Array.isArray((idx as ProofIndex).seenProofHashes);
  if (bad) {
    throw new Error("proof-index: malformed/corrupt index — refusing to reset-to-empty");
  }
  // Deep-validate each seenProofHashes element is a string.
  const hashes = (idx as ProofIndex).seenProofHashes;
  for (const h of hashes) {
    if (typeof h !== "string") {
      throw new Error("proof-index: malformed/corrupt index — refusing to reset-to-empty");
    }
  }
  // Deep-validate each records value carries the expected core fields with correct types.
  // Tolerant of extra fields; rejects missing or wrong-typed core fields.
  const records = (idx as ProofIndex).records;
  for (const rec of Object.values(records)) {
    const r = rec as Record<string, unknown>;
    if (
      typeof r["requestId"] !== "string" ||
      typeof r["paramsDigest"] !== "string" ||
      (r["outcome"] !== "allow" && r["outcome"] !== "deny") ||
      typeof r["consumedAt"] !== "number"
    ) {
      throw new Error("proof-index: malformed/corrupt index — refusing to reset-to-empty");
    }
  }
}

/**
 * Durable, cross-process-safe proof ledger.
 *
 * Mirrors FileAuthStorageBackend.withLock (auth-storage.ts:100-115):
 * - ensureParentDir (mode 0o700)
 * - ensureFileExists (index seeded with a FULL fresh index JSON, mode 0o600 — Defect 1)
 * - acquireLockSyncWithRetry(indexPath)
 * - readFileSync current content inside lock
 * - consumeOnce parses + shape-validates + decides
 *
 * consumeOnce inlines the lock sequence (acquire → read → validate → decide → on success:
 * write-index-FIRST then append-audit → finally release) so read+write is one indivisible
 * critical section AND the index-first crash ordering (Defect 2) holds.
 *
 * CRASH-CONSISTENCY INVARIANT (Defect 2): index(consumed) ⊇ audit-trail.
 * The index is the sole single-use/replay authority AND a retained record. On a successful
 * consume the index is committed durably FIRST (atomic temp+fsync+rename), THEN the JSONL
 * audit line is appended best-effort. A committed consume is therefore durable and is NEVER
 * bypassed on crash/restart; its audit line may LAG by at most the in-flight line, never LEAD.
 * If the post-commit audit append throws, the consume is already committed (single-use holds)
 * and we re-throw so the caller DENIES — the proof is "burned" (committed but denied). That is
 * the accepted fail-closed tradeoff: a rare audit-write failure burns a proof rather than risk
 * a single-use bypass.
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
      // Defect 1: seed a FULL fresh index (not "{}") so a freshly-created empty ledger
      // parses to the valid v1 shape — "{}" would fail shape-validation (correctly),
      // so we must not create the file in that degenerate form.
      writeFileSync(this.indexPath, FRESH_INDEX_JSON, "utf-8");
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

  /**
   * consumeOnce inlines the lock sequence (Defect 2 — index-first crash ordering).
   * consumeOnce is the ONLY writer, so there is no generic withLock helper: a single
   * critical section acquires the lock, reads + shape-validates the index, decides, and on
   * SUCCESS writes the index durably FIRST, THEN appends the audit line — all before release.
   */
  consumeOnce(
    proof: string | undefined,
    requestId: string,
    paramsDigest: string,
    outcome: "allow" | "deny",
  ): LedgerConsumeResult {
    const jsonlPath = this.jsonlPath;
    const dir = this.dir;

    this.ensureDir();
    this.ensureIndex();

    const release = acquireLockSyncWithRetry(this.indexPath);
    try {
      // Ensure JSONL file exists with correct permissions (first-use creation)
      ensureJsonlFile(jsonlPath);

      const proofHash = proof !== undefined ? sha256hex(proof) : null;

      // Step 1: Guard falsy identifiers (read-only, no index write). Nothing is consumed,
      // so a reject-leg audit append failure just throws → caller denies (no burn).
      if (!requestId || !paramsDigest) {
        appendAuditLine(dir, jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "invalid_identifier",
        });
        return { ok: false, reason: "invalid_identifier" };
      }
      // Step 2: Guard empty-string proof (read-only, no index write)
      if (proof === "") {
        appendAuditLine(dir, jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash: null,
          decision: "invalid_identifier",
        });
        return { ok: false, reason: "invalid_identifier" };
      }

      // Step 3: Read + parse index.
      // Treat ONLY current===undefined (file genuinely absent) as fresh-empty. A present
      // index — including "" (JSON.parse throws) and "{}" — must go through shape-validation
      // and THROW if malformed (Defect 1: no amnesty, no reset-to-empty). JSON.parse throws
      // on corrupt content — do NOT catch (fail-closed).
      const current = existsSync(this.indexPath)
        ? readFileSync(this.indexPath, "utf-8")
        : undefined;
      let index: ProofIndex;
      if (current === undefined) {
        index = freshIndex();
      } else {
        const parsed: unknown = JSON.parse(current);
        assertProofIndexShape(parsed); // THROWS on any shape/type/version mismatch
        index = parsed;
      }

      const consumed = new Map<string, ProofRecord>(Object.entries(index.records));
      const seen = new Set<string>(index.seenProofHashes);

      // Step 4: Replay check (skip if proof===undefined) — membership over the HASH (Defect 3)
      if (proofHash !== null && seen.has(proofHash)) {
        appendAuditLine(dir, jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "replayed",
        });
        return { ok: false, reason: "replayed" };
      }

      // Step 5: Single-use check
      const key = proofKey(requestId, paramsDigest);
      if (consumed.has(key)) {
        appendAuditLine(dir, jsonlPath, {
          ts: Date.now(),
          requestId,
          paramsDigest,
          outcome,
          proofHash,
          decision: "already_consumed",
        });
        return { ok: false, reason: "already_consumed" };
      }

      // Step 6: Success — INDEX-FIRST ordering (Defect 2).
      // Build the updated index and COMMIT it durably (atomic temp+fsync+rename) as the
      // authoritative single-use gate. Store only the proof HASH at rest (Defect 3).
      if (proofHash !== null) {
        seen.add(proofHash);
      }
      consumed.set(key, {
        requestId,
        paramsDigest,
        outcome,
        consumedAt: Date.now(),
      });
      const updatedIndex: ProofIndex = {
        v: 1,
        records: Object.fromEntries(consumed),
        seenProofHashes: Array.from(seen),
      };
      this.replaceIndexAtomic(JSON.stringify(updatedIndex)); // (2) authoritative commit

      // (3) Append the audit line AFTER the index is committed. If this throws, the consume
      // is already durable (single-use holds) — re-throw so the caller DENIES. The proof is
      // "burned" (committed but denied): the accepted fail-closed tradeoff. Invariant now
      // holds: index(consumed) ⊇ audit-trail (audit may lag by the in-flight line, never lead).
      appendAuditLine(dir, jsonlPath, {
        ts: Date.now(),
        requestId,
        paramsDigest,
        outcome,
        proofHash,
        decision: "consumed",
      });

      return { ok: true };
    } finally {
      release();
    }
  }

  /**
   * RETAIN query: read the on-disk index and return ProofAuditRecord entries
   * whose requestId matches.
   *
   * READ-ONLY. Does NOT acquire a write lock — only reads the current snapshot.
   * This is consistent with the crash-consistency invariant: the index is the
   * authoritative record; any committed consume is durable before the lock releases.
   *
   * Never throws: returns [] on missing requestId, absent/malformed index, or
   * any I/O error. The caller must not need to distinguish "not found" from "error".
   *
   * Does NOT return the raw proof (L2 secret-at-rest): ProofAuditRecord is a
   * copy of ProofRecord fields without any raw proof material.
   */
  getAuditRecord(requestId: string): ProofAuditRecord[] {
    if (!requestId) return [];
    try {
      this.ensureDir();
      this.ensureIndex();
      if (!existsSync(this.indexPath)) return [];
      const raw = readFileSync(this.indexPath, "utf-8");
      const parsed: unknown = JSON.parse(raw);
      assertProofIndexShape(parsed); // shape-validate — throws on corrupt index
      const results: ProofAuditRecord[] = [];
      for (const record of Object.values(parsed.records)) {
        const r = record as ProofRecord;
        if (r.requestId === requestId) {
          results.push({
            requestId: r.requestId,
            paramsDigest: r.paramsDigest,
            outcome: r.outcome,
            consumedAt: r.consumedAt,
          });
        }
      }
      return results;
    } catch {
      // Read-only: never throw to caller (returns [] on any error)
      return [];
    }
  }
}

// ---------------------------------------------------------------------------
// Default durable ledger singleton (L2.6)
// ---------------------------------------------------------------------------

import { getAgentDir } from "../agents/config.js";

let _defaultLedger: ProofLedger | undefined;

/**
 * Returns the process-wide default FileProofLedger, lazily constructed on
 * first call. The ledger directory is co-located with auth.json under
 * getAgentDir() — same root, same ownership model.
 *
 * LAZY: never constructed at import time so tests that never call
 * decideCapabilityApproval do not create the agent-dir on disk.
 * Inject opts.ledger in tests to avoid touching the real agent dir.
 */
export function getDefaultProofLedger(): ProofLedger {
  if (!_defaultLedger) {
    _defaultLedger = new FileProofLedger(join(getAgentDir(), "proof-ledger"));
  }
  return _defaultLedger;
}

/**
 * Test-only. Re-points the default ledger singleton so tests get isolated
 * single-use state instead of the real agent dir.
 *
 * - `overridePath` given → a durable File ledger at that dir (e.g. a live drill
 *   that inspects the on-disk index + audit trail).
 * - NO argument → a FRESH in-memory ledger. This is the isolation default:
 *   tests get clean, non-persistent single-use state that never touches (or
 *   accumulates in) the real agent dir. A no-op reset that merely nulled the
 *   singleton would let getDefaultProofLedger() rebuild a File ledger over the
 *   SAME on-disk `getAgentDir()/proof-ledger` — bleeding consumed-proof state
 *   ACROSS test runs (the codex integration replay-guard tests caught exactly
 *   this: a proof consumed in an earlier run poisoned a later run's allow leg).
 *
 * Called by __resetProofRegistryForTest so existing test teardown keeps working.
 */
export function __resetDefaultProofLedgerForTest(overridePath?: string): void {
  _defaultLedger = overridePath ? new FileProofLedger(overridePath) : new InMemoryProofLedger();
}
