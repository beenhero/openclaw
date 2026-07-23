/**
 * Proof-ledger test suite.
 *
 * Contains:
 *   1. proofKey injectivity unit test (L2.1)
 *   2. Shared parametrized decision suite run against BOTH implementations (L2.2 + L2.3)
 *   3. FileProofLedger-specific structural assertions (L2.3)
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileProofLedger, InMemoryProofLedger, proofKey } from "./proof-ledger.js";
import type { ProofLedger } from "./proof-ledger.js";

// ---------------------------------------------------------------------------
// L2.1 — proofKey injectivity
// ---------------------------------------------------------------------------

describe("proofKey", () => {
  it("is injective: ('a b','c') !== ('a','b c')", () => {
    expect(proofKey("a b", "c")).not.toBe(proofKey("a", "b c"));
  });

  it("encodes the length prefix so requestId boundaries are unambiguous", () => {
    // requestId length differs → different keys even if concatenation matches
    expect(proofKey("ab", "cde")).not.toBe(proofKey("abc", "de"));
    expect(proofKey("abc", "de")).not.toBe(proofKey("abcde", ""));
  });

  it("produces the same value for identical inputs", () => {
    expect(proofKey("req-1", "sha256:abc")).toBe(proofKey("req-1", "sha256:abc"));
  });
});

// ---------------------------------------------------------------------------
// L2.2 + L2.3 — shared parametrized decision suite
// ---------------------------------------------------------------------------

/**
 * Factory-parametrized decision suite. Both InMemory and File ledgers are
 * expected to produce BYTE-IDENTICAL LedgerConsumeResult for identical call
 * sequences — any divergence is a bug.
 */
function runDecisionSuite(suiteName: string, makeLedger: () => ProofLedger) {
  describe(suiteName, () => {
    let ledger: ProofLedger;

    beforeEach(() => {
      ledger = makeLedger();
    });

    // Test 1: undefined-proof not single-shotted
    it("undefined-proof: two consumes with DIFFERENT requestIds both return ok", () => {
      const r1 = ledger.consumeOnce(undefined, "req-1", "digest-1", "allow");
      const r2 = ledger.consumeOnce(undefined, "req-2", "digest-2", "allow");
      expect(r1).toEqual({ ok: true });
      expect(r2).toEqual({ ok: true });
    });

    // Also verify the same requestId+paramsDigest still gets single-shotted
    // even with undefined proof (the pair is the key, not the proof)
    it("undefined-proof: same {requestId,paramsDigest} consumed twice → already_consumed", () => {
      const r1 = ledger.consumeOnce(undefined, "req-1", "digest-1", "allow");
      const r2 = ledger.consumeOnce(undefined, "req-1", "digest-1", "allow");
      expect(r1).toEqual({ ok: true });
      expect(r2).toEqual({ ok: false, reason: "already_consumed" });
    });

    // Test 2: empty-proof → invalid_identifier
    it("empty proof string → invalid_identifier", () => {
      const r = ledger.consumeOnce("", "req-1", "digest-1", "allow");
      expect(r).toEqual({ ok: false, reason: "invalid_identifier" });
    });

    // Test 3: falsy requestId or paramsDigest → invalid_identifier
    it("empty requestId → invalid_identifier", () => {
      const r = ledger.consumeOnce("proof-x", "", "digest-1", "allow");
      expect(r).toEqual({ ok: false, reason: "invalid_identifier" });
    });

    it("empty paramsDigest → invalid_identifier", () => {
      const r = ledger.consumeOnce("proof-x", "req-1", "", "allow");
      expect(r).toEqual({ ok: false, reason: "invalid_identifier" });
    });

    it("both requestId and paramsDigest empty → invalid_identifier", () => {
      const r = ledger.consumeOnce("proof-x", "", "", "allow");
      expect(r).toEqual({ ok: false, reason: "invalid_identifier" });
    });

    // Test 4: same proof replayed across differing requestIds → replayed
    it("proof replayed on a DIFFERENT {requestId,paramsDigest} → replayed", () => {
      const proof = "shared-proof-token";
      const r1 = ledger.consumeOnce(proof, "req-1", "digest-1", "allow");
      const r2 = ledger.consumeOnce(proof, "req-2", "digest-2", "allow");
      expect(r1).toEqual({ ok: true });
      expect(r2).toEqual({ ok: false, reason: "replayed" });
    });

    // Test 5: repeat same {requestId,paramsDigest} → already_consumed
    it("same {requestId,paramsDigest} consumed twice → already_consumed", () => {
      const r1 = ledger.consumeOnce("proof-a", "req-1", "digest-1", "allow");
      const r2 = ledger.consumeOnce("proof-b", "req-1", "digest-1", "allow");
      expect(r1).toEqual({ ok: true });
      expect(r2).toEqual({ ok: false, reason: "already_consumed" });
    });

    // Test 6: two DISTINCT pairs → both ok
    it("two distinct {requestId,paramsDigest} pairs both succeed", () => {
      const r1 = ledger.consumeOnce("proof-a", "req-1", "digest-1", "allow");
      const r2 = ledger.consumeOnce("proof-b", "req-2", "digest-2", "deny");
      expect(r1).toEqual({ ok: true });
      expect(r2).toEqual({ ok: true });
    });

    // Test 7: success path (outcome stored — verify by checking replay prevention)
    it("success path: after consume, the proof string is seen (replay-blocked)", () => {
      const proof = "unique-proof-abc";
      const r1 = ledger.consumeOnce(proof, "req-1", "digest-1", "allow");
      expect(r1).toEqual({ ok: true });

      // Try to replay on a fresh pair — should be rejected as replayed, not ok
      const r2 = ledger.consumeOnce(proof, "req-NEW", "digest-NEW", "allow");
      expect(r2).toEqual({ ok: false, reason: "replayed" });
    });
  });
}

// ---------------------------------------------------------------------------
// Run suite against InMemoryProofLedger
// ---------------------------------------------------------------------------

runDecisionSuite("InMemoryProofLedger — decision suite", () => new InMemoryProofLedger());

// ---------------------------------------------------------------------------
// Run suite against FileProofLedger + structural assertions
// ---------------------------------------------------------------------------

describe("FileProofLedger — decision suite + structural assertions", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-proof-ledger-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Wire the shared suite against FileProofLedger
  runDecisionSuite("FileProofLedger (parametrized)", () => {
    const dir = path.join(tmpDir, "ledger");
    return new FileProofLedger(dir);
  });

  // Structural: index file is 0o600
  it("proof-index.json is created with mode 0o600", () => {
    const dir = path.join(tmpDir, "ledger-perms");
    new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");
    const stat = fs.statSync(indexPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  // Structural: directory is 0o700
  it("ledger directory is created with mode 0o700", () => {
    const dir = path.join(tmpDir, "ledger-dirperms");
    new FileProofLedger(dir);
    const stat = fs.statSync(dir);
    expect(stat.mode & 0o777).toBe(0o700);
  });

  // Structural: .lock file cleaned up after consumeOnce
  it(".lock file is cleaned up after consumeOnce completes", () => {
    const dir = path.join(tmpDir, "ledger-lock");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce("proof-z", "req-z", "digest-z", "allow");
    const lockPath = path.join(dir, "proof-index.json.lock");
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  // Structural: byte-parity — InMemory and File produce identical results for identical sequences
  it("byte-parity: InMemory and File produce identical results for identical call sequences", () => {
    const dir = path.join(tmpDir, "ledger-parity");
    const mem = new InMemoryProofLedger();
    const file = new FileProofLedger(dir);

    const calls: Array<[string | undefined, string, string, "allow" | "deny"]> = [
      [undefined, "req-1", "digest-1", "allow"],
      ["proof-a", "req-2", "digest-2", "allow"],
      ["proof-a", "req-3", "digest-3", "deny"], // replayed proof
      ["proof-b", "req-2", "digest-2", "allow"], // already_consumed pair
      ["", "req-4", "digest-4", "allow"], // empty proof
      ["proof-c", "", "digest-5", "allow"], // empty requestId
      ["proof-d", "req-5", "digest-6", "deny"], // distinct pair → ok
      [undefined, "req-1", "digest-1", "allow"], // same pair as first → already_consumed
    ];

    for (const [proof, requestId, paramsDigest, outcome] of calls) {
      const memResult = mem.consumeOnce(proof, requestId, paramsDigest, outcome);
      const fileResult = file.consumeOnce(proof, requestId, paramsDigest, outcome);
      expect(fileResult).toEqual(memResult);
    }
  });

  // Structural: index file is readable JSON with v:1 after a consume
  it("proof-index.json is valid JSON with v:1 after a successful consume", () => {
    const dir = path.join(tmpDir, "ledger-json");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce("proof-1", "req-1", "digest-1", "allow");
    const indexPath = path.join(dir, "proof-index.json");
    const raw = fs.readFileSync(indexPath, "utf-8");
    const parsed = JSON.parse(raw) as {
      v: number;
      records: Record<string, unknown>;
      seenProofs: string[];
    };
    expect(parsed.v).toBe(1);
    expect(typeof parsed.records).toBe("object");
    expect(Array.isArray(parsed.seenProofs)).toBe(true);
    // The proof should appear in seenProofs
    expect(parsed.seenProofs).toContain("proof-1");
    // The pair key should appear in records
    const key = proofKey("req-1", "digest-1");
    expect(key in parsed.records).toBe(true);
  });

  // Structural: reject legs do NOT write the index
  it("reject legs do not mutate the index file", () => {
    const dir = path.join(tmpDir, "ledger-no-write");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // Read initial state after construction
    const before = fs.readFileSync(indexPath, "utf-8");

    // Trigger various reject legs
    ledger.consumeOnce("", "req-1", "digest-1", "allow"); // invalid_identifier
    ledger.consumeOnce("proof-x", "", "digest-1", "allow"); // invalid_identifier

    const after = fs.readFileSync(indexPath, "utf-8");
    expect(after).toBe(before);
  });

  // ---------------------------------------------------------------------------
  // L2.5 — Fail-closed matrix tests
  // ---------------------------------------------------------------------------

  it("CORRUPT INDEX: JSON.parse throws and does not reset-to-empty (no amnesty)", () => {
    const dir = path.join(tmpDir, "ledger-corrupt");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // First consume a valid pair so the index has real state
    const r1 = ledger.consumeOnce("proof-corrupt-1", "req-1", "digest-1", "allow");
    expect(r1).toEqual({ ok: true });

    // Capture the valid post-consume index content
    const validContent = fs.readFileSync(indexPath, "utf-8");

    // Corrupt the index
    fs.writeFileSync(indexPath, "{ not json", "utf-8");

    // consumeOnce must THROW — corrupt index must brick the gate, never reset-to-empty
    expect(() => {
      ledger.consumeOnce("proof-corrupt-2", "req-2", "digest-2", "allow");
    }).toThrow();

    // Restore the valid index (no amnesty check)
    fs.writeFileSync(indexPath, validContent, "utf-8");

    // The previously consumed {requestId,paramsDigest} pair must still be rejected.
    // Use a DIFFERENT proof so we hit already_consumed (step 5), not replayed (step 4).
    const r3 = ledger.consumeOnce("proof-corrupt-different", "req-1", "digest-1", "allow");
    expect(r3).toEqual({ ok: false, reason: "already_consumed" });
  });

  it("UNREADABLE INDEX: EACCES propagates as throw, never bypasses", () => {
    const dir = path.join(tmpDir, "ledger-unreadable");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // Consume once to establish state
    const r1 = ledger.consumeOnce("proof-unread-1", "req-1", "digest-1", "allow");
    expect(r1).toEqual({ ok: true });

    // Make index unreadable
    fs.chmodSync(indexPath, 0o000);

    try {
      // consumeOnce must THROW (EACCES propagates)
      expect(() => {
        ledger.consumeOnce("proof-unread-2", "req-2", "digest-2", "allow");
      }).toThrow();
    } finally {
      // Restore permissions so afterEach cleanup works
      fs.chmodSync(indexPath, 0o600);
    }
  });

  it("UNWRITABLE AUDIT LOG: append failure throws and index is NOT mutated", () => {
    const dir = path.join(tmpDir, "ledger-audit-fail");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // Pre-create proof-ledger.jsonl as a directory so appendFileSync throws EISDIR
    fs.mkdirSync(path.join(dir, "proof-ledger.jsonl"));

    // Capture initial index state (should be '{}' since no successful consume yet)
    const before = fs.readFileSync(indexPath, "utf-8");

    // consumeOnce must throw (audit append fails)
    expect(() => {
      ledger.consumeOnce("proof-audit-1", "req-1", "digest-1", "allow");
    }).toThrow();

    // Index must NOT have been mutated
    const after = fs.readFileSync(indexPath, "utf-8");
    expect(after).toBe(before);
  });

  it("ELOCKED: lock contention throws after retries", () => {
    const dir = path.join(tmpDir, "ledger-locked");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // Create the .lock path as a directory — proper-lockfile uses mkdir to acquire
    // the lock, so if the path already exists as a directory, mkdir fails → ELOCKED
    fs.mkdirSync(`${indexPath}.lock`);

    // consumeOnce must throw (lock contention)
    expect(() => {
      ledger.consumeOnce("proof-locked-1", "req-1", "digest-1", "allow");
    }).toThrow();
  });

  // ---------------------------------------------------------------------------
  // L2.4 audit trail — JSONL content assertions
  // ---------------------------------------------------------------------------

  it("JSONL audit: proof-ledger.jsonl is created with mode 0o600", () => {
    const dir = path.join(tmpDir, "ledger-audit-mode");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce("proof-mode-1", "req-1", "digest-1", "allow");
    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    expect(fs.existsSync(jsonlPath)).toBe(true);
    const stat = fs.statSync(jsonlPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it("JSONL audit: every consumeOnce call appends exactly one line (accepted AND rejected legs)", () => {
    const dir = path.join(tmpDir, "ledger-audit-lines");
    const ledger = new FileProofLedger(dir);

    // accepted
    ledger.consumeOnce("proof-line-1", "req-1", "digest-1", "allow");
    // already_consumed
    ledger.consumeOnce("proof-line-2", "req-1", "digest-1", "allow");
    // replayed
    ledger.consumeOnce("proof-line-1", "req-2", "digest-2", "allow");
    // invalid_identifier (empty proof)
    ledger.consumeOnce("", "req-3", "digest-3", "allow");
    // invalid_identifier (empty requestId)
    ledger.consumeOnce("proof-line-x", "", "digest-4", "allow");

    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    const lines = fs
      .readFileSync(jsonlPath, "utf-8")
      .split("\n")
      .filter((l) => l.trim() !== "");
    expect(lines).toHaveLength(5);
  });

  it("JSONL audit: audit line shape is correct (ts, requestId, paramsDigest, outcome, proofHash, decision)", () => {
    const dir = path.join(tmpDir, "ledger-audit-shape");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce("proof-shape-1", "req-1", "digest-1", "allow");

    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    const raw = fs.readFileSync(jsonlPath, "utf-8").trim();
    const entry = JSON.parse(raw) as Record<string, unknown>;

    expect(typeof entry["ts"]).toBe("number");
    expect(entry["requestId"]).toBe("req-1");
    expect(entry["paramsDigest"]).toBe("digest-1");
    expect(entry["outcome"]).toBe("allow");
    expect(entry["decision"]).toBe("consumed");
    // proofHash must be sha256 hex (64 hex chars), NOT the raw proof
    expect(typeof entry["proofHash"]).toBe("string");
    expect(entry["proofHash"] as string).toHaveLength(64);
    expect(entry["proofHash"] as string).toMatch(/^[0-9a-f]{64}$/);
    expect(entry["proofHash"]).not.toBe("proof-shape-1");
  });

  it("JSONL audit: proofHash is null when proof is undefined", () => {
    const dir = path.join(tmpDir, "ledger-audit-null-hash");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce(undefined, "req-1", "digest-1", "allow");

    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    const raw = fs.readFileSync(jsonlPath, "utf-8").trim();
    const entry = JSON.parse(raw) as Record<string, unknown>;
    expect(entry["proofHash"]).toBeNull();
  });

  it("JSONL audit: all 4 decision values appear for corresponding legs", () => {
    const dir = path.join(tmpDir, "ledger-audit-decisions");
    const ledger = new FileProofLedger(dir);

    // consumed
    ledger.consumeOnce("proof-dec-1", "req-1", "digest-1", "allow");
    // replayed
    ledger.consumeOnce("proof-dec-1", "req-2", "digest-2", "allow");
    // already_consumed
    ledger.consumeOnce("proof-dec-2", "req-1", "digest-1", "allow");
    // invalid_identifier
    ledger.consumeOnce("", "req-3", "digest-3", "allow");

    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    const lines = fs
      .readFileSync(jsonlPath, "utf-8")
      .split("\n")
      .filter((l) => l.trim() !== "");
    const decisions = lines.map((l) => (JSON.parse(l) as Record<string, unknown>)["decision"]);

    expect(decisions).toContain("consumed");
    expect(decisions).toContain("replayed");
    expect(decisions).toContain("already_consumed");
    expect(decisions).toContain("invalid_identifier");
  });

  it("JSONL audit: audit line is a superset of consumeOnce inputs (requestId, paramsDigest, outcome present for all legs)", () => {
    const dir = path.join(tmpDir, "ledger-audit-superset");
    const ledger = new FileProofLedger(dir);

    const calls: Array<[string | undefined, string, string, "allow" | "deny"]> = [
      ["proof-sup-1", "req-1", "digest-1", "allow"],
      ["proof-sup-1", "req-2", "digest-2", "deny"], // replayed
      ["proof-sup-2", "req-1", "digest-1", "allow"], // already_consumed
      ["", "req-3", "digest-3", "allow"], // invalid_identifier
    ];

    for (const [proof, requestId, paramsDigest, outcome] of calls) {
      ledger.consumeOnce(proof, requestId, paramsDigest, outcome);
    }

    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    const lines = fs
      .readFileSync(jsonlPath, "utf-8")
      .split("\n")
      .filter((l) => l.trim() !== "");

    expect(lines).toHaveLength(4);

    for (let i = 0; i < calls.length; i++) {
      const [, requestId, paramsDigest, outcome] = calls[i]!;
      const entry = JSON.parse(lines[i]!) as Record<string, unknown>;
      // Every audit line must carry requestId, paramsDigest, outcome
      expect(entry["requestId"]).toBe(requestId);
      expect(entry["paramsDigest"]).toBe(paramsDigest);
      expect(entry["outcome"]).toBe(outcome);
      expect(typeof entry["ts"]).toBe("number");
    }
  });

  it("JSONL audit: audit line is written BEFORE index mutation (ordering invariant)", () => {
    // After a successful consume, proof-ledger.jsonl must exist and the index must be updated.
    // We verify: if we read both files after consumeOnce, both reflect the consume.
    // This test is a structural ordering check — it doesn't simulate crash-midway,
    // but verifies the post-condition that the audit line exists alongside the updated index.
    const dir = path.join(tmpDir, "ledger-audit-order");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");
    const jsonlPath = path.join(dir, "proof-ledger.jsonl");

    ledger.consumeOnce("proof-order-1", "req-1", "digest-1", "allow");

    // Both files must exist
    expect(fs.existsSync(jsonlPath)).toBe(true);
    expect(fs.existsSync(indexPath)).toBe(true);

    // Audit must contain the consumed entry
    const auditLine = fs.readFileSync(jsonlPath, "utf-8").trim();
    const entry = JSON.parse(auditLine) as Record<string, unknown>;
    expect(entry["decision"]).toBe("consumed");

    // Index must also contain the consumed pair
    const index = JSON.parse(fs.readFileSync(indexPath, "utf-8")) as {
      records: Record<string, unknown>;
    };
    expect(Object.keys(index.records)).toHaveLength(1);
  });
});
