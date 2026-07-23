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
});
