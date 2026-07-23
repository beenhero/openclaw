/**
 * Proof-ledger test suite.
 *
 * Contains:
 *   1. proofKey injectivity unit test (L2.1)
 *   2. Shared parametrized decision suite run against BOTH implementations (L2.2 + L2.3)
 *   3. FileProofLedger-specific structural assertions (L2.3)
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileProofLedger, InMemoryProofLedger, proofKey } from "./proof-ledger.js";
import type { ProofLedger } from "./proof-ledger.js";

const sha256hex = (s: string): string => createHash("sha256").update(s).digest("hex");

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
      seenProofHashes: string[];
    };
    expect(parsed.v).toBe(1);
    expect(typeof parsed.records).toBe("object");
    expect(Array.isArray(parsed.seenProofHashes)).toBe(true);
    // Defect 3: the HASH — not the raw proof — appears at rest.
    expect(parsed.seenProofHashes).toContain(sha256hex("proof-1"));
    // The pair key should appear in records
    const key = proofKey("req-1", "digest-1");
    expect(key in parsed.records).toBe(true);
  });

  // Defect 3: raw reusable-secret proofs must NEVER be persisted plaintext at rest.
  it("SECRET-AT-REST: raw proof string never appears anywhere in proof-index.json", () => {
    const dir = path.join(tmpDir, "ledger-no-raw-proof");
    const ledger = new FileProofLedger(dir);
    const rawProof = "S3cr3t-proof-do-not-persist";
    const r = ledger.consumeOnce(rawProof, "req-1", "digest-1", "allow");
    expect(r).toEqual({ ok: true });

    const indexPath = path.join(dir, "proof-index.json");
    const onDisk = fs.readFileSync(indexPath, "utf-8");
    // The raw proof must NOT appear anywhere in the persisted index (neither in
    // seenProofHashes nor duplicated into records[key].proof).
    expect(onDisk).not.toContain(rawProof);
    // But its hash MUST, so replay membership still works across restart.
    expect(onDisk).toContain(sha256hex(rawProof));

    // Sanity: the record must carry NO `proof` field at all.
    const parsed = JSON.parse(onDisk) as { records: Record<string, Record<string, unknown>> };
    const key = proofKey("req-1", "digest-1");
    expect(parsed.records[key]).toBeDefined();
    expect("proof" in (parsed.records[key] as object)).toBe(false);

    // And replay of the raw proof on a NEW instance is still blocked (hash membership).
    const ledger2 = new FileProofLedger(dir);
    const replay = ledger2.consumeOnce(rawProof, "req-NEW", "digest-NEW", "allow");
    expect(replay).toEqual({ ok: false, reason: "replayed" });
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

  it("CORRUPT/MALFORMED INDEX: every non-throwing amnesty shape THROWS (no reset-to-empty)", () => {
    const dir = path.join(tmpDir, "ledger-corrupt");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");

    // (a) Consume a real pair so the index carries genuine prior state.
    const r1 = ledger.consumeOnce("proof-corrupt-1", "req-1", "digest-1", "allow");
    expect(r1).toEqual({ ok: true });

    // Capture the valid post-consume index — restored ONLY for the final durability leg.
    const validContent = fs.readFileSync(indexPath, "utf-8");

    // (b) Every valid-JSON-but-wrong-shape input (the amnesty class) — plus parse-garbage
    //     and a bare `{}` overwritten onto populated state — must make consumeOnce THROW.
    //     We overwrite the on-disk index and assert the throw WITHOUT restoring good content,
    //     so the test genuinely proves "malformed index bricks the gate, never amnesties".
    const amnestyInputs = [
      "{ not json", // parse-garbage (SyntaxError)
      '{"v":1}', // missing records + seenProofHashes
      "[]", // array, not object
      "123", // scalar number
      "true", // scalar boolean
      '"x"', // scalar string
      '{"v":1,"records":[],"seenProofHashes":[]}', // records-as-array
      '{"v":2,"records":{},"seenProofHashes":[]}', // wrong version
      '{"v":1,"records":{},"seenProofHashes":{}}', // seenProofHashes-as-object
      "{}", // bare {} overwritten onto populated state (indistinguishable-from-fresh amnesty)
      "", // empty string (JSON.parse throws anyway)
    ];

    for (const bad of amnestyInputs) {
      fs.writeFileSync(indexPath, bad, "utf-8");
      // A DIFFERENT pair each time so a hypothetical amnesty would return {ok:true}
      // (i.e. the assertion is not accidentally satisfied by already_consumed).
      expect(
        () => ledger.consumeOnce("proof-fresh", "req-fresh", "digest-fresh", "allow"),
        `malformed index ${JSON.stringify(bad)} must throw, never reset-to-empty`,
      ).toThrow();
      // NOTE: no restore between iterations — each bad shape is asserted on its own.
    }

    // (c) Durability across instances: restore a VALID index that still carries the
    //     consumed key, open a BRAND-NEW FileProofLedger against the on-disk file, and
    //     assert the prior pair is STILL rejected already_consumed (state survived).
    fs.writeFileSync(indexPath, validContent, "utf-8");
    const freshInstance = new FileProofLedger(dir);
    const r3 = freshInstance.consumeOnce("proof-corrupt-different", "req-1", "digest-1", "allow");
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

  // INDEX-FIRST ORDERING PROOF: this is the definitive proof of Defect 2's ordering
  // invariant. A committed pair-1 (good audit) and a burned pair-2 (index committed but
  // audit failed + threw) can only co-exist if the index write precedes the audit append.
  // If ordering were audit-first, pair-2's index entry would not exist (it would be written
  // after the audit, which threw) — so the subsequent retry would succeed (not already_consumed).
  // The fact that pair-2 IS burned (already_consumed on retry) proves index-first is enforced.
  it("UNWRITABLE AUDIT LOG (index-first): a successful pair survives; the audit-failed pair is BURNED (throws + fail-closed)", () => {
    const dir = path.join(tmpDir, "ledger-audit-fail");
    const ledger = new FileProofLedger(dir);

    // (a) Consume pair-1 successfully → non-trivial index (NOT the empty seed).
    const r1 = ledger.consumeOnce("proof-audit-1", "req-1", "digest-1", "allow");
    expect(r1).toEqual({ ok: true });

    // (b) Now make the JSONL audit append fail: remove the file and put a directory
    //     in its place so appendFileSync throws EISDIR on the NEXT consume.
    const jsonlPath = path.join(dir, "proof-ledger.jsonl");
    // pair-1's audit line must exist before we destroy the file
    expect(fs.existsSync(jsonlPath)).toBe(true);
    const pair1AuditLine = fs.readFileSync(jsonlPath, "utf-8").trim();
    expect((JSON.parse(pair1AuditLine) as Record<string, unknown>)["requestId"]).toBe("req-1");
    fs.rmSync(jsonlPath, { force: true });
    fs.mkdirSync(jsonlPath);

    // (c) Consume pair-2 → index is committed FIRST, then the audit append throws.
    //     Under index-first ordering the consume is already durable, so the call must
    //     throw (fail-closed: caller DENIES) even though the index was updated.
    expect(() => {
      ledger.consumeOnce("proof-audit-2", "req-2", "digest-2", "allow");
    }).toThrow();

    // Remove the directory-blocker so subsequent reads/writes work for the assertions.
    fs.rmSync(jsonlPath, { recursive: true, force: true });

    // (d) pair-1 (the earlier good consume) is still single-shotted — prior state intact.
    const r1again = ledger.consumeOnce("proof-audit-1b", "req-1", "digest-1", "allow");
    expect(r1again).toEqual({ ok: false, reason: "already_consumed" });

    // (e) pair-2 is BURNED: the index committed before the audit failed, so a retry of
    //     the SAME pair is already_consumed. This proves index-first + throw-on-audit-fail
    //     is genuinely fail-closed (the proof is spent, never replayable).
    // pair-2 has NO audit line (the JSONL was blocked when it ran) — only in the index.
    const r2retry = ledger.consumeOnce("proof-audit-2b", "req-2", "digest-2", "allow");
    expect(r2retry).toEqual({ ok: false, reason: "already_consumed" });

    // (f) Explicit audit-line split: pair-2 has NO audit line (the JSONL write was
    //     blocked), but the index has pair-2 (written first, before the blocked audit).
    //     The ordering proof is that index ⊇ audit: pair-2 is index-only (burned).
    // After the dir-blocker is removed, a new consume on pair-3 succeeds to confirm the
    // ledger is live again, and req-2 must NOT appear in any audit line.
    const r3 = ledger.consumeOnce("proof-audit-3", "req-3", "digest-3", "allow");
    expect(r3).toEqual({ ok: true });
    const recoveredLines = fs
      .readFileSync(jsonlPath, "utf-8")
      .split("\n")
      .filter((l) => l.trim() !== "");
    const recoveredEntries = recoveredLines.map((l) => JSON.parse(l) as Record<string, unknown>);
    // pair-2's INITIAL consume audit write was blocked (JSONL was a directory).
    // Its audit line with decision="consumed" must NOT exist — pair-2 is index-only/burned.
    // (The already_consumed retry in step (e) may legitimately write an "already_consumed"
    //  line for req-2 after the blocker is removed — that is expected and is fine.)
    const pair2ConsumedLine = recoveredEntries.find(
      (e) => e["requestId"] === "req-2" && e["decision"] === "consumed",
    );
    expect(pair2ConsumedLine).toBeUndefined();
    // pair-3 (req-3) MUST appear as consumed — recovery is complete.
    const pair3ConsumedLine = recoveredEntries.find(
      (e) => e["requestId"] === "req-3" && e["decision"] === "consumed",
    );
    expect(pair3ConsumedLine).toBeDefined();
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

  it("JSONL audit: after a successful consume BOTH the audit line and the index reflect it (index-first post-condition)", () => {
    // Under index-first ordering the index is written durably FIRST, then the audit line
    // is appended. This test verifies the success post-condition: both files reflect the consume.
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

  // DEEP INDEX SHAPE VALIDATION: defense-in-depth — a malformed records value or a
  // non-string seenProofHashes element must throw (not silently amnesty).
  it("MALFORMED INDEX (deep): consumeOnce throws if records entry is not a well-formed object", () => {
    const dir = path.join(tmpDir, "ledger-malformed-record");
    const ledger = new FileProofLedger(dir);
    // Prime the ledger so the index file exists
    ledger.consumeOnce("proof-m1", "req-m1", "digest-m1", "allow");
    const indexPath = path.join(dir, "proof-index.json");

    // Write an index whose records value is a primitive (not a well-formed record object)
    const corrupt = JSON.stringify({ v: 1, records: { somekey: 123 }, seenProofHashes: [] });
    fs.writeFileSync(indexPath, corrupt, "utf-8");

    const reloaded = new FileProofLedger(dir);
    expect(() => {
      reloaded.consumeOnce("proof-m2", "req-m2", "digest-m2", "allow");
    }).toThrow("proof-index: malformed/corrupt index — refusing to reset-to-empty");
  });

  it("MALFORMED INDEX (deep): consumeOnce throws if seenProofHashes contains a non-string", () => {
    const dir = path.join(tmpDir, "ledger-malformed-hash");
    const ledger = new FileProofLedger(dir);
    ledger.consumeOnce("proof-h1", "req-h1", "digest-h1", "allow");
    const indexPath = path.join(dir, "proof-index.json");

    // Write an index with a non-string element in seenProofHashes
    const corrupt = JSON.stringify({ v: 1, records: {}, seenProofHashes: [123] });
    fs.writeFileSync(indexPath, corrupt, "utf-8");

    const reloaded = new FileProofLedger(dir);
    expect(() => {
      reloaded.consumeOnce("proof-h2", "req-h2", "digest-h2", "allow");
    }).toThrow("proof-index: malformed/corrupt index — refusing to reset-to-empty");
  });

  it("MALFORMED INDEX (deep): a well-formed populated index does NOT throw (no false positive)", () => {
    // Regression guard: deep validation must not reject a valid populated index.
    const dir = path.join(tmpDir, "ledger-valid-populated");
    const ledger = new FileProofLedger(dir);
    // Consume once to populate
    const r1 = ledger.consumeOnce("proof-vp1", "req-vp1", "digest-vp1", "allow");
    expect(r1).toEqual({ ok: true });

    // Fresh instance reads the populated index — must NOT throw
    const reloaded = new FileProofLedger(dir);
    const r2 = reloaded.consumeOnce("proof-vp2", "req-vp1", "digest-vp1", "allow");
    // req-vp1+digest-vp1 was consumed → already_consumed (not a throw)
    expect(r2).toEqual({ ok: false, reason: "already_consumed" });
  });

  // Durability: a committed index (persisted during a real successful consume) survives
  // audit-trail loss and is honoured by a fresh instance. This proves the index is the
  // authoritative single-use gate — not the audit JSONL. It does NOT prove index-first
  // ordering; that proof is the "UNWRITABLE AUDIT LOG" test above (a committed pair-1 +
  // a burned pair-2 can only arise if the index write precedes the audit append).
  it("a committed index survives a lost audit trail on a fresh instance", () => {
    const dir = path.join(tmpDir, "ledger-crash");
    const ledger = new FileProofLedger(dir);
    const indexPath = path.join(dir, "proof-index.json");
    const jsonlPath = path.join(dir, "proof-ledger.jsonl");

    // Consume a real pair → index committed durably.
    const r1 = ledger.consumeOnce("proof-crash-1", "req-1", "digest-1", "allow");
    expect(r1).toEqual({ ok: true });

    // Simulate a crash that lost the audit trail but kept the committed index
    // (the "audit lags by at most the in-flight line, never leads" direction).
    fs.rmSync(jsonlPath, { force: true });
    expect(fs.existsSync(indexPath)).toBe(true);

    // A brand-new instance (fresh process) reads ONLY the on-disk index.
    const restarted = new FileProofLedger(dir);

    // Single-use MUST hold: the pair is rejected already_consumed (different proof so we
    // land on step 5, not the replay path).
    const r2 = restarted.consumeOnce("proof-crash-different", "req-1", "digest-1", "allow");
    expect(r2).toEqual({ ok: false, reason: "already_consumed" });

    // The original proof is also still replay-blocked from the committed seenProofHashes.
    const r3 = restarted.consumeOnce("proof-crash-1", "req-2", "digest-2", "allow");
    expect(r3).toEqual({ ok: false, reason: "replayed" });
  });
});
