// Effect-set canonicalization primitives — L3.3 (sortEffects + dedupeByKind) and
// L3.4 (digestForEffects behavior-preservation golden, branch A).
import { describe, expect, it } from "vitest";
import { computeParamsDigest } from "./capability-approval.js";
import { dedupeByKind, digestForEffects, sortEffects } from "./effect-classifier.js";
import type { EffectDescriptor } from "./host-hooks.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EXEC_EFFECT: EffectDescriptor = {
  kind: "process.exec",
  command: "/bin/ls",
  cwd: "/tmp",
};

const EGRESS_EFFECT: EffectDescriptor = {
  kind: "net.egress",
  hosts: ["example.com"],
  ports: [443],
};

// ---------------------------------------------------------------------------
// L3.3 — sortEffects
// ---------------------------------------------------------------------------

describe("sortEffects", () => {
  it("[net.egress, process.exec] and [process.exec, net.egress] sort to identical order", () => {
    const order1 = sortEffects([EGRESS_EFFECT, EXEC_EFFECT]);
    const order2 = sortEffects([EXEC_EFFECT, EGRESS_EFFECT]);

    // Both must produce the same result (net.egress < process.exec by localeCompare).
    expect(order1).toEqual(order2);
    // net.egress sorts before process.exec ('n' < 'p').
    expect(order1[0]?.kind).toBe("net.egress");
    expect(order1[1]?.kind).toBe("process.exec");
  });

  it("sort is stable across multiple insertion orders (three effects)", () => {
    const a: EffectDescriptor = { kind: "zzz.last" };
    const b: EffectDescriptor = { kind: "aaa.first" };
    const c: EffectDescriptor = { kind: "mmm.middle" };

    const r1 = sortEffects([a, b, c]);
    const r2 = sortEffects([c, a, b]);
    const r3 = sortEffects([b, c, a]);

    expect(r1).toEqual(r2);
    expect(r2).toEqual(r3);
    expect(r1[0]?.kind).toBe("aaa.first");
    expect(r1[1]?.kind).toBe("mmm.middle");
    expect(r1[2]?.kind).toBe("zzz.last");
  });

  it("single-element array is returned sorted (trivially)", () => {
    const result = sortEffects([EXEC_EFFECT]);
    expect(result).toEqual([EXEC_EFFECT]);
  });

  it("does not mutate the input array", () => {
    const input = [EXEC_EFFECT, EGRESS_EFFECT];
    const originalFirst = input[0];
    sortEffects(input);
    // Input order must be unchanged.
    expect(input[0]).toBe(originalFirst);
  });
});

// ---------------------------------------------------------------------------
// L3.3 — dedupeByKind
// ---------------------------------------------------------------------------

describe("dedupeByKind", () => {
  it("returns the array unchanged when all kinds are unique", () => {
    const effects = [EXEC_EFFECT, EGRESS_EFFECT];
    const result = dedupeByKind(effects);
    expect(result).toEqual(effects);
  });

  it("THROWS on a duplicate kind — invalid input, classifier bug", () => {
    const duplicate: EffectDescriptor = { kind: "process.exec", command: "/bin/cat", cwd: "/tmp" };
    expect(() => dedupeByKind([EXEC_EFFECT, duplicate])).toThrow(/duplicate effect kind/);
    expect(() => dedupeByKind([EXEC_EFFECT, duplicate])).toThrow(/"process\.exec"/);
  });

  it("THROWS on duplicate net.egress kind", () => {
    const egress2: EffectDescriptor = { kind: "net.egress", hosts: ["other.com"] };
    expect(() => dedupeByKind([EGRESS_EFFECT, egress2])).toThrow(/duplicate effect kind/);
  });

  it("single-element array passes validation (no duplicates possible)", () => {
    expect(() => dedupeByKind([EXEC_EFFECT])).not.toThrow();
    expect(dedupeByKind([EXEC_EFFECT])).toEqual([EXEC_EFFECT]);
  });

  it("empty array passes validation", () => {
    expect(() => dedupeByKind([])).not.toThrow();
    expect(dedupeByKind([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// L3.4 — digestForEffects behavior-preservation golden (branch A)
// ---------------------------------------------------------------------------

describe("digestForEffects", () => {
  // ---------------------------------------------------------------------------
  // GOLDEN TEST — frozen hex for the single-effect process.exec case.
  //
  // This hex is the ACTUAL current output of computeParamsDigest for the input
  // { kind: 'process.exec', command: '/bin/ls', cwd: '/tmp' }.
  //
  // It is frozen here to prevent a future refactor from silently switching
  // digestForEffects to the array-digest path (branch B), which would produce
  // a DIFFERENT hex and invalidate all parked process.exec proof-ledger keys.
  //
  // If this test fails, it means either:
  //   (a) stableStringify/fingerprintJson changed — audit carefully before
  //       updating (all cached/parked approvals will be invalidated on deploy), OR
  //   (b) digestForEffects was accidentally changed to the array path —
  //       revert and re-read the branch-A comment in effect-classifier.ts.
  //
  // FROZEN VALUE: sha256:a67944b5693d9183e0504f89d4ad43f0b9128adee162a1d63ca00c57c98a7fed
  // ---------------------------------------------------------------------------
  const GOLDEN_EXEC_HEX = "sha256:a67944b5693d9183e0504f89d4ad43f0b9128adee162a1d63ca00c57c98a7fed";

  it("L3.4 GOLDEN: digestForEffects([execEffect]) === frozen hex === computeParamsDigest(execEffect)", () => {
    const effect: EffectDescriptor = { kind: "process.exec", command: "/bin/ls", cwd: "/tmp" };

    // Assert against the FROZEN literal — the anti-regression lock.
    expect(digestForEffects([effect])).toBe(GOLDEN_EXEC_HEX);

    // Also assert byte-identity with today's computeParamsDigest(effect).
    // If these ever diverge, digestForEffects has drifted off branch A.
    expect(digestForEffects([effect])).toBe(computeParamsDigest(effect));
  });

  it("branch A: single-effect digest is byte-identical to computeParamsDigest(effect) for net.egress too", () => {
    const effect: EffectDescriptor = { kind: "net.egress", hosts: ["x.com"], ports: [443] };
    expect(digestForEffects([effect])).toBe(computeParamsDigest(effect));
  });

  it("branch B: multi-effect digest is order-independent (sortEffects applied before hashing)", () => {
    const order1 = digestForEffects([EGRESS_EFFECT, EXEC_EFFECT]);
    const order2 = digestForEffects([EXEC_EFFECT, EGRESS_EFFECT]);
    expect(order1).toBe(order2);
  });

  it("branch B: multi-effect digest differs from both single-effect digests", () => {
    const multiDigest = digestForEffects([EXEC_EFFECT, EGRESS_EFFECT]);
    const execOnly = digestForEffects([EXEC_EFFECT]);
    const egressOnly = digestForEffects([EGRESS_EFFECT]);

    expect(multiDigest).not.toBe(execOnly);
    expect(multiDigest).not.toBe(egressOnly);
  });

  it("branch B: multi-effect digest equals computeParamsDigest(sortEffects(effects))", () => {
    const effects = [EXEC_EFFECT, EGRESS_EFFECT];
    const expected = computeParamsDigest(sortEffects(effects));
    expect(digestForEffects(effects)).toBe(expected);
  });

  it("adding a second effect to a previously-single-effect tool produces a DIFFERENT digest (intentional fail-closed re-approval)", () => {
    // This documents the branch-flip behavior: a tool that previously had
    // only [process.exec] now also has [net.egress]. The digest changes.
    // This is NOT a bug — it is the correct fail-closed behavior.
    const before = digestForEffects([EXEC_EFFECT]);
    const after = digestForEffects([EXEC_EFFECT, EGRESS_EFFECT]);
    expect(before).not.toBe(after);
  });
});
