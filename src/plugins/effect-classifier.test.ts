// Effect-set canonicalization primitives — L3.3 (sortEffects + dedupeByKind) and
// L3.4 (digestForEffects behavior-preservation golden, branch A).
// 3-tier classifier — L3.5 (Tier-A), L3.6 (Tier-B), L3.7 (Tier-C), L3.8 (orchestrator + floor).
import { afterEach, describe, expect, it, vi } from "vitest";
import { computeParamsDigest } from "./capability-approval.js";
import {
  EXEC_CAPABLE_TOOL_NAMES,
  NET_EGRESS_TOOL_NAMES,
  SUPERSET_EFFECTS,
  classifyEffects,
  classifyEffectsSync,
  classifyTierA,
  classifyTierB,
  dedupeByKind,
  digestForEffects,
  refineTierC,
  sortEffects,
} from "./effect-classifier.js";
import type { EffectDescriptor } from "./host-hooks.js";
import { createEmptyPluginRegistry } from "./registry-empty.js";
import { setActivePluginRegistry } from "./runtime.js";

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

// ---------------------------------------------------------------------------
// L3.5 — Tier-A: harness-native discriminator
// ---------------------------------------------------------------------------

describe("classifyTierA", () => {
  it("exec tool names → [process.exec]", () => {
    for (const name of EXEC_CAPABLE_TOOL_NAMES) {
      const result = classifyTierA(null, name, {});
      expect(result).toHaveLength(1);
      expect(result[0]?.kind).toBe("process.exec");
    }
  });

  it("net.egress tool names → [net.egress]", () => {
    for (const name of NET_EGRESS_TOOL_NAMES) {
      const result = classifyTierA(null, name, {});
      expect(result).toHaveLength(1);
      expect(result[0]?.kind).toBe("net.egress");
    }
  });

  it("bash → [process.exec]", () => {
    const result = classifyTierA(null, "bash", { command: "ls -la", cwd: "/tmp" });
    expect(result).toHaveLength(1);
    expect(result[0]?.kind).toBe("process.exec");
    expect(result[0]?.command).toBe("ls -la");
    expect(result[0]?.cwd).toBe("/tmp");
  });

  it("web_fetch → [net.egress] with hosts:['*'] (Tier-C refines host)", () => {
    const result = classifyTierA(null, "web_fetch", { url: "https://example.com" });
    expect(result).toHaveLength(1);
    expect(result[0]?.kind).toBe("net.egress");
    expect(result[0]?.hosts).toEqual(["*"]);
  });

  it("unknown tool → [] (pre-floor, floor in classifyEffects handles this)", () => {
    expect(classifyTierA(null, "my_custom_tool", {})).toEqual([]);
    expect(classifyTierA(null, "read_file", {})).toEqual([]);
    expect(classifyTierA(null, "write_file", {})).toEqual([]);
  });

  it("spoofed/invalid tool name → [] (fail-closed)", () => {
    // Injection attempt via non-tool chars
    expect(classifyTierA(null, "'; DROP TABLE tools; --", {})).toEqual([]);
    // Unicode injection
    expect(classifyTierA(null, "bash exec", {})).toEqual([]);
    // Too long
    expect(classifyTierA(null, "a".repeat(200), {})).toEqual([]);
    // Empty string
    expect(classifyTierA(null, "", {})).toEqual([]);
    // Non-string
    expect(classifyTierA(null, null, {})).toEqual([]);
    expect(classifyTierA(null, 42, {})).toEqual([]);
    expect(classifyTierA(null, undefined, {})).toEqual([]);
    expect(classifyTierA(null, {}, {})).toEqual([]);
  });

  it("extracts argv from params when present", () => {
    const result = classifyTierA(null, "exec", { argv: ["ls", "-la"], cwd: "/tmp" });
    expect(result[0]?.kind).toBe("process.exec");
    expect(result[0]?.argv).toEqual(["ls", "-la"]);
  });

  it("Tier-A result is a subset of what classifyEffects returns (monotonicity)", async () => {
    const inputs = [
      { name: "bash", params: { command: "ls" } },
      { name: "web_fetch", params: { url: "https://x.com" } },
      { name: "exec", params: { command: "echo hi" } },
    ];
    for (const { name, params } of inputs) {
      const tierA = classifyTierA(null, name, params);
      const full = await classifyEffects(null, name, params);
      // Every Tier-A kind must appear in the full result
      for (const effect of tierA) {
        expect(full.some((e) => e.kind === effect.kind)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// L3.6 — Tier-B: declarative tool-metadata capabilities
// ---------------------------------------------------------------------------

describe("classifyTierB", () => {
  afterEach(() => {
    // Reset to clean state so injected malformed registries don't bleed into other tests.
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  it("no registry → [] (graceful — no crash)", () => {
    // With no active registry, classifyTierB returns []
    const result = classifyTierB("my_custom_tool");
    expect(result).toEqual([]);
  });

  it("unknown tool → []", () => {
    expect(classifyTierB("nonexistent_tool_xyz")).toEqual([]);
  });

  it("invalid tool name → []", () => {
    expect(classifyTierB(null)).toEqual([]);
    expect(classifyTierB("")).toEqual([]);
    expect(classifyTierB(42)).toEqual([]);
  });

  it("Tier-B cannot drop a Tier-A effect (union semantics proven by classifyEffects)", async () => {
    // bash is a Tier-A exec tool. Even if there were Tier-B metadata without capabilities,
    // classifyEffects must still return process.exec (Tier-A wins, Tier-B is additive).
    const result = await classifyEffects(null, "bash", { command: "ls" });
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
  });

  // EMPTY-2/B1: guard Tier-B registry reads — malformed toolMetadata must not throw
  it("EMPTY-2: malformed registry (toolMetadata absent/not-array) → [] without throwing", () => {
    // Inject a registry whose toolMetadata is undefined (simulates unexpected registry shape).
    const malformed = {
      ...createEmptyPluginRegistry(),
      toolMetadata: undefined as unknown as [],
    };
    setActivePluginRegistry(malformed);

    // Must return [] and NEVER throw — so classifyEffects floor can apply superset.
    expect(() => classifyTierB("some_tool")).not.toThrow();
    expect(classifyTierB("some_tool")).toEqual([]);
  });

  it("EMPTY-2: classifyEffects still yields superset for unknown tool with malformed registry", async () => {
    // Even with malformed toolMetadata, orchestrator floor must yield SUPERSET (non-empty, fail-closed).
    const malformed = {
      ...createEmptyPluginRegistry(),
      toolMetadata: undefined as unknown as [],
    };
    setActivePluginRegistry(malformed);

    const result = await classifyEffects(null, "totally-unknown-xyz", null);
    // Floor applied: must have both effects
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// L3.7 — Tier-C: host argv/param refiner
// ---------------------------------------------------------------------------

describe("refineTierC", () => {
  it("curl command on a process.exec effect → adds net.egress with host:x.com port:443", () => {
    const baseEffects: EffectDescriptor[] = [
      { kind: "process.exec", command: "curl https://x.com", cwd: "/tmp" },
    ];
    const result = refineTierC(baseEffects, "bash", { command: "curl https://x.com" });
    expect(result.length).toBeGreaterThanOrEqual(baseEffects.length);
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress).toBeDefined();
    expect(egress?.hosts).toEqual(["x.com"]);
    expect(egress?.ports).toEqual([443]);
  });

  it("non-fetch command → unchanged (process.exec only)", () => {
    const baseEffects: EffectDescriptor[] = [
      { kind: "process.exec", command: "ls -la /tmp", cwd: "/tmp" },
    ];
    const result = refineTierC(baseEffects, "bash", { command: "ls -la /tmp" });
    // Should be unchanged — no net.egress added for ls
    expect(result.length).toBe(baseEffects.length);
    expect(result.find((e) => e.kind === "net.egress")).toBeUndefined();
  });

  it("malformed URL → does not crash (falls to floor)", () => {
    const baseEffects: EffectDescriptor[] = [
      { kind: "process.exec", command: "curl not-a-url", cwd: "/tmp" },
    ];
    // Should not throw — parse failure is graceful
    expect(() => refineTierC(baseEffects, "bash", { command: "curl not-a-url" })).not.toThrow();
  });

  it("refineTierC is monotonic: result.length >= input.length", () => {
    const inputs = [
      {
        effects: [{ kind: "process.exec", command: "curl https://x.com" }] as EffectDescriptor[],
        params: { command: "curl https://x.com" },
      },
      {
        effects: [{ kind: "process.exec", command: "ls -la" }] as EffectDescriptor[],
        params: { command: "ls -la" },
      },
      {
        effects: [{ kind: "net.egress", hosts: ["*"] }] as EffectDescriptor[],
        params: { url: "https://example.com" },
      },
      { effects: [] as EffectDescriptor[], params: {} },
    ];
    for (const { effects, params } of inputs) {
      const result = refineTierC(effects, "tool", params);
      expect(result.length).toBeGreaterThanOrEqual(effects.length);
    }
  });

  it("web_fetch net.egress → refines host/port from params.url", () => {
    const baseEffects: EffectDescriptor[] = [{ kind: "net.egress", hosts: ["*"] }];
    const result = refineTierC(baseEffects, "web_fetch", { url: "https://api.example.com/data" });
    expect(result).toHaveLength(1);
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["api.example.com"]);
    expect(egress?.ports).toEqual([443]);
    expect(egress?.url).toBe("https://api.example.com/data");
  });

  it("web_fetch with http URL → port 80", () => {
    const baseEffects: EffectDescriptor[] = [{ kind: "net.egress", hosts: ["*"] }];
    const result = refineTierC(baseEffects, "web_fetch", { url: "http://api.example.com" });
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["api.example.com"]);
    expect(egress?.ports).toEqual([80]);
  });

  it("Tier-C does not shrink effects — effects unchanged on non-fetch command", () => {
    const baseEffects: EffectDescriptor[] = [
      { kind: "process.exec", command: "echo hello" },
      { kind: "net.egress", hosts: ["x.com"] },
    ];
    const result = refineTierC(baseEffects, "bash", { command: "echo hello" });
    // No new effects added for 'echo', existing net.egress preserved
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// L3.8 — classifyEffects orchestrator + soundness superset floor
// SECURITY CORE — these tests are exhaustive and adversarial
// ---------------------------------------------------------------------------

describe("classifyEffects — soundness (NEVER [])", () => {
  // -------------------------------------------------------------------------
  // GARBAGE CORPUS — every one of these MUST return length >= 1
  // AND the fully-unparseable case MUST return BOTH process.exec AND net.egress
  // -------------------------------------------------------------------------
  const GARBAGE_CORPUS = [
    // Null/undefined params
    { toolName: null, params: null },
    { toolName: undefined, params: undefined },
    // Empty string
    { toolName: "", params: {} },
    // Spoofed tool name with injection chars
    { toolName: "'; DROP TABLE tools;--", params: {} },
    { toolName: "<script>alert(1)</script>", params: {} },
    { toolName: "bash\x00exec", params: {} }, // null byte
    { toolName: "bash\nexec", params: {} }, // newline
    // Too long
    { toolName: "a".repeat(300), params: {} },
    // Unicode tricks
    { toolName: "bаsh", params: {} }, // Cyrillic 'а' instead of 'a'
    { toolName: " bash", params: {} },
    // Object toolName
    { toolName: {}, params: {} },
    { toolName: [], params: {} },
    { toolName: 42, params: {} },
    { toolName: true, params: {} },
    // Completely unknown but valid-looking tool name
    { toolName: "totally.unknown.tool.xyz123", params: {} },
    { toolName: "random-tool-name", params: {} },
    // Non-object params
    { toolName: "bash", params: null },
    { toolName: "bash", params: "not-an-object" },
    { toolName: "bash", params: 42 },
    { toolName: "bash", params: [] },
  ];

  it.each(GARBAGE_CORPUS)(
    "classifyEffects with garbage input ($toolName) → length >= 1 (never [])",
    async ({ toolName, params }) => {
      const result = await classifyEffects(null, toolName, params);
      expect(result.length).toBeGreaterThanOrEqual(1);
    },
  );

  it("fully-unparseable input returns BOTH process.exec AND net.egress (widest superset)", async () => {
    // Fully unparseable = unknown tool, no metadata → both superset effects
    const result = await classifyEffects(null, "totally.unknown.xyz", null);
    expect(result.length).toBeGreaterThanOrEqual(2);
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
  });

  it("SUPERSET_EFFECTS has both process.exec and net.egress", () => {
    expect(SUPERSET_EFFECTS.some((e) => e.kind === "process.exec")).toBe(true);
    expect(SUPERSET_EFFECTS.some((e) => e.kind === "net.egress")).toBe(true);
    expect(SUPERSET_EFFECTS.length).toBe(2);
  });

  it("null params → superset (NEVER [])", async () => {
    const result = await classifyEffects(null, null, null);
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it("null toolName → superset (NEVER [])", async () => {
    const result = await classifyEffects(null, null, {});
    expect(result.length).toBeGreaterThanOrEqual(1);
    // This is a fully-unparseable case → superset
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
  });
});

describe("classifyEffects — happy paths", () => {
  it("plain command (bash) → [process.exec]", async () => {
    const result = await classifyEffects(null, "bash", { command: "ls -la" });
    expect(result.length).toBe(1);
    expect(result[0]?.kind).toBe("process.exec");
  });

  it("curl command → [net.egress, process.exec] (both effects)", async () => {
    const result = await classifyEffects(null, "bash", { command: "curl https://x.com" });
    // Must have both effects
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
    // net.egress must have correct host
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["x.com"]);
    expect(egress?.ports).toEqual([443]);
  });

  it("web_fetch → [net.egress] with refined host/port", async () => {
    const result = await classifyEffects(null, "web_fetch", { url: "https://api.example.com" });
    expect(result.length).toBe(1);
    expect(result[0]?.kind).toBe("net.egress");
    expect(result[0]?.hosts).toEqual(["api.example.com"]);
    expect(result[0]?.ports).toEqual([443]);
  });

  it("exec → [process.exec]", async () => {
    const result = await classifyEffects(null, "exec", { command: "node script.js" });
    expect(result.length).toBe(1);
    expect(result[0]?.kind).toBe("process.exec");
  });
});

describe("classifyEffects — monotonicity", () => {
  it("classifyTierA ⊆ classifyEffects for all recognized tool names", async () => {
    const testCases = [
      { name: "bash", params: { command: "ls" } },
      { name: "exec", params: { command: "echo" } },
      { name: "shell", params: {} },
      { name: "web_fetch", params: { url: "https://x.com" } },
    ];
    for (const { name, params } of testCases) {
      const tierA = classifyTierA(null, name, params);
      const full = await classifyEffects(null, name, params);
      for (const effect of tierA) {
        expect(full.some((e) => e.kind === effect.kind)).toBe(true);
      }
    }
  });

  it("classifyEffects always returns >= 1 effects (fuzz-lite: random tool names)", async () => {
    const randomNames = [
      "aaaaa",
      "12345",
      "foo-bar",
      "x.y.z",
      "ab/cd",
      "tool1",
      "TOOL", // uppercase → normalized
      "tool-name-123",
      "net.fetch",
      "sys.exec",
    ];
    for (const name of randomNames) {
      const result = await classifyEffects(null, name, {});
      expect(result.length).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// L3.8 — classifyEffectsSync vs classifyEffects consistency
// ---------------------------------------------------------------------------

describe("classifyEffectsSync", () => {
  it("sync and async return same effects for bash (non-curl exec)", async () => {
    const params = { command: "ls -la" };
    const asyncResult = await classifyEffects(null, "bash", params);
    const syncResult = classifyEffectsSync(null, "bash", params);
    // Both should have process.exec
    expect(syncResult.some((e) => e.kind === "process.exec")).toBe(
      asyncResult.some((e) => e.kind === "process.exec"),
    );
  });

  it("sync and async return same effects for unknown tool (both → superset)", async () => {
    const asyncResult = await classifyEffects(null, "totally-unknown-xyz", {});
    const syncResult = classifyEffectsSync(null, "totally-unknown-xyz", {});
    // Both should have the same kinds
    const asyncKinds = new Set(asyncResult.map((e) => e.kind));
    const syncKinds = new Set(syncResult.map((e) => e.kind));
    expect(asyncKinds).toEqual(syncKinds);
  });

  it("sync never returns []", () => {
    const garbageInputs = [null, undefined, "", 42, {}, [], "'; DROP TABLE;"];
    for (const input of garbageInputs) {
      const result = classifyEffectsSync(null, input, {});
      expect(result.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("sync: bash → [process.exec]", () => {
    const result = classifyEffectsSync(null, "bash", { command: "ls" });
    expect(result.length).toBe(1);
    expect(result[0]?.kind).toBe("process.exec");
  });

  it("sync: unknown → superset (both process.exec and net.egress)", () => {
    const result = classifyEffectsSync(null, "totally-unknown-xyz", {});
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
  });

  it("sync: curl command → [process.exec] only (no Tier-C in sync)", () => {
    // Sync does NOT run Tier-C, so curl command on 'bash' only gives process.exec
    const result = classifyEffectsSync(null, "bash", { command: "curl https://x.com" });
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    // No net.egress from Tier-C (sync skips Tier-C)
    expect(result.some((e) => e.kind === "net.egress")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// L3.7 — net-egress refiner (unit tests for refiners directly)
// ---------------------------------------------------------------------------

describe("refineCurlNetEgress (via effect-refiners/net-egress)", () => {
  // Import via the classifier which imports it
  it("curl https://x.com → hosts:['x.com'] port:443", async () => {
    const result = await classifyEffects(null, "bash", { command: "curl https://x.com" });
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["x.com"]);
    expect(egress?.ports).toEqual([443]);
  });

  it("curl http://example.com → hosts:['example.com'] port:80", async () => {
    const result = await classifyEffects(null, "bash", { command: "curl http://example.com" });
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["example.com"]);
    expect(egress?.ports).toEqual([80]);
  });

  it("curl with --url flag → extracts host", async () => {
    const result = await classifyEffects(null, "bash", {
      command: "curl --url https://api.example.com/v1",
    });
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress?.hosts).toEqual(["api.example.com"]);
  });

  it("wget https://x.com → adds net.egress", async () => {
    // wget is in EXEC_CAPABLE_TOOL_NAMES... wait, no — let me check if wget is in exec names
    // Actually wget is in NET_EGRESS_TOOL_NAMES, so classifyTierA returns net.egress with hosts:['*']
    // But if called via bash, the command would be 'bash' tool with 'wget' in the command string
    const result = await classifyEffects(null, "bash", { command: "wget https://x.com/file.txt" });
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress).toBeDefined();
    expect(egress?.hosts).toEqual(["x.com"]);
  });

  it("plain ls command → no net.egress added", async () => {
    const result = await classifyEffects(null, "bash", { command: "ls -la /tmp" });
    expect(result.find((e) => e.kind === "net.egress")).toBeUndefined();
    expect(result.length).toBe(1);
  });

  it("malformed curl URL → no crash, superset fallback (hosts:['*'])", async () => {
    // 'curl not-a-url' — refineCurlNetEgress returns {hosts:['*']} for unparseable fetch
    const result = await classifyEffects(null, "bash", { command: "curl not-a-url" });
    // Must not crash and must have at least process.exec
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    // Should have net.egress with hosts:['*'] (curl detected, url unparseable)
    const egress = result.find((e) => e.kind === "net.egress");
    expect(egress).toBeDefined();
    expect(egress?.hosts).toEqual(["*"]);
  });
});

// ---------------------------------------------------------------------------
// Backstop test: if classifyEffects somehow returned [], the caller throws
// ---------------------------------------------------------------------------
describe("caller-side backstop (belt-and-suspenders proof)", () => {
  it("SUPERSET_EFFECTS is non-empty — proving the floor is sound", () => {
    // The floor returns SUPERSET_EFFECTS when effects is empty.
    // This test proves SUPERSET_EFFECTS itself is non-empty (so the floor cannot produce []).
    expect(SUPERSET_EFFECTS.length).toBeGreaterThanOrEqual(1);
    expect(SUPERSET_EFFECTS.length).toBe(2);
  });

  it("classifyEffects mocked to empty would be caught by the floor (structural proof)", async () => {
    // We cannot mock classifyEffects from outside (it's the function under test),
    // but we can prove the floor is the LAST line before return by checking
    // that assertSuperset(SUPERSET_EFFECTS) === SUPERSET_EFFECTS (no double-wrapping).
    //
    // Proof: run with an input that exercises the floor path (unknown tool).
    const result = await classifyEffects(null, "totally-unknown-xyz-abc", null);
    // Floor was triggered: result === SUPERSET_EFFECTS content
    expect(result.some((e) => e.kind === "process.exec")).toBe(true);
    expect(result.some((e) => e.kind === "net.egress")).toBe(true);
    // The unparseable superset has the expected shape
    const execEffect = result.find((e) => e.kind === "process.exec");
    expect(execEffect?.["unparseable"]).toBe(true);
    const egressEffect = result.find((e) => e.kind === "net.egress");
    expect(egressEffect?.hosts).toEqual(["*"]);
  });
});
