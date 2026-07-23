// Core capability-approval proof registry — structural replay + single-use enforcement.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetProofRegistryForTest,
  assertProofFresh,
  computeParamsDigest,
  decideCapabilityApproval,
  fingerprintJson,
  recordAndConsumeProof,
} from "./capability-approval.js";
import type { PluginJsonValue } from "./host-hook-json.js";
import type { ApprovalDecision, ApprovalRequest } from "./host-hooks.js";
import { InMemoryProofLedger, type ProofLedger } from "./proof-ledger.js";
import { createEmptyPluginRegistry } from "./registry-empty.js";
import { setActivePluginRegistry } from "./runtime.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EFFECT = { kind: "process.exec" as const, command: "/bin/echo hello", cwd: "/tmp" };
const PARAMS_DIGEST = computeParamsDigest(EFFECT);

function makeRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    requestId: "req-test-1",
    capability: "process.exec",
    toolName: "bash",
    effects: [EFFECT],
    paramsDigest: PARAMS_DIGEST,
    ...overrides,
  };
}

function makeRegistryWithResolver(
  resolve: (
    req: ApprovalRequest,
    opts: { signal: AbortSignal; deadlineMs: number },
  ) => Promise<ApprovalDecision>,
) {
  const registry = {
    ...createEmptyPluginRegistry(),
    approvalResolvers: [
      {
        pluginId: "test-plugin",
        pluginName: "Test Plugin",
        source: "test",
        registration: {
          id: "test-exec-resolver",
          description: "Test approval resolver",
          scope: { capabilities: ["process.exec" as const] },
          exclusive: true as const,
          resolve,
        },
      },
    ],
  };
  return registry;
}

// ---------------------------------------------------------------------------
// decideCapabilityApproval test suite
// ---------------------------------------------------------------------------

describe("decideCapabilityApproval", () => {
  beforeEach(() => {
    __resetProofRegistryForTest();
  });

  afterEach(() => {
    vi.useRealTimers();
    // Reset to empty registry so approval-resolver reads no entries.
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  it("fallthrough — no resolver registered → {kind:'fallthrough'}", async () => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    expect(verdict).toEqual({ kind: "fallthrough" });
  });

  it("allow — resolver returns allow with matching requestId → {kind:'allow'}", async () => {
    const req = makeRequest();
    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "allow",
      })),
    );
    const verdict = await decideCapabilityApproval(req, {
      deadlineMs: 5000,
      ledger: new InMemoryProofLedger(),
    });
    expect(verdict).toEqual({ kind: "allow", requestId: req.requestId });
  });

  it("deny — clean policy deny (matching requestId) → {kind:'deny',reason} with NO failureDisposition (graceful block)", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "deny",
        reason: "not allowed",
      })),
    );
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    // A clean policy DENY is a DECISION, not a failure: no failureDisposition is
    // emitted, so the caller's graceful-block (front-stage veto) branch fires.
    expect(verdict).toEqual({
      kind: "deny",
      requestId: makeRequest().requestId,
      reason: "not allowed",
    });
    expect(
      (verdict as { kind: "deny"; failureDisposition?: string }).failureDisposition,
    ).toBeUndefined();
  });

  it("deny — resolver throws → {kind:'deny',failureDisposition:'failed'}", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver(async () => {
        throw new Error("resolver exploded");
      }),
    );
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    expect(verdict.kind).toBe("deny");
    expect((verdict as { kind: "deny"; failureDisposition?: string }).failureDisposition).toBe(
      "failed",
    );
  });

  it("deny — requestId mismatch → {kind:'deny',failureDisposition:'failed'}", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver(async () => ({
        requestId: "WRONG-requestId",
        decision: "allow",
      })),
    );
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    expect(verdict.kind).toBe("deny");
    expect((verdict as { kind: "deny"; failureDisposition?: string }).failureDisposition).toBe(
      "failed",
    );
  });

  it("deny — malformed decision value → {kind:'deny',failureDisposition:'failed'}", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "approve-always" as unknown as "allow" | "deny",
      })),
    );
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    expect(verdict.kind).toBe("deny");
    expect((verdict as { kind: "deny"; failureDisposition?: string }).failureDisposition).toBe(
      "failed",
    );
  });

  it("deny — resolver never resolves → timed_out after deadline (fake timers)", async () => {
    vi.useFakeTimers();
    setActivePluginRegistry(
      makeRegistryWithResolver(
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        (_req, opts) =>
          new Promise<ApprovalDecision>((resolve) => {
            // Cooperatively stop when aborted; otherwise hang forever.
            opts.signal.addEventListener("abort", () => {
              resolve({ requestId: _req.requestId, decision: "deny", reason: "aborted" });
            });
          }),
      ),
    );

    const verdictPromise = decideCapabilityApproval(makeRequest(), { deadlineMs: 3000 });
    await vi.advanceTimersByTimeAsync(3001);
    const verdict = await verdictPromise;
    expect(verdict.kind).toBe("deny");
    const d = verdict as { kind: "deny"; failureDisposition?: string };
    expect(d.failureDisposition).toBe("timed_out");
  });

  it("deny — caller aborts signal mid-hold → {kind:'deny'}", async () => {
    const ac = new AbortController();
    let resolverResolve!: (d: ApprovalDecision) => void;
    setActivePluginRegistry(
      makeRegistryWithResolver(
        (r) =>
          new Promise<ApprovalDecision>((res) => {
            resolverResolve = () => res({ requestId: r.requestId, decision: "deny" });
          }),
      ),
    );
    const verdictPromise = decideCapabilityApproval(makeRequest(), {
      deadlineMs: 30000,
      signal: ac.signal,
    });
    // Abort before the resolver finishes.
    ac.abort();
    resolverResolve();
    const verdict = await verdictPromise;
    expect(verdict.kind).toBe("deny");
  });

  it("deny — replayed/consumed proof → {kind:'deny',failureDisposition:'failed'}", async () => {
    const proof = "proof-unique-abc";
    // Pre-consume the proof in the injected ledger so the second attempt is replayed.
    const ledger = new InMemoryProofLedger();
    ledger.consumeOnce(proof, "req-pre-seed", "sha256:aabbcc", "allow"); // first sight → consumed

    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "allow",
        proof,
      })),
    );
    // Use a DIFFERENT requestId so it isn't already_consumed — it must be denied as replayed.
    const verdict = await decideCapabilityApproval(makeRequest({ requestId: "req-replay-check" }), {
      deadlineMs: 5000,
      ledger,
    });
    expect(verdict.kind).toBe("deny");
    expect((verdict as { kind: "deny"; failureDisposition?: string }).failureDisposition).toBe(
      "failed",
    );
  });

  it("deny — single-use: same requestId+paramsDigest consumed twice → second call denied", async () => {
    const req = makeRequest();
    // Share ONE ledger across both calls — state persists between calls.
    const ledger = new InMemoryProofLedger();
    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "allow",
      })),
    );
    // First call consumes the {requestId, paramsDigest} pair.
    const first = await decideCapabilityApproval(req, { deadlineMs: 5000, ledger });
    expect(first.kind).toBe("allow");

    // Second call with the SAME requestId must be denied (pair already consumed).
    // We need to rebuild the registry since the active one still has the resolver,
    // but the proof registry is the blocker.
    const second = await decideCapabilityApproval(req, { deadlineMs: 5000, ledger });
    expect(second.kind).toBe("deny");
  });

  it("deny — poisoned resolver entry (registration getter throws) → fail-closed deny", async () => {
    const poisonedEntry = {
      pluginId: "poison-plugin",
      source: "test",
      get registration(): never {
        throw new Error("TOCTOU: registration unreadable");
      },
    };
    const registry = {
      ...createEmptyPluginRegistry(),
      approvalResolvers: [poisonedEntry as never],
    };
    setActivePluginRegistry(registry);
    const verdict = await decideCapabilityApproval(makeRequest(), { deadlineMs: 5000 });
    expect(verdict.kind).toBe("deny");
  });

  it("deny(failed) when ledger.consumeOnce throws", async () => {
    const throwingLedger: ProofLedger = {
      consumeOnce: () => {
        throw new Error("disk full");
      },
    };
    const req = makeRequest();
    setActivePluginRegistry(
      makeRegistryWithResolver(async (r) => ({
        requestId: r.requestId,
        decision: "allow",
      })),
    );
    const result = await decideCapabilityApproval(req, {
      deadlineMs: 5000,
      ledger: throwingLedger,
    });
    expect(result.kind).toBe("deny");
    expect((result as { kind: "deny"; reason?: string }).reason).toBe(
      "approval proof ledger unavailable",
    );
    expect((result as { kind: "deny"; failureDisposition?: string }).failureDisposition).toBe(
      "failed",
    );
  });
});

describe("Codex approval-proof registry", () => {
  beforeEach(() => {
    __resetProofRegistryForTest();
  });

  it("consumes a {requestId,paramsDigest} key exactly once", () => {
    const rec = {
      requestId: "req-1",
      paramsDigest: "sha256:aaaa",
      outcome: "allow" as const,
    };

    expect(recordAndConsumeProof(rec)).toEqual({ ok: true });
    expect(recordAndConsumeProof(rec)).toEqual({
      ok: false,
      reason: "already_consumed",
    });
  });

  it("treats a different requestId or paramsDigest as a distinct key", () => {
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });

    // Same digest, different request id -> new key -> ok.
    expect(
      recordAndConsumeProof({
        requestId: "req-2",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });

    // Same request id, different digest -> new key -> ok.
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:bbbb",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
  });

  it("does not let a null-byte in requestId collide across the key separator", () => {
    // Guard against `${a} ${b}` key ambiguity: ("a b","c") vs ("a","b c").
    expect(
      recordAndConsumeProof({
        requestId: "a b",
        paramsDigest: "c",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
    expect(
      recordAndConsumeProof({
        requestId: "a",
        paramsDigest: "b c",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
  });

  it("marks a proof string replayed on the second sighting", () => {
    expect(assertProofFresh("proof-abc")).toEqual({ ok: true });
    expect(assertProofFresh("proof-abc")).toEqual({
      ok: false,
      reason: "replayed",
    });
  });

  it("treats an undefined proof as fresh without recording it", () => {
    expect(assertProofFresh(undefined)).toEqual({ ok: true });
    expect(assertProofFresh(undefined)).toEqual({ ok: true });
  });

  it("rejects recordAndConsumeProof when requestId is empty", () => {
    expect(
      recordAndConsumeProof({
        requestId: "",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: false, reason: "invalid_identifier" });
  });

  it("rejects recordAndConsumeProof when paramsDigest is empty", () => {
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "",
        outcome: "allow",
      }),
    ).toEqual({ ok: false, reason: "invalid_identifier" });
  });

  it("rejects assertProofFresh when proof is an empty string", () => {
    expect(assertProofFresh("")).toEqual({
      ok: false,
      reason: "invalid_identifier",
    });
  });

  it("__resetProofRegistryForTest clears both the consumed keys and the seen proofs", () => {
    recordAndConsumeProof({
      requestId: "req-1",
      paramsDigest: "sha256:aaaa",
      outcome: "allow",
    });
    assertProofFresh("proof-abc");

    __resetProofRegistryForTest();

    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
    expect(assertProofFresh("proof-abc")).toEqual({ ok: true });
  });
});

describe("params-digest", () => {
  it("computeParamsDigest is key-order independent and sha256-prefixed", () => {
    const a: PluginJsonValue = { command: "/bin/ls", cwd: "/tmp", approval: { id: 1 } };
    const b: PluginJsonValue = { approval: { id: 1 }, cwd: "/tmp", command: "/bin/ls" };
    const digestA = computeParamsDigest(a);
    const digestB = computeParamsDigest(b);
    expect(digestA).toBe(digestB);
    expect(digestA).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("different command → different digest", () => {
    const base: PluginJsonValue = { command: "/bin/ls", cwd: "/tmp" };
    const other: PluginJsonValue = { command: "/bin/rm -rf /tmp/x", cwd: "/tmp" };
    expect(computeParamsDigest(base)).not.toBe(computeParamsDigest(other));
  });

  it("fingerprintJson returns bare 64-char hex (no prefix)", () => {
    const hex = fingerprintJson({ a: 1, b: [2, 3], c: null } satisfies PluginJsonValue);
    expect(hex).toMatch(/^[a-f0-9]{64}$/);
    // computeParamsDigest is exactly the prefixed form of fingerprintJson.
    expect(computeParamsDigest({ a: 1, b: [2, 3], c: null })).toBe(`sha256:${hex}`);
  });

  it("stableStringify semantics preserved: nested arrays keep order, object keys sort", () => {
    // Arrays are order-sensitive; only object keys are sorted.
    const ordered: PluginJsonValue = { list: [1, 2, 3] };
    const reordered: PluginJsonValue = { list: [3, 2, 1] };
    expect(fingerprintJson(ordered)).not.toBe(fingerprintJson(reordered));
  });

  it("computeParamsDigest pins a literal golden digest (algorithm-drift guard)", () => {
    // Computed once: stableStringify({command:"/bin/ls",cwd:"/tmp"}) →
    //   '{"command":"/bin/ls","cwd":"/tmp"}' (keys sort: command < cwd)
    // sha256 of that UTF-8 string = the hex below.
    // If this test ever breaks, the hashing algorithm or key-sort changed —
    // treat that as a breaking change to the wire format (paramsDigest).
    expect(computeParamsDigest({ command: "/bin/ls", cwd: "/tmp" })).toBe(
      "sha256:5c83d9f79f812871296758a1e01f42dcd28738c6bf45080f5fc577caa3aca01e",
    );
  });
});
