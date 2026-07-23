// Layer 4, Dispatch A — front-stage resolver helpers unit tests.
// L4.1: HookBlockedReason widening for 'capability-resolver'
// L4.2: frontStageResolverTimeoutMs config default
// L4.3: pickOwner helper
// L4.4: buildFrontStageApprovalRequest shape
// L4.5: runFrontStageResolver verdict→HookOutcome matrix
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { digestForEffects } from "../plugins/effect-classifier.js";
import type { EffectDescriptor, ApprovalRequest, ApprovalDecision } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import {
  buildBlockedToolResult,
  isPreExecutionBlockedToolResult,
} from "./agent-tools.before-tool-call.js";
import {
  buildFrontStageApprovalRequest,
  DEFAULT_FRONT_STAGE_RESOLVER_TIMEOUT_MS,
  pickOwner,
  runFrontStageResolver,
} from "./front-stage-resolver.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EXEC_EFFECT: EffectDescriptor = {
  kind: "process.exec",
  command: "/bin/echo hello",
  cwd: "/tmp",
};

const EGRESS_EFFECT: EffectDescriptor = {
  kind: "net.egress",
  hosts: ["example.com"],
  ports: [443],
};

const TOOL_NAME = "bash";
const PARAMS = { cmd: "echo hello" };

function makeCtx(overrides: Record<string, unknown> = {}) {
  return {
    sessionKey: "test-session-key",
    runId: "test-run-id",
    agentId: "test-agent-id",
    ...overrides,
  };
}

function makeRegistryWithResolver(
  capability: string,
  resolve: (
    req: ApprovalRequest,
    opts: { signal: AbortSignal; deadlineMs: number },
  ) => Promise<ApprovalDecision>,
) {
  return {
    ...createEmptyPluginRegistry(),
    approvalResolvers: [
      {
        pluginId: "test-plugin",
        pluginName: "Test Plugin",
        source: "test",
        registration: {
          id: `test-${capability}-resolver`,
          description: `Test ${capability} approval resolver`,
          scope: { capabilities: [capability] },
          exclusive: true as const,
          resolve,
        },
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// L4.1 — HookBlockedReason widening for 'capability-resolver'
// ---------------------------------------------------------------------------

describe("L4.1 — buildBlockedToolResult with deniedReason:'capability-resolver'", () => {
  it("accepts 'capability-resolver' deniedReason and produces correct shape", () => {
    const result = buildBlockedToolResult({
      reason: "blocked by capability resolver test",
      deniedReason: "capability-resolver",
      toolCallId: "call-1",
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0]).toEqual({
      type: "text",
      text: "blocked by capability resolver test",
    });
    expect(result.details.status).toBe("blocked");
    expect(result.details.deniedReason).toBe("capability-resolver");
    expect(result.details.reason).toBe("blocked by capability resolver test");
  });

  it("isPreExecutionBlockedToolResult returns true for 'capability-resolver' result", () => {
    const result = buildBlockedToolResult({
      reason: "capability resolver denial",
      deniedReason: "capability-resolver",
    });
    expect(isPreExecutionBlockedToolResult(result)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// L4.2 — frontStageResolverTimeoutMs config default
// ---------------------------------------------------------------------------

describe("L4.2 — frontStageResolverTimeoutMs config", () => {
  it("DEFAULT_FRONT_STAGE_RESOLVER_TIMEOUT_MS is 500", () => {
    expect(DEFAULT_FRONT_STAGE_RESOLVER_TIMEOUT_MS).toBe(500);
  });

  it("runFrontStageResolver uses default 500ms when config is absent (no-resolver path completes without timeout)", async () => {
    // With no resolver, it should short-circuit before using the timeout.
    setActivePluginRegistry(createEmptyPluginRegistry());
    const signal = AbortSignal.timeout(5000);
    const result = await runFrontStageResolver({
      toolName: TOOL_NAME,
      params: PARAMS,
      ctx: makeCtx({ config: undefined }),
      signal,
    });
    expect(result).toBeUndefined();
  });

  it("runFrontStageResolver uses config.approvals.frontStageResolverTimeoutMs when provided", async () => {
    // Register a resolver that hangs forever; with a 1ms timeout it should deny/timed_out.
    const neverResolve = (
      _req: ApprovalRequest,
      _opts: { signal: AbortSignal; deadlineMs: number },
    ) => new Promise<ApprovalDecision>(() => {}); // never resolves
    setActivePluginRegistry(makeRegistryWithResolver("process.exec", neverResolve));

    const ctx = makeCtx({
      config: {
        approvals: {
          frontStageResolverTimeoutMs: 1, // 1ms — will time out immediately
        },
      },
    });

    const signal = AbortSignal.timeout(5000);
    const result = await runFrontStageResolver({
      toolName: "bash",
      params: { cmd: "echo hello" },
      ctx,
      signal,
    });

    // Should return a failure outcome due to timeout
    expect(result).toBeDefined();
    expect(result?.blocked).toBe(true);
    expect((result as { kind: string }).kind).toBe("failure");
    expect((result as { disposition: string }).disposition).toBe("timed_out");
    expect((result as { deniedReason: string }).deniedReason).toBe("capability-resolver");
  });
});

// ---------------------------------------------------------------------------
// L4.3 — pickOwner helper
// ---------------------------------------------------------------------------

describe("L4.3 — pickOwner", () => {
  it("[{kind:'process.exec'}] → 'process.exec'", () => {
    expect(pickOwner([EXEC_EFFECT])).toBe("process.exec");
  });

  it("[{kind:'net.egress'},{kind:'process.exec'}] → 'process.exec'", () => {
    expect(pickOwner([EGRESS_EFFECT, EXEC_EFFECT])).toBe("process.exec");
  });

  it("[{kind:'process.exec'},{kind:'net.egress'}] → 'process.exec'", () => {
    expect(pickOwner([EXEC_EFFECT, EGRESS_EFFECT])).toBe("process.exec");
  });

  it("[{kind:'net.egress'}] → 'net.egress'", () => {
    expect(pickOwner([EGRESS_EFFECT])).toBe("net.egress");
  });

  it("empty array → 'net.egress' (fallback)", () => {
    expect(pickOwner([])).toBe("net.egress");
  });

  it("unknown kind only → that kind", () => {
    const effect: EffectDescriptor = { kind: "file.write" };
    expect(pickOwner([effect])).toBe("file.write");
  });
});

// ---------------------------------------------------------------------------
// L4.4 — buildFrontStageApprovalRequest shape
// ---------------------------------------------------------------------------

describe("L4.4 — buildFrontStageApprovalRequest", () => {
  it("shape correct: requestId, capability, effects, paramsDigest, toolName", () => {
    const effects = [EXEC_EFFECT];
    const req = buildFrontStageApprovalRequest(effects, TOOL_NAME, makeCtx(), "call-42");

    expect(typeof req.requestId).toBe("string");
    expect(req.requestId.length).toBeGreaterThan(0);
    expect(req.capability).toBe("process.exec"); // pickOwner([EXEC_EFFECT])
    expect(req.effects).toBe(effects); // same reference
    expect(req.paramsDigest).toBe(digestForEffects(effects));
    expect(req.toolName).toBe(TOOL_NAME);
  });

  it("capability = pickOwner(effects)", () => {
    // Two-effect set: process.exec should win
    const effects = [EGRESS_EFFECT, EXEC_EFFECT];
    const req = buildFrontStageApprovalRequest(effects, TOOL_NAME, makeCtx(), undefined);
    expect(req.capability).toBe("process.exec");
  });

  it("capability = 'net.egress' for pure net.egress effect", () => {
    const effects = [EGRESS_EFFECT];
    const req = buildFrontStageApprovalRequest(effects, "web_fetch", makeCtx(), undefined);
    expect(req.capability).toBe("net.egress");
  });

  it("paramsDigest matches digestForEffects(effects) — single effect branch A", () => {
    const effects = [EXEC_EFFECT];
    const req = buildFrontStageApprovalRequest(effects, TOOL_NAME, makeCtx(), undefined);
    expect(req.paramsDigest).toBe(digestForEffects([EXEC_EFFECT]));
  });

  it("paramsDigest matches digestForEffects(effects) — two-effect branch B", () => {
    const effects = [EXEC_EFFECT, EGRESS_EFFECT];
    const req = buildFrontStageApprovalRequest(effects, TOOL_NAME, makeCtx(), undefined);
    expect(req.paramsDigest).toBe(digestForEffects([EXEC_EFFECT, EGRESS_EFFECT]));
  });

  it("requestId falls back to crypto.randomUUID() when no toolCallId", () => {
    const req1 = buildFrontStageApprovalRequest([EXEC_EFFECT], TOOL_NAME, makeCtx(), undefined);
    const req2 = buildFrontStageApprovalRequest([EXEC_EFFECT], TOOL_NAME, makeCtx(), undefined);
    // Both should be valid UUIDs and different
    expect(req1.requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(req1.requestId).not.toBe(req2.requestId);
  });

  it("requestId = toolCallId when provided", () => {
    const req = buildFrontStageApprovalRequest([EXEC_EFFECT], TOOL_NAME, makeCtx(), "my-call-id");
    expect(req.requestId).toBe("my-call-id");
  });

  it("optional fields (agentId, sessionKey, runId, toolCallId) omitted when absent", () => {
    const req = buildFrontStageApprovalRequest([EXEC_EFFECT], TOOL_NAME, {}, undefined);
    expect(req.agentId).toBeUndefined();
    expect(req.sessionKey).toBeUndefined();
    expect(req.runId).toBeUndefined();
    expect(req.toolCallId).toBeUndefined();
  });

  it("optional fields present from ctx when available", () => {
    const ctx = makeCtx({ agentId: "agent-x", sessionKey: "sk-1", runId: "run-1" });
    const req = buildFrontStageApprovalRequest([EXEC_EFFECT], TOOL_NAME, ctx, "call-99");
    expect(req.agentId).toBe("agent-x");
    expect(req.sessionKey).toBe("sk-1");
    expect(req.runId).toBe("run-1");
    expect(req.toolCallId).toBe("call-99");
  });
});

// ---------------------------------------------------------------------------
// L4.5 — runFrontStageResolver verdict→HookOutcome matrix
// ---------------------------------------------------------------------------

describe("L4.5 — runFrontStageResolver", () => {
  afterEach(() => {
    vi.useRealTimers();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  it("no resolver registered → returns undefined, decideCapabilityApproval NOT called", async () => {
    setActivePluginRegistry(createEmptyPluginRegistry());

    // Mock decideCapabilityApproval to track if it was called
    const decideSpy = vi.spyOn(
      await import("../plugins/capability-approval.js"),
      "decideCapabilityApproval",
    );

    const result = await runFrontStageResolver({
      toolName: TOOL_NAME,
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result).toBeUndefined();
    expect(decideSpy).not.toHaveBeenCalled();

    decideSpy.mockRestore();
  });

  it("allow verdict → returns undefined (chain continues)", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async (req) => ({
        requestId: req.requestId,
        decision: "allow",
      })),
    );

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result).toBeUndefined();
  });

  it("fallthrough verdict (no resolver matches inside decideCapabilityApproval) → returns undefined", async () => {
    // Register a resolver for net.egress only, but classify process.exec tool
    // Actually: with our simple pickOwner, bash→process.exec, and we have no
    // process.exec resolver → hasApprovalResolverForScope returns false → short-circuits
    setActivePluginRegistry(
      makeRegistryWithResolver("net.egress", async (req) => ({
        requestId: req.requestId,
        decision: "allow",
      })),
    );

    // bash tool classifies as process.exec, but only net.egress resolver is registered
    // → hasApprovalResolverForScope('process.exec') = false → undefined before decide
    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result).toBeUndefined();
  });

  it("deny verdict (no failureDisposition) → returns {blocked:true, kind:'veto', deniedReason:'capability-resolver', reason, params}", async () => {
    // Register a resolver so hasApprovalResolverForScope('process.exec') = true.
    // Then mock decideCapabilityApproval to return deny WITHOUT failureDisposition,
    // which is a valid value of CapabilityApprovalVerdict (field is optional).
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async () => {
        throw new Error("should not be called — decideCapabilityApproval is mocked");
      }),
    );

    const capModule = await import("../plugins/capability-approval.js");
    const decideSpy = vi.spyOn(capModule, "decideCapabilityApproval").mockResolvedValueOnce({
      kind: "deny",
      requestId: "req-mocked",
      reason: "blocked-by-test-policy",
      // no failureDisposition — tests the veto branch
    });

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result).toBeDefined();
    expect(result?.blocked).toBe(true);
    expect((result as { kind: string }).kind).toBe("veto");
    expect((result as { deniedReason: string }).deniedReason).toBe("capability-resolver");
    expect((result as { reason: string }).reason).toBe("blocked-by-test-policy");
    // params MUST be non-undefined and match original
    expect((result as { params: unknown }).params).toBe(PARAMS);

    decideSpy.mockRestore();
  });

  it("deny verdict with failureDisposition:'timed_out' → returns {blocked:true, kind:'failure', disposition:'timed_out', deniedReason:'capability-resolver'}", async () => {
    // Resolver never resolves → decideCapabilityApproval will timeout → deny/timed_out
    const neverResolve = (
      _req: ApprovalRequest,
      _opts: { signal: AbortSignal; deadlineMs: number },
    ) => new Promise<ApprovalDecision>(() => {});
    setActivePluginRegistry(makeRegistryWithResolver("process.exec", neverResolve));

    const ctx = makeCtx({
      config: { approvals: { frontStageResolverTimeoutMs: 10 } },
    });

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx,
      signal: AbortSignal.timeout(5000),
    });

    expect(result).toBeDefined();
    expect(result?.blocked).toBe(true);
    expect((result as { kind: string }).kind).toBe("failure");
    expect((result as { disposition: string }).disposition).toBe("timed_out");
    expect((result as { deniedReason: string }).deniedReason).toBe("capability-resolver");
    expect((result as { params: unknown }).params).toBe(PARAMS);
  });

  it("classifier throws → uses SUPERSET_EFFECTS → decides (no crash), returns appropriate outcome", async () => {
    // Register a resolver for process.exec (SUPERSET includes process.exec).
    // Mock decideCapabilityApproval to return a clean deny (no failureDisposition) → veto.
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async () => {
        throw new Error("should not be called — decideCapabilityApproval is mocked");
      }),
    );

    // Mock classifyEffects to throw
    const classifyModule = await import("../plugins/effect-classifier.js");
    const classifySpy = vi
      .spyOn(classifyModule, "classifyEffects")
      .mockRejectedValueOnce(new Error("classifier exploded"));

    // Mock decideCapabilityApproval to return deny without failureDisposition → veto shape
    const capModule = await import("../plugins/capability-approval.js");
    const decideSpy = vi.spyOn(capModule, "decideCapabilityApproval").mockResolvedValueOnce({
      kind: "deny",
      requestId: "req-superset",
      reason: "superset-deny",
    });

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    // Should have used SUPERSET_EFFECTS → process.exec resolver → deny → veto
    expect(result).toBeDefined();
    expect(result?.blocked).toBe(true);
    expect((result as { kind: string }).kind).toBe("veto");
    expect((result as { deniedReason: string }).deniedReason).toBe("capability-resolver");
    expect((result as { params: unknown }).params).toBe(PARAMS);
    expect(classifySpy).toHaveBeenCalled();
    expect(decideSpy).toHaveBeenCalled();

    classifySpy.mockRestore();
    decideSpy.mockRestore();
  });

  it("params always carried on blocked outcome (non-undefined)", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async (req) => ({
        requestId: req.requestId,
        decision: "deny",
        reason: "params-carry-test",
      })),
    );

    const specificParams = { cmd: "specific-command", flag: true };
    const result = await runFrontStageResolver({
      toolName: "bash",
      params: specificParams,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result?.blocked).toBe(true);
    expect((result as { params: unknown }).params).toBe(specificParams);
  });

  it("REAL core: clean policy deny (matching requestId) → {kind:'veto'} (not failure), params carried", async () => {
    // End-to-end through the REAL decideCapabilityApproval (no core mock): a
    // resolver clean deny must surface as a graceful veto, activating the
    // front-stage block branch — NOT a failure/throw.
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async (req) => ({
        requestId: req.requestId,
        decision: "deny",
        reason: "clean policy deny",
      })),
    );

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result?.blocked).toBe(true);
    expect((result as { kind: string }).kind).toBe("veto");
    expect((result as { deniedReason: string }).deniedReason).toBe("capability-resolver");
    expect((result as { reason: string }).reason).toBe("clean policy deny");
    // No disposition field on a veto (graceful block).
    expect((result as { disposition?: string }).disposition).toBeUndefined();
    expect((result as { params: unknown }).params).toBe(PARAMS);
  });

  it("deny verdict with no reason → uses fallback reason string", async () => {
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async (req) => ({
        requestId: req.requestId,
        decision: "deny",
        // no reason field
      })),
    );

    const result = await runFrontStageResolver({
      toolName: "bash",
      params: PARAMS,
      ctx: makeCtx(),
      signal: AbortSignal.timeout(5000),
    });

    expect(result?.blocked).toBe(true);
    expect(typeof (result as { reason: string }).reason).toBe("string");
    expect((result as { reason: string }).reason.length).toBeGreaterThan(0);
  });
});
