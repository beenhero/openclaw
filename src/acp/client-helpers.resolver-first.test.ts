/**
 * L5.4 + L5.5 — Client-mode resolver-first tests for resolvePermissionRequest.
 *
 * STRUCTURAL GRADE (L5.5):
 *   The resolver-first branch in resolvePermissionRequest is STRUCTURAL only.
 *   In the standalone `openclaw acp client` process the plugin registry is NOT
 *   loaded (it lives server-side only). hasApprovalResolverForScope() therefore
 *   returns false → immediate fallthrough → today's human prompt (byte-unchanged).
 *
 *   These tests exercise the branch by loading a registry IN-PROCESS (embedded
 *   host topology), proving correctness IF a registry is present, but do NOT
 *   constitute a live end-to-end drill of the standalone client. The live grade
 *   for the client-mode path is STRUCTURAL until an embedded-host topology ships.
 *
 * Test matrix:
 *  1. no resolver → existing classifyAcpToolApproval logic runs, response identical
 *     to today, decideCapabilityApproval NOT called (spy).
 *  2. resolver + allow → allow response, classifyAcpToolApproval / prompt NOT consulted.
 *  3. resolver + deny  → deny response, prompt NOT consulted.
 *  4. resolver for a DIFFERENT capability (net.egress) + exec-capable toolCall →
 *     existing logic byte-unchanged (fallthrough because capability doesn't match).
 *  5. resolver throws → fallthrough to existing prompt logic (fail-open-to-human).
 *  6. no resolver + exec-capable tool → prompt IS called (regression guard).
 *  7. no resolver + readonly tool → auto-approve without prompt (regression guard).
 */
import type { RequestPermissionRequest } from "@agentclientprotocol/sdk";
import {
  __resetProofRegistryForTest,
  decideCapabilityApproval,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import type {
  ApprovalDecision,
  ApprovalRequest,
  PluginApprovalResolverRegistryRegistration,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  __resetDefaultProofLedgerForTest,
  createEmptyPluginRegistry,
  setActivePluginRegistry,
} from "openclaw/plugin-sdk/plugin-test-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolvePermissionRequest } from "./client-helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeExecPermissionRequest(
  overrides: Partial<RequestPermissionRequest> = {},
): RequestPermissionRequest {
  return {
    sessionId: "session-client-resolver-test",
    toolCall: {
      toolCallId: "tc-exec-1",
      title: "exec: echo hello",
      status: "pending",
      _meta: { toolName: "exec" },
      rawInput: { name: "exec", command: "echo hello" },
    },
    options: [
      { kind: "allow_once", name: "Allow once", optionId: "allow-once" },
      { kind: "reject_once", name: "Reject once", optionId: "reject-once" },
    ],
    ...overrides,
  };
}

function makeReadPermissionRequest(cwd: string): RequestPermissionRequest {
  return {
    sessionId: "session-client-read-test",
    toolCall: {
      toolCallId: "tc-read-1",
      title: "read: src/index.ts",
      status: "pending",
      rawInput: { path: "src/index.ts" },
    },
    options: [
      { kind: "allow_once", name: "Allow once", optionId: "allow-once" },
      { kind: "reject_once", name: "Reject once", optionId: "reject-once" },
    ],
  };
  void cwd; // used by caller as deps.cwd
}

/**
 * Register a resolver covering the given capabilities into the active registry.
 */
function registerResolver(
  capabilities: string[],
  resolve: (req: ApprovalRequest) => Promise<ApprovalDecision> | ApprovalDecision,
): void {
  const registry = createEmptyPluginRegistry();
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "test-client-resolver-plugin",
    pluginName: "test-client-resolver-plugin",
    source: "test",
    registration: {
      id: "test-client-resolver",
      description: "test resolver for L5.4 client-mode tests",
      scope: { capabilities: capabilities as ["process.exec"] },
      exclusive: true,
      resolve: async (req) => resolve(req),
    },
  };
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("resolvePermissionRequest — L5.4 resolver-first branch", () => {
  beforeEach(() => {
    __resetProofRegistryForTest();
    __resetDefaultProofLedgerForTest();
    // Start each test with an EMPTY registry → no resolver → existing logic runs.
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  // -------------------------------------------------------------------------
  // Test 1: no resolver → existing logic, decideCapabilityApproval NOT called
  // -------------------------------------------------------------------------
  it("no resolver → existing classifyAcpToolApproval logic runs, response identical to today", async () => {
    // Spy on decideCapabilityApproval — must NOT be called when no resolver.
    const decideSpy = vi.spyOn(
      await import("../plugins/capability-approval.js"),
      "decideCapabilityApproval",
    );

    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    // The existing code prompts for exec and returns reject.
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(prompt).toHaveBeenCalledWith("exec", "exec: echo hello");
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "reject-once" } });
    // decideCapabilityApproval was NOT called.
    expect(decideSpy).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Test 2: resolver + allow → allow response, prompt NOT called
  // -------------------------------------------------------------------------
  it("resolver allow → allow response, prompt NOT consulted", async () => {
    // Register an exec resolver that allows.
    registerResolver(["process.exec"], (req) => ({
      requestId: req.requestId,
      decision: "allow",
    }));

    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    // Must return the allow option without prompting.
    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "allow-once" } });
  });

  // -------------------------------------------------------------------------
  // Test 3: resolver + deny → deny response, prompt NOT called
  // -------------------------------------------------------------------------
  it("resolver deny → reject response, prompt NOT consulted", async () => {
    registerResolver(["process.exec"], () => ({
      requestId: "ignored",
      decision: "deny",
      reason: "policy deny",
    }));

    const prompt = vi.fn(async () => true);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "reject-once" } });
  });

  // -------------------------------------------------------------------------
  // Test 4: resolver for DIFFERENT capability → fallthrough to existing logic
  // -------------------------------------------------------------------------
  it("resolver for net.egress only → exec-capable toolCall falls through to prompt (existing logic)", async () => {
    // Register a resolver ONLY for net.egress, not process.exec.
    registerResolver(["net.egress"], (req) => ({
      requestId: req.requestId,
      decision: "allow",
    }));

    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    // The process.exec toolCall has no resolver → falls through → prompt is called.
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(prompt).toHaveBeenCalledWith("exec", "exec: echo hello");
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "reject-once" } });
  });

  // -------------------------------------------------------------------------
  // Test 5: resolver throws (failureDisposition deny) → reject response
  //
  // When the resolver fn throws, decideCapabilityApproval catches it and returns
  // a deny verdict with failureDisposition:'failed'. Per the plan: both clean
  // policy deny AND failure-disposition deny map to the deny/reject response.
  // The callback has no throw path; all denies (graceful + failure) → reject.
  // -------------------------------------------------------------------------
  it("resolver throws → deny verdict → reject response, prompt NOT called", async () => {
    registerResolver(["process.exec"], () => {
      throw new Error("resolver exploded");
    });

    const prompt = vi.fn(async () => true);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    // Resolver throw → decideCapabilityApproval returns deny (failureDisposition:'failed')
    // → reject response. Prompt is NOT called (resolver path handled it).
    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "reject-once" } });
  });

  // -------------------------------------------------------------------------
  // L5.5 — no resolver + exec-capable tool → prompt IS called (regression guard)
  // -------------------------------------------------------------------------
  it("L5.5 regression: no resolver + exec-capable tool → prompt IS called", async () => {
    // No registry — standalone-client topology: hasApprovalResolverForScope = false.
    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(makeExecPermissionRequest(), {
      prompt,
      log: () => {},
    });

    expect(prompt).toHaveBeenCalledTimes(1);
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "reject-once" } });
  });

  // -------------------------------------------------------------------------
  // L5.5 — no resolver + readonly-scoped tool → auto-approve (regression guard)
  // -------------------------------------------------------------------------
  it("L5.5 regression: no resolver + readonly-scoped read tool → auto-approved without prompt", async () => {
    const cwd = "/tmp/openclaw-acp-cwd";
    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(makeReadPermissionRequest(cwd), {
      prompt,
      log: () => {},
      cwd,
    });

    // read inside cwd → auto-approve without prompt.
    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "selected", optionId: "allow-once" } });
  });

  // -------------------------------------------------------------------------
  // Edge: allow response when allow option is missing → cancelled
  // -------------------------------------------------------------------------
  it("resolver allow but no allow option in request → cancelled (not error)", async () => {
    registerResolver(["process.exec"], (req) => ({
      requestId: req.requestId,
      decision: "allow",
    }));

    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(
      makeExecPermissionRequest({
        // Only reject option available — no allow option.
        options: [{ kind: "reject_once", name: "Reject", optionId: "reject-only" }],
      }),
      { prompt, log: () => {} },
    );

    // Resolver said allow but no allow option exists → cancelled (mirrors plan gotcha).
    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "cancelled" } });
  });

  // -------------------------------------------------------------------------
  // Edge: deny response when reject option is missing → cancelled
  // -------------------------------------------------------------------------
  it("resolver deny but no reject option in request → cancelled", async () => {
    registerResolver(["process.exec"], () => ({
      requestId: "ignored",
      decision: "deny",
    }));

    const prompt = vi.fn(async () => false);
    const res = await resolvePermissionRequest(
      makeExecPermissionRequest({
        // Only allow option available — no reject option.
        options: [{ kind: "allow_once", name: "Allow", optionId: "allow-only" }],
      }),
      { prompt, log: () => {} },
    );

    // Resolver said deny but no reject option exists → cancelled.
    expect(prompt).not.toHaveBeenCalled();
    expect(res).toEqual({ outcome: { outcome: "cancelled" } });
  });
});
