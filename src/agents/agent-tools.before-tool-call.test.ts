/**
 * L4.7 — No-resolver byte-unchanged regression lock for runBeforeToolCallHook.
 *
 * Proves that with ZERO resolvers registered, runBeforeToolCallHook outcomes are
 * byte-identical to the pre-L4.6 baseline. Also proves resolver-deny pre-empts
 * both the trusted-policy (:1637) and plugin-hook (:1720) veto points.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getGlobalHookRunner, resetGlobalHookRunner } from "../plugins/hook-runner-global.js";
import type { HookRunner } from "../plugins/hooks.js";
import type { ApprovalDecision, ApprovalRequest } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { runBeforeToolCallHook } from "./agent-tools.before-tool-call.js";

// ---------------------------------------------------------------------------
// Mock getGlobalHookRunner so we can control before_tool_call hook behavior.
// ---------------------------------------------------------------------------

vi.mock("../plugins/hook-runner-global.js", async () => {
  const actual = await vi.importActual<typeof import("../plugins/hook-runner-global.js")>(
    "../plugins/hook-runner-global.js",
  );
  return {
    ...actual,
    getGlobalHookRunner: vi.fn(),
  };
});

const mockGetGlobalHookRunner = vi.mocked(getGlobalHookRunner);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        source: "test" as const,
        registration: {
          id: `test-${capability}-resolver`,
          description: `Test ${capability} approval resolver`,
          scope: { capabilities: [capability] as string[] },
          exclusive: true as const,
          resolve,
        },
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// L4.7.1 — Parametrized baseline: no resolver → outcomes byte-identical
// ---------------------------------------------------------------------------

describe("L4.7 — no-resolver byte-unchanged regression lock", () => {
  let runBeforeToolCallMock: ReturnType<typeof vi.fn<HookRunner["runBeforeToolCall"]>>;
  let hookRunner: Pick<HookRunner, "hasHooks" | "runBeforeToolCall">;

  beforeEach(() => {
    // No resolver registered — default empty plugin registry.
    setActivePluginRegistry(createEmptyPluginRegistry());
    resetGlobalHookRunner();

    runBeforeToolCallMock = vi.fn<HookRunner["runBeforeToolCall"]>();
    hookRunner = {
      hasHooks: vi.fn<HookRunner["hasHooks"]>().mockReturnValue(true),
      runBeforeToolCall: runBeforeToolCallMock,
    };
    mockGetGlobalHookRunner.mockReturnValue(hookRunner as HookRunner);
  });

  afterEach(() => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    resetGlobalHookRunner();
  });

  it("allowed pass-through (no hooks) → {blocked:false, params} unchanged", async () => {
    // hasHooks=false → hookRunner path skipped → reaches the trivial allowed branch
    (hookRunner.hasHooks as ReturnType<typeof vi.fn>).mockReturnValue(false);

    const result = await runBeforeToolCallHook({
      toolName: "read_file",
      params: { path: "/tmp/foo.txt" },
    });

    expect(result).toEqual({ blocked: false, params: { path: "/tmp/foo.txt" } });
  });

  it("trusted-policy veto → {blocked:true, kind:'veto', deniedReason:'plugin-before-tool-call'} unchanged", async () => {
    const registry = createEmptyPluginRegistry();
    registry.trustedToolPolicies = [
      {
        pluginId: "test-tp",
        pluginName: "Test Trusted Policy",
        source: "test",
        policy: {
          id: "block-all",
          description: "Block everything",
          evaluate: () => ({ block: true, blockReason: "blocked-by-trusted-policy" }),
        },
      },
    ];
    setActivePluginRegistry(registry);
    (hookRunner.hasHooks as ReturnType<typeof vi.fn>).mockReturnValue(false);

    const params = { command: "rm -rf /tmp/test" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { agentId: "main", sessionKey: "agent:main:main" },
    });

    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "plugin-before-tool-call",
      reason: "blocked-by-trusted-policy",
      params,
    });
  });

  it("plugin-hook veto → {blocked:true, kind:'veto', deniedReason:'plugin-before-tool-call'} unchanged", async () => {
    runBeforeToolCallMock.mockResolvedValue({
      block: true,
      blockReason: "plugin-hook-blocked",
    });

    const params = { command: "deploy" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { agentId: "main", sessionKey: "agent:main:main" },
    });

    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "plugin-before-tool-call",
      reason: "plugin-hook-blocked",
      params,
    });
  });

  it("loop-critical block → {blocked:true, kind:'veto', deniedReason:'tool-loop'} unchanged", async () => {
    // Mock loadBeforeToolCallRuntime (via the runtime module) to inject a detectToolCallLoop
    // that always returns critical, simulating the loop-block path in runBeforeToolCallHook
    // without needing to organically trigger the full loop detector history.
    const runtimeModule = await import("./agent-tools.before-tool-call.runtime.js");
    const detectSpy = vi
      .spyOn(runtimeModule.beforeToolCallRuntime, "detectToolCallLoop")
      .mockReturnValue({
        stuck: true,
        level: "critical",
        detector: "known_poll_no_progress",
        count: 20,
        message: "CRITICAL: called 20 times with no progress",
      });

    (hookRunner.hasHooks as ReturnType<typeof vi.fn>).mockReturnValue(false);

    const params = { command: "poll_status" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { sessionKey: "agent:loop-test:main" },
    });

    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "tool-loop",
      reason: "CRITICAL: called 20 times with no progress",
      params,
    });

    detectSpy.mockRestore();
  });

  // L4.7.2 — Spy: decideCapabilityApproval NOT called with zero resolvers
  it("decideCapabilityApproval NOT called when no resolver is registered", async () => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    (hookRunner.hasHooks as ReturnType<typeof vi.fn>).mockReturnValue(false);

    const capModule = await import("../plugins/capability-approval.js");
    const decideSpy = vi.spyOn(capModule, "decideCapabilityApproval");

    await runBeforeToolCallHook({
      toolName: "bash",
      params: { command: "echo hi" },
      ctx: { sessionKey: "agent:main:main", agentId: "main" },
    });

    expect(decideSpy).not.toHaveBeenCalled();
    decideSpy.mockRestore();
  });

  // L4.7.3 — Resolver-deny pre-empts BOTH veto points
  it("resolver-deny → {blocked:true, kind:'veto', deniedReason:'capability-resolver'} pre-empts plugin-hook", async () => {
    // Register a resolver so hasApprovalResolverForScope fires, then mock
    // decideCapabilityApproval to return deny WITHOUT failureDisposition → veto shape.
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async () => {
        throw new Error("should not be called — decideCapabilityApproval is mocked");
      }),
    );

    const capModule = await import("../plugins/capability-approval.js");
    const decideSpy = vi.spyOn(capModule, "decideCapabilityApproval").mockResolvedValueOnce({
      kind: "deny",
      requestId: "req-test",
      reason: "test-deny",
      // no failureDisposition → veto shape in runFrontStageResolver
    });

    // Also register a plugin-hook that would veto with a DIFFERENT deniedReason.
    // If the front-stage (L4.6) properly pre-empts, we should see 'capability-resolver',
    // NOT 'plugin-before-tool-call'.
    runBeforeToolCallMock.mockResolvedValue({
      block: true,
      blockReason: "plugin-hook-would-have-blocked",
    });

    const params = { command: "rm -rf /" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { sessionKey: "agent:main:main", agentId: "main" },
    });

    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "capability-resolver",
      reason: "test-deny",
      params,
    });
    // The plugin-hook MUST NOT have been reached
    expect(runBeforeToolCallMock).not.toHaveBeenCalled();

    decideSpy.mockRestore();
  });

  // L4.7.4 — Resolver-allow → chain continues (plugin-hook still runs)
  it("resolver-allow → chain continues, plugin-hook veto fires with deniedReason:'plugin-before-tool-call'", async () => {
    // Register an allow resolver
    setActivePluginRegistry(
      makeRegistryWithResolver("process.exec", async (req) => ({
        requestId: req.requestId,
        decision: "allow",
      })),
    );

    // Plugin-hook vetoes — should still run after allow
    runBeforeToolCallMock.mockResolvedValue({
      block: true,
      blockReason: "plugin-hook-after-allow",
    });

    const params = { command: "safe-cmd" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { sessionKey: "agent:main:main", agentId: "main" },
    });

    // The plugin-hook ran and vetoed
    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "plugin-before-tool-call",
      reason: "plugin-hook-after-allow",
      params,
    });
    // The hook DID run
    expect(runBeforeToolCallMock).toHaveBeenCalledTimes(1);
  });

  // L4.7.5 — No-sessionKey path is byte-unchanged (front-stage guard skips)
  it("no sessionKey → runFrontStageResolver NOT consulted, outcome identical to baseline", async () => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    (hookRunner.hasHooks as ReturnType<typeof vi.fn>).mockReturnValue(false);

    // Spy on runFrontStageResolver to confirm it's not called
    const frontStageModule = await import("./front-stage-resolver.js");
    const frontStageSpy = vi.spyOn(frontStageModule, "runFrontStageResolver");

    const params = { path: "/tmp/file.txt" };
    const result = await runBeforeToolCallHook({
      toolName: "read_file",
      params,
      // ctx has no sessionKey
      ctx: { agentId: "main" },
    });

    expect(result).toEqual({ blocked: false, params });
    expect(frontStageSpy).not.toHaveBeenCalled();

    frontStageSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// L4.7.3b — trusted-policy veto pre-emption (second veto point check)
// ---------------------------------------------------------------------------

describe("L4.7 — resolver-deny pre-empts trusted-policy veto point", () => {
  let runBeforeToolCallMock: ReturnType<typeof vi.fn<HookRunner["runBeforeToolCall"]>>;
  let hookRunner: Pick<HookRunner, "hasHooks" | "runBeforeToolCall">;

  beforeEach(() => {
    resetGlobalHookRunner();
    runBeforeToolCallMock = vi.fn<HookRunner["runBeforeToolCall"]>();
    hookRunner = {
      hasHooks: vi.fn<HookRunner["hasHooks"]>().mockReturnValue(false),
      runBeforeToolCall: runBeforeToolCallMock,
    };
    mockGetGlobalHookRunner.mockReturnValue(hookRunner as HookRunner);
  });

  afterEach(() => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    resetGlobalHookRunner();
  });

  it("resolver-deny pre-empts trusted-policy veto → deniedReason is 'capability-resolver' not 'plugin-before-tool-call'", async () => {
    // Register both a deny resolver stub AND a blocking trusted policy.
    // Mock decideCapabilityApproval to return deny without failureDisposition → veto shape.
    // The front-stage (resolver-first) must win over the trusted-policy veto.
    const registry = createEmptyPluginRegistry();
    registry.trustedToolPolicies = [
      {
        pluginId: "trusted-policy",
        pluginName: "Trusted Policy",
        source: "test",
        policy: {
          id: "block-all",
          description: "Block all tools",
          evaluate: () => ({ block: true, blockReason: "trusted-policy-blocked" }),
        },
      },
    ];
    const registryWithResolver = {
      ...registry,
      approvalResolvers: [
        {
          pluginId: "test-plugin",
          pluginName: "Test Plugin",
          source: "test" as const,
          registration: {
            id: "test-process.exec-resolver",
            description: "Test process.exec resolver",
            scope: { capabilities: ["process.exec"] as string[] },
            exclusive: true as const,
            resolve: async (): Promise<ApprovalDecision> => {
              throw new Error("should not be called — decideCapabilityApproval is mocked");
            },
          },
        },
      ],
    };
    setActivePluginRegistry(registryWithResolver);

    const capModule = await import("../plugins/capability-approval.js");
    const decideSpy = vi.spyOn(capModule, "decideCapabilityApproval").mockResolvedValueOnce({
      kind: "deny",
      requestId: "req-trusted-policy-test",
      reason: "capability-resolver-denied",
      // no failureDisposition → veto shape
    });

    const params = { command: "dangerous" };
    const result = await runBeforeToolCallHook({
      toolName: "bash",
      params,
      ctx: { sessionKey: "agent:main:main", agentId: "main" },
    });

    // Front-stage resolver should have fired and denied before trusted-policy
    expect(result).toEqual({
      blocked: true,
      kind: "veto",
      deniedReason: "capability-resolver",
      reason: "capability-resolver-denied",
      params,
    });

    decideSpy.mockRestore();
  });
});
