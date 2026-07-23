// Codex tests cover the exclusive process.exec approval-resolver decision branch.
import {
  callGatewayTool,
  hasNativeHookRelayInvocation,
  invokeNativeHookRelay,
  resolveNativeHookRelayDeferredToolApproval,
  runBeforeToolCallHook,
  __resetProofRegistryForTest,
  type EmbeddedRunAttemptParams,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import type {
  ApprovalDecision,
  ApprovalRequest,
  PluginApprovalResolverRegistryRegistration,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  createEmptyPluginRegistry,
  setActivePluginRegistry,
} from "openclaw/plugin-sdk/plugin-test-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handleCodexAppServerApprovalRequest } from "./approval-bridge.js";
import type { JsonObject } from "./protocol.js";

// Neutralize the gateway + trusted-tool hook + native-relay so the only decision
// surface under test is the resolver branch. The approval-resolver retrieval helpers
// (hasApprovalResolverForScope / getApprovalResolverForScope) are NOT mocked here:
// decideCapabilityApproval (the core primitive) imports them directly from
// approval-resolver.ts, bypassing the barrel, so barrel mocks do not intercept
// those calls. The TOCTOU case uses a poisoned registry entry instead.
vi.mock("openclaw/plugin-sdk/agent-harness-runtime", async (importOriginal) => {
  const actual = await importOriginal<typeof import("openclaw/plugin-sdk/agent-harness-runtime")>();
  return {
    ...actual,
    callGatewayTool: vi.fn(),
    hasNativeHookRelayInvocation: vi.fn(() => false),
    invokeNativeHookRelay: vi.fn(),
    resolveNativeHookRelayDeferredToolApproval: vi.fn(),
    runBeforeToolCallHook: vi.fn(async ({ params }: { params: unknown }) => ({
      blocked: false,
      params,
    })),
  };
});

vi.mock("openclaw/plugin-sdk/agent-harness-exec-review-runtime", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("openclaw/plugin-sdk/agent-harness-exec-review-runtime")
  >()),
  reviewExecRequestWithConfiguredModel: vi.fn(),
}));

const mockCallGatewayTool = vi.mocked(callGatewayTool);
const mockHasNativeHookRelayInvocation = vi.mocked(hasNativeHookRelayInvocation);
const mockRunBeforeToolCallHook = vi.mocked(runBeforeToolCallHook);

const WORKSPACE_DIR = "/tmp/resolver-exec-workspace";

function paramsForRun(): EmbeddedRunAttemptParams {
  return {
    agentId: "agent-1",
    sessionKey: "session-1",
    runId: "run-1",
    workspaceDir: WORKSPACE_DIR,
    onAgentEvent: vi.fn(),
  } as unknown as EmbeddedRunAttemptParams;
}

function requestParams(command = "/bin/bash -lc 'rm -rf /tmp/x'"): JsonObject {
  return {
    threadId: "thread-1",
    turnId: "turn-1",
    itemId: "cmd-1",
    command,
    cwd: WORKSPACE_DIR,
  };
}

/**
 * Registers a single process.exec resolver on the active plugin registry and
 * returns the requests the resolver observed so tests can echo requestId.
 */
function registerResolver(
  resolve: (req: ApprovalRequest) => Promise<ApprovalDecision> | ApprovalDecision,
): { seen: ApprovalRequest[] } {
  const seen: ApprovalRequest[] = [];
  const registry = createEmptyPluginRegistry();
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "test-plugin",
    pluginName: "test-plugin",
    source: "test",
    registration: {
      id: "test-resolver",
      description: "test process.exec resolver",
      scope: { capabilities: ["process.exec"] },
      exclusive: true,
      resolve: async (req) => {
        seen.push(req);
        return resolve(req);
      },
    },
  };
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
  return { seen };
}

async function drive(command?: string): Promise<unknown> {
  return handleCodexAppServerApprovalRequest({
    method: "item/commandExecution/requestApproval",
    requestParams: requestParams(command),
    paramsForRun: paramsForRun(),
    threadId: "thread-1",
    turnId: "turn-1",
  });
}

describe("approval-bridge process.exec resolver branch", () => {
  beforeEach(() => {
    mockCallGatewayTool.mockReset();
    mockHasNativeHookRelayInvocation.mockReset();
    mockHasNativeHookRelayInvocation.mockReturnValue(false);
    mockRunBeforeToolCallHook.mockReset();
    mockRunBeforeToolCallHook.mockImplementation(async ({ params }) => ({
      blocked: false,
      params,
    }));
    __resetProofRegistryForTest();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  it("resolver deny → decline, and neither the trusted-tool hook nor the human tap is reached", async () => {
    const { seen } = registerResolver((req) => ({
      requestId: req.requestId,
      decision: "deny",
      reason: "policy denied",
    }));

    const response = await drive();

    expect(response).toEqual({ decision: "decline" });
    // Structural exclusivity: the human tap (plugin.approval.request/waitDecision
    // over the gateway) is never dispatched, and the trusted-tool hook is skipped.
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
    expect(mockRunBeforeToolCallHook).not.toHaveBeenCalled();
    expect(seen).toHaveLength(1);
    expect(seen[0]?.capability).toBe("process.exec");
    expect(seen[0]?.effect.command).toBe("/bin/bash -lc 'rm -rf /tmp/x'");
    expect(seen[0]?.effect.kind).toBe("process.exec");
    expect(seen[0]?.toolName).toBe("exec");
    expect(seen[0]?.paramsDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    // The opaque requestId is generated gateway-side, NOT the codex approvalId.
    expect(seen[0]?.requestId).not.toBe(seen[0]?.toolCallId);
    expect(seen[0]?.toolCallId).toBe("cmd-1");
  });

  it("resolver allow → accept (approved-once), tap and trusted-tool hook skipped", async () => {
    registerResolver((req) => ({ requestId: req.requestId, decision: "allow" }));

    const response = await drive();

    expect(response).toEqual({ decision: "accept" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
    expect(mockRunBeforeToolCallHook).not.toHaveBeenCalled();
  });

  it("async resolve within the deadline is honored (allow → accept)", async () => {
    registerResolver(
      (req) =>
        new Promise<ApprovalDecision>((resolveDecision) => {
          // The resolver Promise IS the async wallet-hold; resolve on a macrotask.
          setTimeout(() => resolveDecision({ requestId: req.requestId, decision: "allow" }), 0);
        }),
    );

    expect(await drive()).toEqual({ decision: "accept" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("resolver returns a nullish verdict → fail-closed decline", async () => {
    registerResolver(() => undefined as unknown as ApprovalDecision);
    expect(await drive()).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("resolver throws → fail-closed decline", async () => {
    registerResolver(() => {
      throw new Error("resolver boom");
    });
    expect(await drive()).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("requestId echo mismatch → fail-closed decline (request-binding guard)", async () => {
    registerResolver(() => ({ requestId: "attacker-substituted", decision: "allow" }));
    expect(await drive()).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("verdict with a malformed decision (neither allow nor deny) → fail-closed decline (allow-list, not deny-list)", async () => {
    // The gate must APPROVE only on an explicit "allow"; any other decision value —
    // including an unexpected/malformed string the type forbids — fails closed.
    registerResolver((req) => ({
      requestId: req.requestId,
      // Cast through `never` to smuggle a value the ApprovalDecision type forbids.
      decision: "maybe" as never,
    }));
    expect(await drive()).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
    expect(mockRunBeforeToolCallHook).not.toHaveBeenCalled();
  });

  it("resolver that never resolves → bridge-enforced deadline denies with timed_out", async () => {
    vi.useFakeTimers();
    // The resolver hold never settles; only the bridge's deadline timer can end it.
    registerResolver(() => new Promise<ApprovalDecision>(() => {}));

    const pending = drive();
    // Advance past DEFAULT_CODEX_APPROVAL_TIMEOUT_MS (120s) so the race deadline fires.
    await vi.advanceTimersByTimeAsync(120_000);

    // A timed_out disposition maps to a decline (fail-closed), and the codex
    // approval is NOT parked forever waiting on the resolver.
    expect(await pending).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
    expect(mockRunBeforeToolCallHook).not.toHaveBeenCalled();
  });

  it("poisoned resolver entry (TOCTOU guard) → decline, never falls through to the tap", async () => {
    // Simulate the registry-swap TOCTOU at the registry level: a resolver entry
    // whose registration getter throws. decideCapabilityApproval (the core primitive
    // that now owns this guard) reads the registry directly, so the fail-closed path
    // is reached via a poisoned entry — not via barrel-mock overrides.
    const registry = createEmptyPluginRegistry();
    registry.approvalResolvers.push({
      pluginId: "poison-plugin",
      pluginName: "Poison",
      source: "test",
      get registration(): never {
        throw new Error("TOCTOU: registration unreadable");
      },
    } as unknown as (typeof registry.approvalResolvers)[0]);
    setActivePluginRegistry(registry);

    const response = await drive();

    expect(response).toEqual({ decision: "decline" });
    // Neither the trusted-tool hook nor the human tap may run — total exclusivity.
    expect(mockRunBeforeToolCallHook).not.toHaveBeenCalled();
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("abort during the resolver hold → fail-closed decline", async () => {
    const controller = new AbortController();
    registerResolver(
      (req) =>
        new Promise<ApprovalDecision>((resolveDecision) => {
          // Abort while the hold is in flight, then resolve allow. The aborted
          // signal must override the allow and deny fail-closed.
          controller.abort();
          resolveDecision({ requestId: req.requestId, decision: "allow" });
        }),
    );

    const response = await handleCodexAppServerApprovalRequest({
      method: "item/commandExecution/requestApproval",
      requestParams: requestParams(),
      paramsForRun: paramsForRun(),
      threadId: "thread-1",
      turnId: "turn-1",
      signal: controller.signal,
    });

    expect(response).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("allow whose proof was already seen → decline (single-use replay guard)", async () => {
    registerResolver((req) => ({ requestId: req.requestId, decision: "allow", proof: "proof-A" }));
    // First allow consumes proof-A → accept.
    expect(await drive("cmd-first")).toEqual({ decision: "accept" });
    // A second parked request replaying the same proof string → decline.
    expect(await drive("cmd-second")).toEqual({ decision: "decline" });
    expect(mockCallGatewayTool).not.toHaveBeenCalled();
  });

  it("no resolver registered → branch is skipped and the human tap route runs (byte-unchanged regression)", async () => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    // Unavailable tap (no approval id) → decline, exactly the existing behavior.
    mockCallGatewayTool.mockResolvedValue({ id: undefined } as never);

    const response = await drive();

    // With no resolver, control falls through: the trusted-tool hook AND the
    // human tap (gateway) MUST be reached.
    expect(mockRunBeforeToolCallHook).toHaveBeenCalledTimes(1);
    expect(mockCallGatewayTool).toHaveBeenCalled();
    expect(mockCallGatewayTool.mock.calls[0]?.[0]).toBe("plugin.approval.request");
    expect(response).toEqual({ decision: "decline" });
  });
});
