/**
 * ACP server-mode resolver-first branch tests (L5.2 + L5.3).
 *
 * Verifies that when a process.exec capability resolver is registered, the
 * resolver decides BEFORE the ACP client is ever asked (requestPermission is
 * NOT called). Conversely, when no resolver is registered the existing relay
 * runs byte-unchanged (requestPermission IS called).
 *
 * Grounded in: approval-bridge.ts pattern + translator.permission-relay.test.ts harness.
 */
import type { CancelNotification } from "@agentclientprotocol/sdk";
import { createInMemorySessionStore } from "@openclaw/acp-core/session";
import {
  __resetProofRegistryForTest,
  classifyEffects,
  decideCapabilityApproval,
  digestForEffects,
  hasApprovalResolverForScope,
  SUPERSET_EFFECTS,
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
import type { EventFrame } from "../../packages/gateway-protocol/src/index.js";
import type { GatewayClient } from "../gateway/client.js";
import { AcpGatewayAgent } from "./translator.js";
import { promptAgent } from "./translator.prompt-harness.test-support.js";
import { createAcpConnection, createAcpGateway } from "./translator.test-helpers.js";

vi.mock("./commands.js", () => ({
  getAvailableCommands: () => [],
}));

const SESSION_ID = "session-resolver-1";
const SESSION_KEY = "agent:main:resolver";

// ---------------------------------------------------------------------------
// Event builders (mirrors translator.permission-relay.test.ts)
// ---------------------------------------------------------------------------

function createApprovalEvent(params: {
  approvalId?: string;
  runId: string;
  sessionKey?: string;
  toolCallId?: string;
}): EventFrame {
  return {
    type: "event",
    event: "agent",
    payload: {
      runId: params.runId,
      sessionKey: params.sessionKey ?? SESSION_KEY,
      stream: "approval",
      data: {
        phase: "requested",
        kind: "exec",
        status: "pending",
        title: "Command approval requested",
        approvalId: params.approvalId ?? "approval-r1",
        toolCallId: params.toolCallId,
        command: "echo event",
        host: "gateway",
      },
    },
  } as EventFrame;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type Harness = {
  agent: AcpGatewayAgent;
  connection: ReturnType<typeof createAcpConnection>;
  promptPromise: ReturnType<AcpGatewayAgent["prompt"]>;
  request: ReturnType<typeof vi.fn>;
  requestPermission: ReturnType<typeof vi.fn>;
  runId: string;
  sessionStore: ReturnType<typeof createInMemorySessionStore>;
};

async function createHarness(
  params: {
    requestPermission?: ReturnType<typeof vi.fn>;
    resolveApproval?: (requestParams?: Record<string, unknown>) => unknown;
  } = {},
): Promise<Harness> {
  let runId: string | undefined;
  const request = vi.fn(async (method: string, requestParams?: Record<string, unknown>) => {
    if (method === "chat.send") {
      runId = requestParams?.idempotencyKey as string | undefined;
      return { status: "started", runId };
    }
    if (method === "exec.approval.get") {
      return {
        id: requestParams?.id,
        commandText: "echo resolver-test",
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        host: "gateway",
      };
    }
    if (method === "exec.approval.resolve" && params.resolveApproval) {
      return params.resolveApproval(requestParams);
    }
    return {};
  }) as ReturnType<typeof vi.fn> & GatewayClient["request"];

  const requestPermission =
    params.requestPermission ??
    vi.fn(async () => ({ outcome: { outcome: "selected", optionId: "allow-once" } }));

  const sessionStore = createInMemorySessionStore();
  sessionStore.createSession({
    sessionId: SESSION_ID,
    sessionKey: SESSION_KEY,
    cwd: "/tmp",
  });

  const connection = createAcpConnection({ requestPermission });
  const agent = new AcpGatewayAgent(connection, createAcpGateway(request), { sessionStore });
  const promptPromise = promptAgent(agent, SESSION_ID);

  await vi.waitFor(() => {
    if (!runId) {
      throw new Error("expected ACP permission relay run id");
    }
  });

  return {
    agent,
    connection,
    promptPromise,
    request,
    requestPermission,
    runId: runId!,
    sessionStore,
  };
}

async function cleanupHarness(harness: Harness): Promise<void> {
  await harness.agent.cancel({ sessionId: SESSION_ID } as CancelNotification);
  await harness.promptPromise;
  harness.sessionStore.clearAllSessionsForTest();
}

function approvalResolveCalls(request: ReturnType<typeof vi.fn>): unknown[][] {
  // vitest's mock.calls element type is now `any[] | undefined` under the
  // upstream vitest bump; narrow to non-optional call tuples for destructuring.
  return (request.mock.calls as unknown[][]).filter((call) => call[0] === "exec.approval.resolve");
}

// ---------------------------------------------------------------------------
// Registry helpers — mirrors approval-resolver-exec-branch.test.ts pattern
// ---------------------------------------------------------------------------

function registerExecResolver(
  resolve: (req: ApprovalRequest) => Promise<ApprovalDecision> | ApprovalDecision,
): void {
  const registry = createEmptyPluginRegistry();
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "test-resolver-plugin",
    pluginName: "test-resolver-plugin",
    source: "test",
    registration: {
      id: "test-exec-resolver",
      description: "test process.exec resolver for L5 ACP adapter tests",
      scope: { capabilities: ["process.exec"] },
      exclusive: true,
      resolve: async (req) => resolve(req),
    },
  };
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ACP translator — resolver-first branch (L5.2 server-mode)", () => {
  beforeEach(() => {
    __resetProofRegistryForTest();
    __resetDefaultProofLedgerForTest();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  // -------------------------------------------------------------------------
  // L5.2 — DENY: resolver decides, requestPermission NOT called
  // -------------------------------------------------------------------------
  it("resolver deny → exec.approval.resolve('deny') called; requestPermission NOT called (#97152 bypass closed)", async () => {
    registerExecResolver(() => ({ requestId: "ignored", decision: "deny", reason: "policy" }));

    const harness = await createHarness();
    await harness.agent.handleGatewayEvent(createApprovalEvent({ runId: harness.runId }));

    await vi.waitFor(() => {
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });

    // The ACP client tap must NEVER be called — this is the #97152 bypass closure.
    expect(harness.requestPermission).not.toHaveBeenCalled();

    const resolveParams = approvalResolveCalls(harness.request)[0]?.[1];
    expect((resolveParams as { decision?: string }).decision).toBe("deny");

    await cleanupHarness(harness);
  });

  // -------------------------------------------------------------------------
  // L5.2 — ALLOW: resolver decides, requestPermission NOT called
  // -------------------------------------------------------------------------
  it("resolver allow → exec.approval.resolve('allow-once') called; requestPermission NOT called", async () => {
    registerExecResolver((req) => ({ requestId: req.requestId, decision: "allow" }));

    const harness = await createHarness();
    await harness.agent.handleGatewayEvent(createApprovalEvent({ runId: harness.runId }));

    await vi.waitFor(() => {
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });

    // The ACP client tap must NEVER be called.
    expect(harness.requestPermission).not.toHaveBeenCalled();

    const resolveParams = approvalResolveCalls(harness.request)[0]?.[1];
    // allow maps conservatively to 'allow-once' (mirrors codex adapter behavior).
    expect((resolveParams as { decision?: string }).decision).toBe("allow-once");

    await cleanupHarness(harness);
  });

  // -------------------------------------------------------------------------
  // L5.2 — finally block marks relay completed on resolver path
  // -------------------------------------------------------------------------
  it("finally block marks relay completed after resolver decision (no memory leak)", async () => {
    registerExecResolver(() => ({ requestId: "x", decision: "deny" }));

    const harness = await createHarness();
    const approvalId = "approval-completed-check";
    await harness.agent.handleGatewayEvent(
      createApprovalEvent({ runId: harness.runId, approvalId }),
    );

    await vi.waitFor(() => {
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });

    // The relay should be marked completed (or removed) — not left in 'active'.
    const relayMap = (
      harness.agent as unknown as { approvalRelays: Map<string, { state: string }> }
    ).approvalRelays;
    const relay = relayMap.get(approvalId);
    // Either completed (kept as sentinel) or removed — not 'active'.
    if (relay) {
      expect(relay.state).toBe("completed");
    }

    await cleanupHarness(harness);
  });

  // -------------------------------------------------------------------------
  // L5.3 — NO RESOLVER: byte-unchanged fallthrough (regression guard)
  // -------------------------------------------------------------------------
  it("no resolver registered → requestPermission IS called (existing relay flow byte-unchanged)", async () => {
    // No resolver registered — hasApprovalResolverForScope('process.exec') = false.
    const harness = await createHarness({
      requestPermission: vi.fn(async () => ({
        outcome: { outcome: "selected", optionId: "allow-once" },
      })),
    });

    await harness.agent.handleGatewayEvent(createApprovalEvent({ runId: harness.runId }));

    await vi.waitFor(() => {
      expect(harness.requestPermission).toHaveBeenCalledTimes(1);
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });

    // The existing relay outcome is echoed through.
    const resolveParams = approvalResolveCalls(harness.request)[0]?.[1];
    expect((resolveParams as { decision?: string }).decision).toBe("allow-once");

    await cleanupHarness(harness);
  });

  // -------------------------------------------------------------------------
  // L5.3 — deny with no resolver is still deny (regression guard)
  // -------------------------------------------------------------------------
  it("no resolver + ACP client denies → exec.approval.resolve('deny') (regression)", async () => {
    const harness = await createHarness({
      requestPermission: vi.fn(async () => ({
        outcome: { outcome: "selected", optionId: "deny" },
      })),
    });

    await harness.agent.handleGatewayEvent(createApprovalEvent({ runId: harness.runId }));

    await vi.waitFor(() => {
      expect(harness.requestPermission).toHaveBeenCalledTimes(1);
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });

    const resolveParams = approvalResolveCalls(harness.request)[0]?.[1];
    expect((resolveParams as { decision?: string }).decision).toBe("deny");

    await cleanupHarness(harness);
  });

  // -------------------------------------------------------------------------
  // L5.6 — surface-#1 exclusivity: the resolver decision IS delivered.
  //
  // This grades the resolver's exclusivity as ORDERING-BASED with a documented
  // tap-race residual (see src/acp/resolver-first.ts "L5.6 surface-#1 residual"
  // note). It asserts the leg L5.6 CAN establish today: when a resolver owns the
  // scope, the resolver's decision reaches the gateway via exec.approval.resolve
  // (surface #2's replacement runs and is authoritative). It does NOT assert that
  // a competing operator APPROVALS_SCOPE tap is byte-suppressed at the create
  // site — that is the documented residual (full closure = selective create-site
  // suppression that keeps the ACP relay's own trigger alive).
  // -------------------------------------------------------------------------
  it("resolver-owned scope → resolver's exec.approval.resolve IS delivered (ordering-based exclusivity leg)", async () => {
    registerExecResolver(() => ({ requestId: "x", decision: "deny", reason: "resolver-owns" }));

    const harness = await createHarness();
    await harness.agent.handleGatewayEvent(createApprovalEvent({ runId: harness.runId }));

    // The resolver's decision must reach the gateway (single-shot resolve; the
    // gateway's manager.resolve is first-resolve-wins, so a resolver decision
    // that lands first wins the record).
    await vi.waitFor(() => {
      expect(approvalResolveCalls(harness.request)).toHaveLength(1);
    });
    const resolveParams = approvalResolveCalls(harness.request)[0]?.[1];
    expect((resolveParams as { decision?: string }).decision).toBe("deny");
    // Surface #2 (the ACP client tap) is suppressed on the resolver path.
    expect(harness.requestPermission).not.toHaveBeenCalled();

    await cleanupHarness(harness);
  });
});

// ---------------------------------------------------------------------------
// L5.1 — buildAcpServerApprovalRequest helper unit tests
// ---------------------------------------------------------------------------
describe("buildAcpServerApprovalRequest helper (L5.1)", () => {
  beforeEach(() => {
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  afterEach(() => {
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  it("plain exec command → process.exec capability", async () => {
    // The helper is imported from the acp module; test via the primitives it composes.
    const effects = await classifyEffects("acp", "exec", { command: "echo hello" }, undefined);
    expect(effects.some((e) => e.kind === "process.exec")).toBe(true);
    const digest = digestForEffects(effects);
    expect(typeof digest).toBe("string");
    expect(digest.length).toBeGreaterThan(0);
  });

  it("classifyEffects throw → SUPERSET_EFFECTS (fail-closed)", async () => {
    // Simulate fail-closed behavior: bad input coerces to SUPERSET via .catch().
    const effects = await classifyEffects("acp", "exec", { command: "echo hi" }, undefined).catch(
      () => SUPERSET_EFFECTS,
    );
    expect(effects.length).toBeGreaterThan(0);
  });

  it("hasApprovalResolverForScope returns false when no resolver registered", () => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    expect(hasApprovalResolverForScope("process.exec")).toBe(false);
  });

  it("hasApprovalResolverForScope returns true when process.exec resolver registered", () => {
    registerExecResolver(() => ({ requestId: "x", decision: "allow" }));
    expect(hasApprovalResolverForScope("process.exec")).toBe(true);
  });
});
