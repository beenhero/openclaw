/**
 * M3 — native × process.exec front-stage enforcement test.
 *
 * Mirrors web-fetch-net-egress-gate.test.ts but for a process.exec resolver,
 * proving that wrapToolWithBeforeToolCallHook short-circuits execute() on a
 * DENY when the capability is process.exec (not just net.egress).
 *
 * Evidence grade before this test: "LIVE-enforced" was backed only by the
 * net.egress E2E (web_fetch) and the codex integration tests. This test makes
 * native × process.exec a genuine in-harness enforcement test at the same tier
 * as the web_fetch one — the wrapper short-circuits execute() on a process.exec
 * deny, the execute spy is NEVER called.
 *
 * Design: we build a minimal fake tool whose name ("command") maps to
 * process.exec in EXEC_CAPABLE_TOOL_NAMES (same as the "exec" entry), register
 * a process.exec resolver, wrap the tool, and assert DENY → execute spy NOT
 * called + blocked result; ALLOW → execute spy IS called.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetDefaultProofLedgerForTest,
  setActivePluginRegistry,
} from "../plugin-sdk/plugin-test-runtime.js";
import type { ApprovalDecision, ApprovalRequest } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import type { PluginApprovalResolverRegistryRegistration } from "../plugins/registry-types.js";
import { wrapToolWithBeforeToolCallHook } from "./agent-tools.before-tool-call.js";
import { createStubTool } from "./test-helpers/agent-tool-stubs.js";
import type { AnyAgentTool } from "./tools/common.js";

// ---------------------------------------------------------------------------
// Registry helper — register a process.exec resolver on the active registry
// ---------------------------------------------------------------------------

function registerProcessExecResolver(
  resolve: (req: ApprovalRequest) => Promise<ApprovalDecision> | ApprovalDecision,
): { seen: ApprovalRequest[] } {
  const seen: ApprovalRequest[] = [];
  const registry = createEmptyPluginRegistry();
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "test-process-exec-plugin",
    pluginName: "test-process-exec-plugin",
    source: "test",
    registration: {
      id: "test-process-exec-resolver",
      description: "test process.exec resolver",
      scope: { capabilities: ["process.exec"] },
      exclusive: true,
      resolve: async (req, _opts) => {
        seen.push(req);
        return resolve(req);
      },
    },
  };
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
  return { seen };
}

// ---------------------------------------------------------------------------
// Minimal fake exec tool — "command" is in EXEC_CAPABLE_TOOL_NAMES, so
// classifyEffects → Tier-A → [{kind:"process.exec", command:...}].
// The execute function is a spy; we assert it is/isn't called.
// ---------------------------------------------------------------------------

const TEST_COMMAND = "/bin/ls /tmp";

function createFakeExecTool(): { tool: AnyAgentTool; executeSpy: ReturnType<typeof vi.fn> } {
  const executeSpy = vi.fn().mockResolvedValue({ output: "fake output" });
  // Base on the canonical stub (name/label/description/parameters) and override
  // execute with the spy — robust to AgentTool shape changes.
  const tool: AnyAgentTool = {
    ...createStubTool("command"),
    description: "fake exec tool for testing",
    execute: executeSpy,
  };
  return { tool, executeSpy };
}

// ---------------------------------------------------------------------------
// Minimal HookContext with sessionKey (required for front-stage to fire).
// The front-stage guard checks `if (args.ctx?.sessionKey)` — without it,
// runFrontStageResolver is never called.
// ---------------------------------------------------------------------------

const TEST_CTX = {
  sessionKey: "agent:test-process-exec:main",
  runId: "run-process-exec-gate",
  agentId: "test-agent",
} as const;

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("process.exec native gate (M3 — #97152 front-stage enforcement)", () => {
  beforeEach(() => {
    // Fresh InMemory proof ledger so the front-stage durable-ledger default never
    // touches the real agent dir.
    __resetDefaultProofLedgerForTest();
    // Clear the resolver registry before each test.
    setActivePluginRegistry(createEmptyPluginRegistry());
  });

  afterEach(() => {
    setActivePluginRegistry(createEmptyPluginRegistry());
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Test 1 — DENY: a clean policy deny blocks execute() gracefully.
  //
  // A resolver returning decision:"deny" with the correct requestId causes
  // wrapToolWithBeforeToolCallHook to return a graceful BLOCKED RESULT (not
  // throw) before calling execute(). The execute spy is NEVER called.
  // -------------------------------------------------------------------------

  it("DENY (clean policy): resolver deny → graceful blocked result, executeSpy NOT called", async () => {
    const { seen } = registerProcessExecResolver((req) => ({
      requestId: req.requestId,
      decision: "deny",
      reason: "blocked by policy",
    }));

    const { tool, executeSpy } = createFakeExecTool();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    // A clean deny is a DECISION → front-stage veto → graceful blocked RESULT.
    const result = await wrapped.execute?.("call-deny", { command: TEST_COMMAND });
    const details = (result as { details?: { status?: unknown; deniedReason?: unknown } }).details;
    expect(details?.status).toBe("blocked");
    expect(details?.deniedReason).toBe("capability-resolver");

    // THE KEY ASSERTION: execute() was NEVER called — the block is enforced.
    expect(executeSpy).not.toHaveBeenCalled();

    // AND: the resolver observed the request with process.exec effects containing the command.
    expect(seen).toHaveLength(1);
    const req = seen[0]!;
    expect(req.capability).toBe("process.exec");
    const execEffect = req.effects.find((e) => e.kind === "process.exec");
    expect(execEffect).toBeDefined();
    if (execEffect && "command" in execEffect) {
      expect(execEffect.command).toBe(TEST_COMMAND);
    }
  });

  // -------------------------------------------------------------------------
  // Test 2 — FAILURE (requestId mismatch): still throws, execute NOT called.
  //
  // A genuine protocol failure (wrong requestId echoed) → fail-closed throw.
  // The execute spy is still NEVER called — fail-closed holds here too.
  // -------------------------------------------------------------------------

  it("FAILURE (requestId mismatch): resolver echoes wrong id → throws, executeSpy NOT called", async () => {
    registerProcessExecResolver(() => ({
      requestId: "WRONG-request-id",
      decision: "allow",
    }));

    const { tool, executeSpy } = createFakeExecTool();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    // Protocol failure → front-stage failure → throw.
    await expect(wrapped.execute?.("call-mismatch", { command: TEST_COMMAND })).rejects.toThrow();

    // Fail-closed: execute was never called.
    expect(executeSpy).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Test 3 — ALLOW: resolver allow → execute IS called.
  // -------------------------------------------------------------------------

  it("ALLOW: resolver allow → executeSpy IS called, result is not a block", async () => {
    registerProcessExecResolver((req) => ({
      requestId: req.requestId,
      decision: "allow",
    }));

    const { tool, executeSpy } = createFakeExecTool();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    await wrapped.execute?.("call-allow", { command: TEST_COMMAND });

    // Execute ran.
    expect(executeSpy).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // Test 4 — NO resolver: empty registry → execute runs normally.
  // -------------------------------------------------------------------------

  it("NO resolver: empty registry → execute runs normally, no block", async () => {
    // Registry is already empty from beforeEach.

    const { tool, executeSpy } = createFakeExecTool();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    await wrapped.execute?.("call-noResolver", { command: TEST_COMMAND });

    // Without a resolver, execute runs normally.
    expect(executeSpy).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // Test 5 — No sessionKey: front-stage guard skips, execute runs even with
  // a deny resolver registered.
  // -------------------------------------------------------------------------

  it("no sessionKey in ctx → front-stage guard skips even with deny resolver, execute runs", async () => {
    // Register a deny resolver — but no sessionKey means it is never consulted.
    registerProcessExecResolver(() => ({
      requestId: "unreachable",
      decision: "deny",
      reason: "should never fire",
    }));

    const { tool, executeSpy } = createFakeExecTool();
    // ctx WITHOUT sessionKey → front-stage guard skips runFrontStageResolver.
    const ctxWithoutSessionKey = {
      runId: "run-no-session-key",
      agentId: "test-agent",
    };
    const wrapped = wrapToolWithBeforeToolCallHook(tool, ctxWithoutSessionKey, {
      emitDiagnostics: false,
    });

    await wrapped.execute?.("call-noKey", { command: TEST_COMMAND });

    // Execute ran (front-stage was not consulted).
    expect(executeSpy).toHaveBeenCalledTimes(1);
  });
});
