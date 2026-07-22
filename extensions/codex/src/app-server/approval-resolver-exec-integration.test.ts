// Structural mock-app-server integration for the capability-scoped process.exec
// approval-resolver seam.
//
// The load-bearing cases (deny, allow, async-hold, requestId-mismatch, no-resolver,
// promotion) drive a real `item/commandExecution/requestApproval` SERVER request through
// the WHOLE mock-app-server routing chain — turn-router → run-attempt-server-requests →
// handleApprovalRequest → handleCodexAppServerApprovalRequest — so the exclusive resolver
// branch (approval-bridge.ts) runs end-to-end against the REAL registry read (no vi.mock
// of the decision path or the resolver-retrieval seam). Verified empirically: with the
// native hook relay registered it terminally handles the command approval BEFORE the
// resolver branch, so the seam is exercised in the run posture where it owns the decision
// — the native relay disabled (`nativeHookRelay: { enabled: false }`), the alternative
// exec-gating mechanism turned off. The native relay is a SEPARATE mechanism, not this one.
//
// Three cases (deadline/timeout, abort mid-hold, and the no-resolver byte-unchanged sanity
// guard) instead invoke handleCodexAppServerApprovalRequest DIRECTLY — the exact bridge
// entry the harness routing calls one hop later — because they need a per-request signal
// or fake-timer control the mock harness's vi.waitFor-based request wait cannot provide.
// Same real resolver branch, same real registry read.
//
// STRUCTURAL grade: this proves OpenClaw routes the approval to the resolver, honors its
// verdict, binds requestId/paramsDigest, and suppresses the human tap. It does NOT prove
// codex-rs refuses to auto-run on a `decline` — that single live-confirmed leg is Task 15
// (approval-resolver-exec.live.test.ts).
import path from "node:path";
import type {
  ApprovalDecision,
  ApprovalRequest,
  ApprovalResolver,
  EmbeddedRunAttemptParams,
  PluginApprovalResolverRegistration,
  PluginApprovalResolverRegistryRegistration,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  createEmptyPluginRegistry,
  setActivePluginRegistry,
} from "openclaw/plugin-sdk/plugin-test-runtime";
import { afterEach, describe, expect, it, vi } from "vitest";
import { handleCodexAppServerApprovalRequest } from "./approval-bridge.js";
import { __resetProofRegistryForTest } from "./approval-proof-registry.js";
import { runApprovalResolverConformance } from "./approval-resolver-conformance.js";
import * as roundtrip from "./plugin-approval-roundtrip.js";
import {
  createParams,
  createStartedThreadHarness,
  extractRelayIdFromThreadRequest,
  runCodexAppServerAttempt,
  setupRunAttemptTestHooks,
  tempDir,
} from "./run-attempt-test-harness.js";

setupRunAttemptTestHooks();

afterEach(() => {
  setActivePluginRegistry(createEmptyPluginRegistry());
  __resetProofRegistryForTest();
});

// Seeds a process.exec resolver onto a fresh active plugin registry and returns the
// requests the resolver observed (so tests can assert command/paramsDigest/toolCallId).
// The bridge's registry read (hasApprovalResolverForScope/getApprovalResolverForScope)
// reads this active registry directly — no mocking of the resolver-retrieval seam.
function installResolver(resolve: ApprovalResolver): { seen: ApprovalRequest[] } {
  const seen: ApprovalRequest[] = [];
  const registration: PluginApprovalResolverRegistration = {
    id: "sigil-exec-resolver",
    description: "test process.exec resolver",
    scope: { capabilities: ["process.exec"] },
    exclusive: true,
    resolve: async (req, opts) => {
      seen.push(req);
      return resolve(req, opts);
    },
  };
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "sigil",
    pluginName: "Sigil",
    registration,
    source: "test",
  };
  const registry = createEmptyPluginRegistry();
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
  return { seen };
}

// Minimal run params for a DIRECT bridge call (handleCodexAppServerApprovalRequest) —
// used by the byte-unchanged sanity guard and the conformance driver.
function paramsForConformanceRun(): EmbeddedRunAttemptParams {
  return {
    agentId: "agent-1",
    sessionKey: "agent:main:session-1",
    runId: "run-1",
    workspaceDir: path.join(tempDir, "workspace"),
    onAgentEvent: vi.fn(),
  } as unknown as EmbeddedRunAttemptParams;
}

// The native hook relay short-circuits command approvals BEFORE the resolver branch;
// disabling it is the run posture under which the resolver owns the exec decision.
const RUN_OPTIONS = {
  nativeHookRelay: { enabled: false, events: ["pre_tool_use"] },
} as const;

const COMMAND = "/bin/bash -lc 'rm -rf /tmp/x'";

type DriveResult = {
  response: unknown;
  run: Promise<unknown>;
  harness: ReturnType<typeof createStartedThreadHarness>;
  tapSpy: ReturnType<typeof vi.spyOn>;
  workspaceDir: string;
};

// Drives ONE in-scope command-execution approval through the mock app-server and
// returns the raw wire response ({ decision: "accept" | "decline" } etc.). The caller
// completes the turn and awaits the run for a clean shutdown.
async function driveApproval(command = COMMAND, requestId = "req-exec-1"): Promise<DriveResult> {
  const tapSpy = vi.spyOn(roundtrip, "requestPluginApproval");
  const sessionFile = path.join(tempDir, "session.jsonl");
  const workspaceDir = path.join(tempDir, "workspace");
  const harness = createStartedThreadHarness();
  const run = runCodexAppServerAttempt(createParams(sessionFile, workspaceDir), RUN_OPTIONS);
  await harness.waitForMethod("turn/start");
  const response = await harness.handleServerRequest({
    id: requestId,
    method: "item/commandExecution/requestApproval",
    params: {
      threadId: "thread-1",
      turnId: "turn-1",
      itemId: "cmd-1",
      command,
      cwd: workspaceDir,
    },
  });
  return { response, run, harness, tapSpy, workspaceDir };
}

async function finish(result: Pick<DriveResult, "harness" | "run">): Promise<void> {
  await result.harness.completeTurn({ threadId: "thread-1", turnId: "turn-1" });
  await result.run;
}

describe("registerApprovalResolver process.exec (mock app-server, structural)", () => {
  it("deny → decline and the human approval tap is never dispatched", async () => {
    let seen: ApprovalRequest | undefined;
    installResolver(async (req) => {
      seen = req;
      return { requestId: req.requestId, decision: "deny", reason: "policy" };
    });
    const result = await driveApproval();
    expect(result.response).toEqual({ decision: "decline" });
    // Exclusivity: the resolver owns the decision; the human tap is never reached.
    expect(result.tapSpy).not.toHaveBeenCalled();
    // The resolver saw the fully-bound request handed by the gateway.
    expect(seen).toMatchObject({
      capability: "process.exec",
      toolName: "exec",
      command: COMMAND,
      toolCallId: "cmd-1",
    });
    // The opaque requestId is gateway-generated, NOT the codex approvalId (toolCallId).
    expect(seen?.requestId).not.toBe(seen?.toolCallId);
    expect(seen?.paramsDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    await finish(result);
  });

  it("allow → accept (approved-once), reaching buildApprovalResponse not the human tap", async () => {
    installResolver(async (req) => ({ requestId: req.requestId, decision: "allow" }));
    const result = await driveApproval();
    expect(result.response).toEqual({ decision: "accept" });
    expect(result.tapSpy).not.toHaveBeenCalled();
    await finish(result);
  });

  it("async-hold resolving within the deadline is honored (allow → accept)", async () => {
    installResolver(async (req) => {
      // The resolver Promise IS the async hold (e.g. a wallet-sign round-trip).
      await new Promise((resolve) => setTimeout(resolve, 25));
      return { requestId: req.requestId, decision: "allow" };
    });
    const result = await driveApproval();
    expect(result.response).toEqual({ decision: "accept" });
    expect(result.tapSpy).not.toHaveBeenCalled();
    await finish(result);
  });

  it("resolver that never resolves within the deadline fails closed (timed_out → decline)", async () => {
    // The resolver hold never settles; only the bridge's 120s deadline race can end it.
    // The harness's server-request wait uses vi.waitFor (real-time polling) so it cannot
    // coexist with fake timers; the deadline race is a pure bridge concern, so this case
    // drives the real bridge directly under fake timers (T11's fake-timer approach).
    vi.useFakeTimers();
    installResolver(() => new Promise<ApprovalDecision>(() => {}));
    const tapSpy = vi.spyOn(roundtrip, "requestPluginApproval");
    const responsePromise = handleCodexAppServerApprovalRequest({
      method: "item/commandExecution/requestApproval",
      requestParams: {
        threadId: "thread-1",
        turnId: "turn-1",
        itemId: "cmd-1",
        command: COMMAND,
        cwd: path.join(tempDir, "workspace"),
      },
      paramsForRun: paramsForConformanceRun(),
      threadId: "thread-1",
      turnId: "turn-1",
      autoApprove: false,
    });
    // Advance past DEFAULT_CODEX_APPROVAL_TIMEOUT_MS (120s) so the deadline race fires.
    await vi.advanceTimersByTimeAsync(120_001);
    const response = await responsePromise;
    expect(response).toEqual({ decision: "decline" });
    expect(tapSpy).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  it("abort mid-hold fails closed to decline", async () => {
    // Abort while the resolver hold is in flight; the aborted signal must override a
    // late `allow`. Driven against the real bridge with a per-request signal (the seam
    // the run-abort feeds) rather than aborting the whole attempt (which the harness
    // would tear down to `undefined` — a coarser signal that hides the branch's own
    // fail-closed). Same real resolver branch, same registry read.
    const controller = new AbortController();
    installResolver(
      (req) =>
        new Promise<ApprovalDecision>((resolve) => {
          // Abort while this hold is in flight, then resolve `allow`. The aborted request
          // signal must override the allow and fail closed (mirrors the T11 branch test).
          controller.abort("test_abort");
          resolve({ requestId: req.requestId, decision: "allow" });
        }),
    );
    const tapSpy = vi.spyOn(roundtrip, "requestPluginApproval");
    const response = await handleCodexAppServerApprovalRequest({
      method: "item/commandExecution/requestApproval",
      requestParams: {
        threadId: "thread-1",
        turnId: "turn-1",
        itemId: "cmd-1",
        command: COMMAND,
        cwd: path.join(tempDir, "workspace"),
      },
      paramsForRun: paramsForConformanceRun(),
      threadId: "thread-1",
      turnId: "turn-1",
      autoApprove: false,
      signal: controller.signal,
    });
    expect(response).toMatchObject({ decision: expect.stringMatching(/^(decline|cancel)$/) });
    expect(tapSpy).not.toHaveBeenCalled();
  });

  it("requestId mismatch fails closed to decline (request-binding guard)", async () => {
    installResolver(async () => ({ requestId: "not-the-parked-id", decision: "allow" }));
    const result = await driveApproval();
    expect(result.response).toEqual({ decision: "decline" });
    expect(result.tapSpy).not.toHaveBeenCalled();
    await finish(result);
  });

  it("no resolver → resolver branch is inert; the pre-existing path is byte-unchanged", async () => {
    // With no resolver registered the resolver branch is skipped and control falls to
    // the pre-existing posture. Under this run's auto-approve posture (approvalPolicy
    // 'never' + danger-full-access) that is the runtime auto-approve fall-through, which
    // maps to the codex verb "acceptForSession" — DISTINCT from a resolver approval
    // ("accept"). The resolver-approved verb ("accept") is NEVER produced without a
    // resolver, proving the branch does not manufacture an approval.
    setActivePluginRegistry(createEmptyPluginRegistry());
    const tapSpy = vi.spyOn(roundtrip, "requestPluginApproval");
    const sessionFile = path.join(tempDir, "session.jsonl");
    const workspaceDir = path.join(tempDir, "workspace");
    const harness = createStartedThreadHarness();
    const run = runCodexAppServerAttempt(createParams(sessionFile, workspaceDir), RUN_OPTIONS);
    await harness.waitForMethod("turn/start");
    const response = await harness.handleServerRequest({
      id: "req-exec-noresolver",
      method: "item/commandExecution/requestApproval",
      params: {
        threadId: "thread-1",
        turnId: "turn-1",
        itemId: "cmd-1",
        command: COMMAND,
        cwd: workspaceDir,
      },
    });
    // Auto-approve fall-through (not a resolver approval); the resolver-owned "accept"
    // verb is never produced without a resolver.
    expect(response).toEqual({ decision: "acceptForSession" });
    // The auto-approve leg short-circuits the human tap; the resolver branch did not
    // manufacture an approval AND did not divert the flow.
    expect(tapSpy).not.toHaveBeenCalled();
    await harness.completeTurn({ threadId: "thread-1", turnId: "turn-1" });
    await run;
    // Byte-unchanged sanity guard: without an auto-approve posture the same no-resolver
    // request DOES fall through to the pre-existing human tap (proving the resolver branch
    // is inert, not swallowing the request). Driven directly against the bridge with
    // autoApprove:false so the human-tap route — the pre-existing fall-through — is reached.
    tapSpy.mockRestore();
    setActivePluginRegistry(createEmptyPluginRegistry());
    const directTapSpy = vi
      .spyOn(roundtrip, "requestPluginApproval")
      .mockResolvedValue({ id: "gw-1" } as never);
    const waitSpy = vi
      .spyOn(roundtrip, "waitForPluginApprovalDecision")
      .mockResolvedValue("deny" as never);
    const directResponse = await handleCodexAppServerApprovalRequest({
      method: "item/commandExecution/requestApproval",
      requestParams: {
        threadId: "thread-1",
        turnId: "turn-1",
        itemId: "cmd-1",
        command: COMMAND,
        cwd: workspaceDir,
      },
      paramsForRun: paramsForConformanceRun(),
      threadId: "thread-1",
      turnId: "turn-1",
      autoApprove: false,
    });
    expect(directTapSpy).toHaveBeenCalledTimes(1);
    expect(waitSpy).toHaveBeenCalledTimes(1);
    expect(directResponse).toEqual({ decision: "decline" });
  });

  it("promotes never→untrusted (features.hooks + PreToolUse relay present) with a resolver", async () => {
    // Promotion surfaces as the never→untrusted trust posture in thread-start config;
    // the promotion is what MAKES the PreToolUse relay config present. Asserted on the
    // observable thread-start config rather than reaching into shouldPromote internals.
    installResolver(async (req) => ({ requestId: req.requestId, decision: "allow" }));
    const sessionFile = path.join(tempDir, "session.jsonl");
    const workspaceDir = path.join(tempDir, "workspace");
    const harness = createStartedThreadHarness();
    const run = runCodexAppServerAttempt(createParams(sessionFile, workspaceDir), {
      nativeHookRelay: { enabled: true, events: ["pre_tool_use"] },
    });
    await harness.waitForMethod("turn/start");
    const startRequest = harness.requests.find((entry) => entry.method === "thread/start");
    const startConfig = (startRequest?.params as { config?: Record<string, unknown> } | undefined)
      ?.config;
    expect(startConfig?.["features.hooks"]).toBe(true);
    expect(startConfig?.["hooks.PreToolUse"]).not.toEqual([]);
    // Sanity: a native hook relay is registered for this promoted run.
    expect(() => extractRelayIdFromThreadRequest(startRequest?.params)).not.toThrow();
    await harness.completeTurn({ threadId: "thread-1", turnId: "turn-1" });
    await run;
  });
});

// ---------------------------------------------------------------------------
// Shared provider-neutral core-seam conformance suite (Task 13) run against the REAL
// approval-resolver branch. The eight dedicated `it()` cases above already prove the
// FULL mock-app-server routing chain (server-request → turn-router →
// run-attempt-server-requests → handleApprovalRequest → handleCodexAppServerApprovalRequest).
// The conformance suite fans out MANY drives (the budget case issues 8 in parallel, the
// single-use case issues 2 sequentially); spinning a full runCodexAppServerAttempt per
// drive is both slow and collides on the shared codex session. So the conformance driver
// invokes `handleCodexAppServerApprovalRequest` DIRECTLY — the exact bridge entry the
// harness routing calls one hop later — with the native relay omitted (so the resolver
// branch owns the decision) and autoApprove:false (so a no-resolver drive fails closed via
// the human tap, which is spied to return no approval id → denied). Same real branch, same
// real registry read, fast and collision-free.
//
// Vocabulary bridge: the conformance suite speaks provider-neutral (`denied` /
// `approved`|`approved-once`); the codex bridge speaks codex verbs (`decline` / `accept`).
// The resolver-approved verb is EXACTLY "accept" (approved-once → commandApprovalDecision);
// "acceptForSession" would be a no-resolver runtime auto-approve (not a resolver approval).
// `ran` is a STRUCTURAL proxy — codex was TOLD to accept; real execution is Task 15.
function toConformanceResponse(wire: unknown): { response: { decision: string }; ran: boolean } {
  const decision = (wire as { decision?: unknown } | undefined)?.decision;
  const resolverApproved = decision === "accept";
  return {
    response: { decision: resolverApproved ? "approved-once" : "denied" },
    ran: resolverApproved,
  };
}

runApprovalResolverConformance({
  registerResolver(resolve: ApprovalResolver) {
    installResolver(resolve);
    return {
      dispose() {
        setActivePluginRegistry(createEmptyPluginRegistry());
      },
    };
  },
  async drive(input: { command: string; cwd?: string }) {
    // No-resolver drives fall through to the human tap; spy it to a no-id result so the
    // bridge fails closed to `denied` instantly instead of awaiting the 120s gateway.
    const tapSpy = vi.spyOn(roundtrip, "requestPluginApproval");
    if (!tapSpy.getMockImplementation()) {
      tapSpy.mockResolvedValue(undefined);
    }
    // Bound the drive with a per-request signal instead of waiting the bridge's real 120s
    // deadline: the "deadline"/stall conformance case's resolver never answers, so a short
    // real-timer proxy aborts the request → the bridge fails closed to `denied` (its real
    // abort-fail-closed leg, the same terminal outcome the 120s deadline produces). This
    // keeps every conformance case fast and concurrency-safe (no global fake-timer toggles
    // across the parallel `budget` drives). The 120s deadline TIMER itself is exercised
    // directly by the dedicated "resolver that never resolves" it() above.
    const controller = new AbortController();
    const proxy = setTimeout(() => controller.abort("conformance_deadline_proxy"), 250);
    try {
      const wire = await handleCodexAppServerApprovalRequest({
        method: "item/commandExecution/requestApproval",
        requestParams: {
          threadId: "thread-1",
          turnId: "turn-1",
          itemId: "cmd-1",
          command: input.command,
          cwd: input.cwd ?? path.join(tempDir, "workspace"),
        },
        paramsForRun: paramsForConformanceRun(),
        threadId: "thread-1",
        turnId: "turn-1",
        autoApprove: false,
        signal: controller.signal,
      });
      return toConformanceResponse(wire);
    } finally {
      clearTimeout(proxy);
      tapSpy.mockRestore();
    }
  },
  reset() {
    setActivePluginRegistry(createEmptyPluginRegistry());
    __resetProofRegistryForTest();
  },
});
