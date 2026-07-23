/**
 * L4.8 — web_fetch net.egress gate enforcement drill.
 *
 * Proves that a registered net.egress resolver's DENY actually STOPS a real
 * web_fetch tool call: the block is honored because web_fetch is OpenClaw-owned
 * and wrapToolWithBeforeToolCallHook awaits the hook + short-circuits execute()
 * before the fetch spy is ever called.
 *
 * This is the "web_fetch gated like curl" acceptance sketch (#97152), enforced
 * in-harness with the network mocked.
 *
 * Enforcement detail: on a CLEAN policy DENY, decideCapabilityApproval returns
 * { kind:"deny", reason } with NO failureDisposition (a decision, not a failure),
 * which causes runFrontStageResolver to return { blocked:true, kind:"veto",
 * deniedReason:"capability-resolver" }, which causes wrapToolWithBeforeToolCallHook
 * to return a graceful BLOCKED RESULT (details.status==="blocked") — short-circuiting
 * execute() so the fetch spy is NEVER called. This mirrors a codex curl-deny's
 * graceful "decline". A GENUINE failure (timeout, requestId-mismatch, malformed
 * decision) still carries a failureDisposition → kind:"failure" → the wrapper
 * throws BeforeToolCallFailureError. Both paths are fail-closed: execute() is
 * never reached, the fetch is never made.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetDefaultProofLedgerForTest,
  setActivePluginRegistry,
} from "../plugin-sdk/plugin-test-runtime.js";
import type { ApprovalDecision, ApprovalRequest } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import type { PluginApprovalResolverRegistryRegistration } from "../plugins/registry-types.js";
import type { FetchMock } from "../test-utils/fetch-mock.js";
import { withFetchPreconnect } from "../test-utils/fetch-mock.js";
import { wrapToolWithBeforeToolCallHook } from "./agent-tools.before-tool-call.js";
import { createWebFetchTool } from "./tools/web-fetch.js";
import { makeFetchHeaders } from "./tools/web-fetch.test-harness.js";
import "./tools/web-fetch.test-mocks.js";

// ---------------------------------------------------------------------------
// Network mock helpers (mirror web-fetch.ssrf.test.ts)
// Use text/plain so the "raw" extractor path is taken (no readability needed).
// ---------------------------------------------------------------------------

function textResponse(body: string): Response {
  return {
    ok: true,
    status: 200,
    headers: makeFetchHeaders({ "content-type": "text/plain" }),
    text: async () => body,
  } as unknown as Response;
}

function setMockFetch(
  impl: FetchMock = async () => textResponse("ok"),
): ReturnType<typeof vi.fn<FetchMock>> {
  const fetchSpy = vi.fn<FetchMock>(impl);
  global.fetch = withFetchPreconnect(fetchSpy);
  return fetchSpy;
}

// ---------------------------------------------------------------------------
// Tool builder (mirrors createWebFetchToolForTest in ssrf.test.ts)
// ---------------------------------------------------------------------------

const lookupMock = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

function createWebFetchToolForTest() {
  return createWebFetchTool({
    config: {
      tools: {
        web: {
          fetch: {
            cacheTtlMinutes: 0,
          },
        },
      },
    },
    lookupFn: lookupMock,
  });
}

// ---------------------------------------------------------------------------
// Registry helper — register a net.egress resolver on the active registry
// ---------------------------------------------------------------------------

function registerNetEgressResolver(
  resolve: (req: ApprovalRequest) => Promise<ApprovalDecision> | ApprovalDecision,
): { seen: ApprovalRequest[] } {
  const seen: ApprovalRequest[] = [];
  const registry = createEmptyPluginRegistry();
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "test-net-egress-plugin",
    pluginName: "test-net-egress-plugin",
    source: "test",
    registration: {
      id: "test-net-egress-resolver",
      description: "test net.egress resolver",
      scope: { capabilities: ["net.egress"] },
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
// Minimal HookContext with sessionKey (required for front-stage to fire).
// The front-stage guard at :1545 is `if (args.ctx?.sessionKey)` — without it,
// runFrontStageResolver is never called.
// ---------------------------------------------------------------------------

const TEST_CTX = {
  sessionKey: "agent:test-net-egress:main",
  runId: "run-net-egress-gate",
  agentId: "test-agent",
} as const;

const TEST_URL = "https://example.com";

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("web_fetch net.egress gate (L4.8 — #97152 acceptance sketch)", () => {
  const priorFetch = global.fetch;

  beforeEach(() => {
    // Ensure the proof ledger is a fresh InMemory instance so the front-stage
    // durable-ledger default never touches the real agent dir.
    __resetDefaultProofLedgerForTest();
    // Clear the resolver registry before each test.
    setActivePluginRegistry(createEmptyPluginRegistry());
    lookupMock.mockClear();
  });

  afterEach(() => {
    global.fetch = priorFetch;
    setActivePluginRegistry(createEmptyPluginRegistry());
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Test 1 — a CLEAN policy DENY blocks the fetch GRACEFULLY (the headline)
  //
  // When a resolver returns a clean deny (matching requestId, decision:"deny"),
  // decideCapabilityApproval returns { kind:"deny", reason } with NO
  // failureDisposition → runFrontStageResolver returns { blocked:true,
  // kind:"veto", deniedReason:"capability-resolver" } → wrapToolWithBeforeToolCallHook
  // returns a GRACEFUL BLOCKED RESULT (details.status==="blocked") before calling
  // execute(). The fetch spy is NEVER called — this is the enforcement proof,
  // and it now declines gracefully like a codex curl-deny (no throw).
  // -------------------------------------------------------------------------

  it("DENY (clean policy): resolver deny → graceful blocked result, fetchSpy NOT called", async () => {
    const { seen } = registerNetEgressResolver((req) => ({
      requestId: req.requestId,
      decision: "deny",
      reason: "blocked by policy",
    }));

    const fetchSpy = setMockFetch();

    const tool = createWebFetchToolForTest();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    // A clean deny is a DECISION → front-stage veto → graceful blocked RESULT
    // (not a throw). This mirrors a codex curl-deny declining gracefully.
    const result = await wrapped.execute?.("call-deny", { url: TEST_URL });
    const details = (result as { details?: { status?: unknown; deniedReason?: unknown } }).details;
    expect(details?.status).toBe("blocked");
    expect(details?.deniedReason).toBe("capability-resolver");

    // THE KEY ASSERTION: the outbound fetch was NEVER called.
    // The block is still genuinely enforced — execute() was short-circuited.
    expect(fetchSpy).not.toHaveBeenCalled();

    // AND: the resolver observed the request with net.egress effects containing example.com.
    expect(seen).toHaveLength(1);
    const req = seen[0]!;
    expect(req.capability).toBe("net.egress");
    const egressEffect = req.effects.find((e) => e.kind === "net.egress");
    expect(egressEffect).toBeDefined();
    // Tier-C refines the host from params.url — example.com must be in hosts.
    if (egressEffect && "hosts" in egressEffect) {
      const hosts = egressEffect.hosts as string[];
      expect(hosts.some((h) => h === "example.com" || h === "*")).toBe(true);
    }
  });

  // -------------------------------------------------------------------------
  // Test 1b — a GENUINE failure (requestId mismatch) still THROWS (fail-closed)
  //
  // A resolver that echoes the WRONG requestId is a protocol failure, not a
  // clean policy decision → decideCapabilityApproval returns
  // { kind:"deny", failureDisposition:"failed" } → front-stage kind:"failure"
  // → the wrapper throws BeforeToolCallFailureError. The fetch is STILL never
  // made — fail-closed holds for the failure path too.
  // -------------------------------------------------------------------------

  it("FAILURE (requestId mismatch): resolver echoes wrong id → throws, fetchSpy NOT called", async () => {
    registerNetEgressResolver(() => ({
      requestId: "WRONG-request-id",
      decision: "allow",
    }));

    const fetchSpy = setMockFetch();

    const tool = createWebFetchToolForTest();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    // A protocol failure (not a clean decision) → front-stage failure → throw.
    await expect(wrapped.execute?.("call-mismatch", { url: TEST_URL })).rejects.toThrow();

    // Fail-closed: the fetch was never made on the failure path either.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Test 2 — ALLOW lets the fetch run
  // -------------------------------------------------------------------------

  it("ALLOW: resolver allow → fetchSpy IS called, result is not a block throw", async () => {
    registerNetEgressResolver((req) => ({
      requestId: req.requestId,
      decision: "allow",
    }));

    const fetchSpy = setMockFetch();

    const tool = createWebFetchToolForTest();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    const result = await wrapped.execute?.("call-allow", { url: TEST_URL });

    // The fetch ran.
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // The result is a normal (non-blocked) shape.
    const details = (result as { details?: { status?: unknown } }).details;
    expect(details?.status).not.toBe("blocked");
    // The raw extractor returns a numeric 200 status.
    expect(details?.status).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Test 3 — NO resolver → byte-unchanged (front-stage is a no-op)
  // -------------------------------------------------------------------------

  it("NO resolver: empty registry → fetch runs normally, no block", async () => {
    // Registry is already empty from beforeEach.

    const fetchSpy = setMockFetch();

    const tool = createWebFetchToolForTest();
    const wrapped = wrapToolWithBeforeToolCallHook(tool, TEST_CTX, {
      emitDiagnostics: false,
    });

    const result = await wrapped.execute?.("call-noResolver", { url: TEST_URL });

    // Without a resolver, the fetch runs normally.
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Result is not blocked.
    const details = (result as { details?: { status?: unknown } }).details;
    expect(details?.status).not.toBe("blocked");
  });

  // -------------------------------------------------------------------------
  // Test 4 — No-sessionKey → front-stage guard skips, fetch runs
  //
  // Proves the front-stage is gated on ctx.sessionKey — without it,
  // runFrontStageResolver is never consulted, even with a deny resolver.
  // -------------------------------------------------------------------------

  it("no sessionKey in ctx → front-stage guard skips even with deny resolver, fetch runs", async () => {
    // Register a deny resolver — but no sessionKey in ctx means it is never consulted.
    registerNetEgressResolver(() => ({
      requestId: "unreachable",
      decision: "deny",
      reason: "should never fire",
    }));

    const fetchSpy = setMockFetch();

    const tool = createWebFetchToolForTest();
    // ctx WITHOUT sessionKey → front-stage guard at :1545 skips runFrontStageResolver.
    const ctxWithoutSessionKey = {
      runId: "run-no-session-key",
      agentId: "test-agent",
    };
    const wrapped = wrapToolWithBeforeToolCallHook(tool, ctxWithoutSessionKey, {
      emitDiagnostics: false,
    });

    const result = await wrapped.execute?.("call-noKey", { url: TEST_URL });

    // Fetch ran (front-stage was not consulted).
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const details = (result as { details?: { status?: unknown } }).details;
    expect(details?.status).not.toBe("blocked");
  });
});
