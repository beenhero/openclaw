// Live proof for the capability-scoped process.exec approval resolver against a
// real Codex app-server, driven through OpenClaw's FULL connection (the same path the
// real agent uses): a denying resolver must block an auto-run exec (no filesystem
// marker; resolver saw the request); an allowing resolver must let it run.
//
// This drives `runCodexAppServerAttempt` (the full attempt) with a REAL codex client
// injected via `setCodexAppServerClientFactoryForTest`, so the OpenClaw promotion
// (never→untrusted, folded on resolver presence), the approval handler
// (handleCodexAppServerApprovalRequest → runOpenClawToolPolicyForApprovalRequest), and
// the native hook relay are all applied — an auto-run exec ESCALATES to the registered
// process.exec resolver, which owns the decision.
//
// Auth: this committed CI form authenticates via OPENAI_API_KEY (set in the injected
// client's start-options env). Gate: OPENCLAW_LIVE_TEST=1 &&
// OPENCLAW_LIVE_CODEX_APPROVAL_RESOLVER=1, codex in [0.143.0, MAX], and OPENAI_API_KEY
// set. The OAuth drill variant (approval-resolver-exec.live-oauth.test.ts) is the local
// run form that rides a ChatGPT `codex login` instead of an API key.
import fs from "node:fs/promises";
import path from "node:path";
import type {
  ApprovalDecision,
  ApprovalRequest,
  PluginApprovalResolverRegistration,
  PluginApprovalResolverRegistryRegistration,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  createEmptyPluginRegistry,
  setActivePluginRegistry,
} from "openclaw/plugin-sdk/plugin-test-runtime";
import { afterEach, describe, expect, it } from "vitest";
import type { CodexAppServerClient } from "./client.js";
import { resolveCodexAppServerRuntimeOptions } from "./config.js";
import {
  createParams,
  runCodexAppServerAttempt,
  setCodexAppServerClientFactoryForTest,
  setupRunAttemptTestHooks,
  tempDir,
} from "./run-attempt-test-harness.js";
import { createIsolatedCodexAppServerClient } from "./shared-client.js";

const LIVE =
  process.env.OPENCLAW_LIVE_TEST === "1" &&
  process.env.OPENCLAW_LIVE_CODEX_APPROVAL_RESOLVER === "1";
const describeLive = LIVE ? describe : describe.skip;

setupRunAttemptTestHooks();

afterEach(() => {
  setActivePluginRegistry(createEmptyPluginRegistry());
});

// Register a process.exec resolver on a fresh active plugin registry. The bridge's
// registry read (hasApprovalResolverForScope / getApprovalResolverForScope) reads this
// active registry directly — no mocking of the resolver-retrieval seam. The registry
// MUST be active before runCodexAppServerAttempt so the connection folds resolver
// presence into the never→untrusted promotion. Returns the recorded requests.
function installResolver(verdict: "allow" | "deny"): { requests: ApprovalRequest[] } {
  const requests: ApprovalRequest[] = [];
  const registration: PluginApprovalResolverRegistration = {
    id: "live-exec-resolver",
    description: "live process.exec resolver (full connection)",
    scope: { capabilities: ["process.exec"] },
    exclusive: true,
    resolve: async (req: ApprovalRequest): Promise<ApprovalDecision> => {
      requests.push(req);
      return {
        requestId: req.requestId,
        decision: verdict,
        reason: verdict === "deny" ? "live resolver denied" : undefined,
      };
    },
  };
  const entry: PluginApprovalResolverRegistryRegistration = {
    pluginId: "live-test",
    registration,
    source: "live-test",
  };
  const registry = createEmptyPluginRegistry();
  registry.approvalResolvers.push(entry);
  setActivePluginRegistry(registry);
  return { requests };
}

// Injects a REAL isolated codex app-server client into the full-connection path. The
// connection resolves its own start options and hands them to this factory; we point the
// client at an isolated codex-home and set OPENAI_API_KEY in its env so it authenticates
// via API key. Everything else in the connection (promotion, approval handler, native
// hook relay) is production wiring around this real client.
function installRealCodexClientFactory(codexHome: string, apiKey: string): void {
  setCodexAppServerClientFactoryForTest(
    async (startOptions, _authProfileId, agentDir): Promise<CodexAppServerClient> => {
      const base = resolveCodexAppServerRuntimeOptions({
        pluginConfig: { appServer: { homeScope: "user" } },
        env: {},
      }).start;
      return createIsolatedCodexAppServerClient({
        startOptions: {
          ...base,
          ...(startOptions ?? {}),
          homeScope: "user",
          env: {
            ...(startOptions?.env ?? {}),
            CODEX_HOME: codexHome,
            OPENAI_API_KEY: apiKey,
          },
        },
        agentDir,
        authProfileId: null,
        timeoutMs: 120_000,
      });
    },
  );
}

async function runLiveExec(params: {
  verdict: "allow" | "deny";
  root: string;
}): Promise<{ markerExists: boolean; resolverRequests: ApprovalRequest[] }> {
  const { verdict, root } = params;
  const apiKey = process.env.OPENAI_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY is required for this live test");
  }

  // Resolver first: the connection reads the active registry to fold resolver presence
  // into the never→untrusted promotion.
  const { requests: resolverRequests } = installResolver(verdict);

  const codexHome = path.join(root, "codex-home");
  const workspace = path.join(root, "workspace");
  const sessionFile = path.join(root, "session.jsonl");
  await fs.mkdir(codexHome, { recursive: true });
  await fs.mkdir(workspace, { recursive: true });
  const marker = path.join(workspace, `RESOLVER_MARKER_${verdict}.txt`);

  installRealCodexClientFactory(codexHome, apiKey);

  // Drive the FULL connection. The native hook relay is ENABLED with pre_tool_use
  // relayed (the default production posture); the resolver-first ordering owns the
  // command-execution decision. The prompt asks codex to write a filesystem marker via a
  // single shell exec — the marker presence is ground-truth for "did the command run".
  const runParams = {
    ...createParams(sessionFile, workspace),
    // The createParams fixture pins gpt-5.4-codex; use gpt-5.5 (the model the live OAuth
    // drill confirmed end-to-end) so both live forms request the same supported model.
    modelId: "gpt-5.5",
    prompt: `Run exactly one shell command and nothing else: touch ${JSON.stringify(
      marker,
    )} . Do not explain. Reply DONE when finished or blocked.`,
    cwd: workspace,
    timeoutMs: 300_000,
  };

  await runCodexAppServerAttempt(runParams, {
    nativeHookRelay: { enabled: true, events: ["pre_tool_use"] },
  });

  const markerExists = await fs
    .access(marker)
    .then(() => true)
    .catch(() => false);
  return { markerExists, resolverRequests };
}

describeLive("process.exec approval resolver — live codex app-server via FULL connection", () => {
  it("denying resolver blocks an auto-run exec (no marker, resolver saw the request)", async () => {
    const { markerExists, resolverRequests } = await runLiveExec({
      verdict: "deny",
      root: tempDir,
    });
    // The resolver was consulted for a process.exec escalation...
    expect(resolverRequests.length).toBeGreaterThan(0);
    expect(resolverRequests[0]?.capability).toBe("process.exec");
    expect(resolverRequests[0]?.paramsDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    // ...and because it denied, codex must NOT have executed the command.
    expect(markerExists).toBe(false);
  }, 600_000);

  it("allowing resolver lets the same exec run (marker written)", async () => {
    const { markerExists, resolverRequests } = await runLiveExec({
      verdict: "allow",
      root: tempDir,
    });
    expect(resolverRequests.length).toBeGreaterThan(0);
    expect(resolverRequests[0]?.capability).toBe("process.exec");
    expect(markerExists).toBe(true);
  }, 600_000);
});
