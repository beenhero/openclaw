// Live proof for the capability-scoped process.exec approval resolver against a
// real Codex app-server: a denying resolver must block an auto-run exec (no
// filesystem marker + codex declined); an allowing resolver must let it run.
// This is the sole live-confirmed leg for the approval-resolver seam.
//
// NOT executed here: the installed codex-cli is 0.141.0, below the
// MIN_CODEX_APP_SERVER_VERSION floor of 0.143.0 — createIsolatedCodexAppServerClient
// would hard-throw at initialize. Gate: OPENCLAW_LIVE_TEST=1 &&
// OPENCLAW_LIVE_CODEX_APPROVAL_RESOLVER=1, run in a full checkout with
// codex ≥ 0.143.0 and OPENAI_API_KEY set.
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
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
import { withTempDir } from "openclaw/plugin-sdk/test-env";
import { afterEach, describe, expect, it } from "vitest";
import type { CodexAppServerClient } from "./client.js";
import { resolveCodexAppServerRuntimeOptions } from "./config.js";
import { isJsonObject } from "./protocol.js";
import { createIsolatedCodexAppServerClient } from "./shared-client.js";

const LIVE =
  process.env.OPENCLAW_LIVE_TEST === "1" &&
  process.env.OPENCLAW_LIVE_CODEX_APPROVAL_RESOLVER === "1";
const describeLive = LIVE ? describe : describe.skip;

// Register a process.exec resolver on a fresh active plugin registry. The
// resolver echoes req.requestId (request-binding, T11) and returns the given
// verdict. Returns the recorded requests so the test can assert dispatch.
function installResolver(verdict: "allow" | "deny"): {
  requests: ApprovalRequest[];
} {
  const requests: ApprovalRequest[] = [];
  const registration: PluginApprovalResolverRegistration = {
    id: "live-exec-resolver",
    description: "live process.exec resolver",
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

async function waitFor<T>(
  probe: () => Promise<T | undefined> | (T | undefined),
  timeoutMs: number,
  what: string,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await probe();
    if (value !== undefined) {
      return value;
    }
    await delay(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

// Drive a real codex app-server that auto-runs an exec (approvalPolicy:"never"),
// with OpenClaw's PreToolUse trust-stamped relay wired so codex escalates the
// command to the OpenClaw approval bridge (where the resolver decides).
async function runLiveExec(params: {
  verdict: "allow" | "deny";
  root: string;
}): Promise<{ markerExists: boolean; resolverRequests: ApprovalRequest[] }> {
  const { verdict, root } = params;
  const apiKey = process.env.OPENAI_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY is required for this live test");
  }
  const { requests: resolverRequests } = installResolver(verdict);

  const codexHome = path.join(root, "codex-home");
  const workspace = path.join(root, "workspace");
  await fs.mkdir(workspace, { recursive: true });
  const marker = path.join(workspace, `RESOLVER_MARKER_${verdict}.txt`);

  const runtime = resolveCodexAppServerRuntimeOptions({
    pluginConfig: { appServer: { homeScope: "user" } },
    env: {},
  });
  let client: CodexAppServerClient | undefined;
  try {
    client = await createIsolatedCodexAppServerClient({
      startOptions: {
        ...runtime.start,
        env: { CODEX_HOME: codexHome },
        clearEnv: ["CODEX_API_KEY", "OPENAI_API_KEY"],
      },
      agentDir: path.join(root, "agent"),
      authProfileId: null,
      timeoutMs: 120_000,
    });
    await client.request("account/login/start", { type: "apiKey", apiKey }, { timeoutMs: 60_000 });

    let threadId = "";
    let turnCompleted = false;
    client.addNotificationHandler((notification) => {
      if (notification.method !== "turn/completed") {
        return;
      }
      const p = isJsonObject(notification.params) ? notification.params : undefined;
      if (p?.threadId === threadId) {
        turnCompleted = true;
      }
    });

    // approvalPolicy:"never" = the auto-run posture: codex does not tap the
    // human; the trust-stamped PreToolUse relay routes exec escalations into the
    // OpenClaw approval bridge where the registered resolver is the sole owner.
    const started = await client.request(
      "thread/start",
      {
        model: "gpt-5.5",
        cwd: workspace,
        approvalPolicy: "never",
        sandbox: "danger-full-access",
        threadSource: "user",
        experimentalRawEvents: true,
      },
      { timeoutMs: 120_000 },
    );
    threadId = started.thread.id;

    // Ask codex to write a filesystem marker via a single shell exec. The marker
    // presence is the ground-truth for "did the command actually run".
    await client.request(
      "turn/start",
      {
        threadId,
        input: [
          {
            type: "text",
            text: `Run exactly one shell command and nothing else: touch ${JSON.stringify(marker)} . Do not explain. Reply DONE when finished or blocked.`,
          },
        ],
      },
      { timeoutMs: 300_000 },
    );

    await waitFor(() => (turnCompleted ? true : undefined), 300_000, "turn completion");

    const markerExists = await fs
      .access(marker)
      .then(() => true)
      .catch(() => false);
    return { markerExists, resolverRequests };
  } finally {
    await client?.closeAndWait().catch(() => {});
  }
}

afterEach(() => {
  setActivePluginRegistry(createEmptyPluginRegistry());
});

describeLive("process.exec approval resolver — live codex app-server", () => {
  it("denying resolver blocks an auto-run exec (no marker, resolver saw the request)", async () => {
    await withTempDir("openclaw-approval-resolver-deny-", async (root) => {
      const { markerExists, resolverRequests } = await runLiveExec({
        verdict: "deny",
        root,
      });
      // The resolver was consulted for a process.exec escalation...
      expect(resolverRequests.length).toBeGreaterThan(0);
      expect(resolverRequests[0]?.capability).toBe("process.exec");
      expect(resolverRequests[0]?.paramsDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
      // ...and because it denied, codex must NOT have executed the command.
      expect(markerExists).toBe(false);
    });
  }, 600_000);

  it("allowing resolver lets the same exec run (marker written)", async () => {
    await withTempDir("openclaw-approval-resolver-allow-", async (root) => {
      const { markerExists, resolverRequests } = await runLiveExec({
        verdict: "allow",
        root,
      });
      expect(resolverRequests.length).toBeGreaterThan(0);
      expect(resolverRequests[0]?.capability).toBe("process.exec");
      expect(markerExists).toBe(true);
    });
  }, 600_000);
});
