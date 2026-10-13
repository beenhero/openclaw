import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __resetProofRegistryForTest } from "../plugins/capability-approval.js";
import type { ApprovalDecision, ApprovalRequest } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { publishPythonInlineArtifact } from "./python-inline-artifact.js";
import { CronService } from "./service.js";
import {
  createCronStoreHarness,
  createNoopLogger,
  installCronTestHooks,
} from "./service.test-harness.js";
import type { CronJob, CronJobCreate } from "./types.js";

const logger = createNoopLogger();
const { makeStorePath } = createCronStoreHarness({ prefix: "cron-command-authorization-" });
installCronTestHooks({ logger, baseTimeIso: "2026-09-29T06:00:00.000Z" });

beforeEach(() => {
  __resetProofRegistryForTest();
  setActivePluginRegistry(createEmptyPluginRegistry());
});

afterEach(() => {
  __resetProofRegistryForTest();
  setActivePluginRegistry(createEmptyPluginRegistry());
});

function installAutomationResolver(
  resolve: (
    request: ApprovalRequest,
    opts: { signal: AbortSignal; deadlineMs: number },
  ) => Promise<ApprovalDecision>,
): void {
  setActivePluginRegistry({
    ...createEmptyPluginRegistry(),
    approvalResolvers: [
      {
        pluginId: "sigil-test",
        pluginName: "Sigil test",
        source: "test",
        registration: {
          id: "sigil-automation",
          description: "Test automation resolver",
          scope: { capabilities: ["automation.command"] },
          exclusive: true,
          resolve,
        },
      },
    ],
  });
}

function createService(storePath: string): CronService {
  return new CronService({
    storePath,
    cronEnabled: true,
    cronConfig: { executionAuthorization: { command: "sigil-automation" } },
    defaultAgentId: "main",
    log: logger,
    enqueueSystemEvent: vi.fn(),
    requestHeartbeat: vi.fn(),
    runCommandJob: vi.fn(async () => ({ status: "ok" as const })),
    runIsolatedAgentJob: vi.fn(async () => ({ status: "ok" as const })),
  });
}

async function createCommandInput(storePath: string): Promise<CronJobCreate> {
  const sourcePath = path.join(path.dirname(storePath), "activation.py");
  await fs.mkdir(path.dirname(sourcePath), { recursive: true });
  await fs.writeFile(sourcePath, "print('activation test')\n");
  const payload = await publishPythonInlineArtifact({
    sourcePath,
    pythonPath: "/usr/bin/python3",
    cwd: path.dirname(sourcePath),
  });
  return {
    name: "activation gated",
    enabled: true,
    schedule: { kind: "every", everyMs: 60_000 },
    sessionTarget: "isolated",
    wakeMode: "now",
    payload,
    delivery: { mode: "none" },
  };
}

async function waitForAuthorization(
  service: CronService,
  jobId: string,
  status: "required" | "ready",
  label: string = status,
): Promise<CronJob> {
  let matched: CronJob | undefined;
  await vi.waitFor(async () => {
    matched = (await service.list({ includeDisabled: true })).find((job) => job.id === jobId);
    const authorization = matched?.state.commandAuthorization;
    expect(authorization?.status, `${label}: ${JSON.stringify(authorization)}`).toBe(status);
  });
  return matched!;
}

describe("CronService command authorization activation", () => {
  it("persists ready authority and does not request it again after restart", async () => {
    const { storePath } = await makeStorePath();
    const requests: ApprovalRequest[] = [];
    installAutomationResolver(async (request) => {
      requests.push(request);
      return { requestId: request.requestId, decision: "allow", proof: `proof:${requests.length}` };
    });

    const first = createService(storePath);
    await first.start();
    const added = await first.add(await createCommandInput(storePath));
    expect(added.enabled).toBe(false);
    const ready = await waitForAuthorization(first, added.id, "ready", "initial activation");
    expect(ready.enabled).toBe(true);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.toolName).toBe("automation.authorize");
    first.stop();

    const restarted = createService(storePath);
    await restarted.start();
    const persisted = await waitForAuthorization(restarted, added.id, "ready", "restart state");
    expect(persisted.enabled).toBe(true);
    expect(requests).toHaveLength(1);
    restarted.stop();
  });

  it("retries a durable required state after restart", async () => {
    const { storePath } = await makeStorePath();
    installAutomationResolver(async (request) => ({
      requestId: request.requestId,
      decision: "deny",
      denialKind: "authorization-required",
      reason: "approval window closed",
    }));

    const first = createService(storePath);
    await first.start();
    const added = await first.add(await createCommandInput(storePath));
    await vi.waitFor(async () => {
      const current = (await first.list({ includeDisabled: true })).find(
        (job) => job.id === added.id,
      );
      expect(current?.state.commandAuthorization).toMatchObject({
        status: "required",
        reason: "standing authorization required",
      });
    });
    const required = await waitForAuthorization(first, added.id, "required");
    expect(required.enabled).toBe(false);
    first.stop();

    const retry = vi.fn(async (request: ApprovalRequest) => ({
      requestId: request.requestId,
      decision: "allow" as const,
      proof: "proof:restart",
    }));
    installAutomationResolver(retry);
    const restarted = createService(storePath);
    await restarted.start();
    const ready = await waitForAuthorization(restarted, added.id, "ready");
    expect(ready.enabled).toBe(true);
    expect(retry).toHaveBeenCalledOnce();
    restarted.stop();
  });

  it("cancels a stale request and activates only the newest authority", async () => {
    const { storePath } = await makeStorePath();
    const attempts: Array<{
      request: ApprovalRequest;
      signal: AbortSignal;
      resolve: (decision: ApprovalDecision) => void;
    }> = [];
    installAutomationResolver(
      (request, opts) =>
        new Promise<ApprovalDecision>((resolve) => {
          attempts.push({ request, signal: opts.signal, resolve });
        }),
    );

    const service = createService(storePath);
    await service.start();
    const added = await service.add(await createCommandInput(storePath));
    expect(attempts).toHaveLength(1);

    const changed = await service.update(added.id, {
      schedule: { kind: "every", everyMs: 120_000 },
    });
    expect(changed.enabled).toBe(false);
    expect(attempts).toHaveLength(2);
    expect(attempts[0]?.signal.aborted).toBe(true);

    attempts[0]?.resolve({
      requestId: attempts[0].request.requestId,
      decision: "allow",
      proof: "proof:stale",
    });
    attempts[1]?.resolve({
      requestId: attempts[1].request.requestId,
      decision: "allow",
      proof: "proof:current",
    });
    const ready = await waitForAuthorization(service, added.id, "ready");
    expect(ready).toMatchObject({
      enabled: true,
      schedule: { kind: "every", everyMs: 120_000 },
      state: { commandAuthorization: { status: "ready", proofRef: expect.any(String) } },
    });
    service.stop();
  });
});
