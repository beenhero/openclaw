import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { MAX_TIMER_TIMEOUT_MS } from "@openclaw/normalization-core/number-coercion";
import { afterEach, describe, expect, it } from "vitest";
import { __resetProofRegistryForTest } from "../plugins/capability-approval.js";
import type { ApprovalDecision, ApprovalRequest } from "../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { resolveCronJobConfigRevision } from "./config-revision.js";
import {
  authorizeCronCommandExecution,
  buildCronCommandExecutionPlan,
} from "./execution-authorization.js";
import { publishPythonInlineArtifact } from "./python-inline-artifact.js";
import type { CronRunReceiptHandle } from "./store/run-receipt-store.js";
import type { CronJob } from "./types.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  __resetProofRegistryForTest();
  setActivePluginRegistry(createEmptyPluginRegistry());
});

function installAutomationResolver(
  resolve: (request: ApprovalRequest) => Promise<ApprovalDecision>,
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

async function makeFixture() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "openclaw-authorization-plan-"));
  dirs.push(dir);
  const sourcePath = path.join(dir, "job.py");
  await writeFile(sourcePath, "print('hello')\n");
  const payload = await publishPythonInlineArtifact({
    sourcePath,
    pythonPath: "/usr/bin/python3",
    cwd: dir,
  });
  const job: CronJob = {
    id: "job-1",
    agentId: "agent-1",
    name: "immutable job",
    enabled: true,
    createdAtMs: 10,
    updatedAtMs: 10,
    schedule: { kind: "every", everyMs: 60_000 },
    sessionTarget: "isolated",
    wakeMode: "now",
    payload,
    delivery: { mode: "none" },
    state: { runningAtMs: 20 },
  };
  const runReceipt: CronRunReceiptHandle = {
    receiptId: "receipt-1",
    storeKey: "store-1",
    jobId: job.id,
    configRevision: resolveCronJobConfigRevision(job),
    agentId: "agent-1",
    ownerPid: process.pid,
    ownerStartTime: 1,
    startedAtMs: 20,
  };
  return { job, runReceipt };
}

describe("cron command execution authorization", () => {
  it("binds definition separately from the per-run receipt", async () => {
    const { job, runReceipt } = await makeFixture();
    const first = buildCronCommandExecutionPlan({ job, runReceipt, runClass: "scheduled" });
    const second = buildCronCommandExecutionPlan({
      job,
      runReceipt: { ...runReceipt, receiptId: "receipt-2", startedAtMs: 30 },
      runClass: "scheduled",
    });
    expect(first.plan.definition.definitionDigest).toBe(second.plan.definition.definitionDigest);
    expect(first.plan.executionDigest).not.toBe(second.plan.executionDigest);
    expect(first.plan.invocation.runReceiptId).toBe("receipt-1");
  });

  it("signs the same effective defaults and timer clamps the runner enforces", async () => {
    const { job, runReceipt } = await makeFixture();
    const defaults = buildCronCommandExecutionPlan({ job, runReceipt, runClass: "scheduled" });
    expect(defaults.plan.definition.process).toMatchObject({
      timeoutMs: 600_000,
      maxOutputBytes: 16 * 1024 * 1024,
    });

    if (job.payload.kind !== "command") throw new Error("expected command payload");
    job.payload.timeoutSeconds = Number.MAX_VALUE;
    job.payload.noOutputTimeoutSeconds = 0;
    job.payload.outputMaxBytes = 1234;
    runReceipt.configRevision = resolveCronJobConfigRevision(job);
    const bounded = buildCronCommandExecutionPlan({ job, runReceipt, runClass: "scheduled" });
    expect(bounded.plan.definition.process).toMatchObject({
      timeoutMs: MAX_TIMER_TIMEOUT_MS,
      noOutputTimeoutMs: 2_147_483_647,
      maxOutputBytes: 1234,
    });
  });

  it("rejects a job snapshot that does not match the receipt revision", async () => {
    const { job, runReceipt } = await makeFixture();
    job.description = "mutated after receipt admission";
    expect(() => buildCronCommandExecutionPlan({ job, runReceipt, runClass: "scheduled" })).toThrow(
      /snapshot does not match its run receipt revision/,
    );
  });

  it("fails closed when the configured provider is unavailable", async () => {
    const { job, runReceipt } = await makeFixture();
    await expect(
      authorizeCronCommandExecution({
        job,
        runReceipt,
        runClass: "scheduled",
        providerId: "sigil-automation",
      }),
    ).resolves.toMatchObject({ kind: "denied", failureDisposition: "failed" });
  });

  it("requires a durable proof reference from a configured provider", async () => {
    const { job, runReceipt } = await makeFixture();
    installAutomationResolver(async (request) => ({
      requestId: request.requestId,
      decision: "allow",
    }));
    await expect(
      authorizeCronCommandExecution({
        job,
        runReceipt,
        runClass: "scheduled",
        providerId: "sigil-automation",
      }),
    ).resolves.toMatchObject({
      kind: "denied",
      failureDisposition: "failed",
      error: expect.stringMatching(/no durable proof reference/),
    });
  });

  it("retains request correlation and only a hash of the provider proof", async () => {
    const { job, runReceipt } = await makeFixture();
    const proof = "provider-secret-proof";
    installAutomationResolver(async (request) => ({
      requestId: request.requestId,
      decision: "allow",
      proof,
    }));
    const result = await authorizeCronCommandExecution({
      job,
      runReceipt,
      runClass: "scheduled",
      providerId: "sigil-automation",
    });
    expect(result).toMatchObject({
      kind: "allowed",
      authorization: {
        providerId: "sigil-automation",
        proofRef: `sha256:${"299546ae6a6cae5c7110d7c47258f564d78ceae93168da1033c6e3d46c725194"}`,
      },
    });
    expect(JSON.stringify(result)).not.toContain(proof);
  });

  it("preserves legacy behavior when no provider is configured", async () => {
    const { job } = await makeFixture();
    await expect(authorizeCronCommandExecution({ job, runClass: "manual" })).resolves.toEqual({
      kind: "unprotected",
      job,
    });
  });
});
