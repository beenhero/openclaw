import { writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { __resetProofRegistryForTest } from "../../plugins/capability-approval.js";
import type { ApprovalResolver } from "../../plugins/host-hooks.js";
import { createEmptyPluginRegistry } from "../../plugins/registry-empty.js";
import { setActivePluginRegistry } from "../../plugins/runtime.js";
import { runOpenClawStateWriteTransaction } from "../../state/openclaw-state-db.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { withTempDir } from "../../test-utils/temp-dir.js";
import { publishPythonInlineArtifact } from "../python-inline-artifact.js";
import { saveCronStore } from "../store.js";
import {
  claimCronRunReceiptInDatabase,
  finishCronRunReceipt,
  prepareCronRunReceiptClaim,
  type CronRunReceiptHandle,
} from "../store/run-receipt-store.js";
import type { CronJob } from "../types.js";
import { releaseQueuedCronRun, reserveQueuedCronRun } from "./run-admission.js";
import { createCronServiceState, type CronServiceState } from "./state.js";
import { executeJobCoreWithTimeout } from "./timer-job-runner.js";

const log = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

afterEach(() => {
  __resetProofRegistryForTest();
  setActivePluginRegistry(createEmptyPluginRegistry());
});

function installResolver(resolve: ApprovalResolver): void {
  setActivePluginRegistry({
    ...createEmptyPluginRegistry(),
    approvalResolvers: [
      {
        pluginId: "authorization-timeout-test",
        pluginName: "Authorization timeout test",
        source: "test",
        registration: {
          id: "sigil-automation",
          description: "Delays a test authorization decision",
          scope: { capabilities: ["automation.command"] },
          exclusive: true,
          resolve,
        },
      },
    ],
  });
}

function installDelayedDenial(delayMs: number): void {
  installResolver(
    (request, opts) =>
      new Promise((settle) => {
        const timer = setTimeout(
          () =>
            settle({ requestId: request.requestId, decision: "deny", reason: "owner declined" }),
          delayMs,
        );
        opts.signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            settle({ requestId: request.requestId, decision: "deny", reason: "aborted" });
          },
          { once: true },
        );
      }),
  );
}

async function withFixture(
  run: (fixture: {
    job: CronJob;
    runReceipt: CronRunReceiptHandle;
    runCommandJob: ReturnType<typeof vi.fn>;
    state: CronServiceState;
  }) => Promise<void>,
): Promise<void> {
  await withOpenClawTestState(
    { layout: "state-only", prefix: "openclaw-authorization-timeout-state-" },
    async () =>
      withTempDir("openclaw-authorization-timeout-", async (dir) => {
        const sourcePath = path.join(dir, "job.py");
        await writeFile(sourcePath, "print('must not run')\n");
        const payload = await publishPythonInlineArtifact({
          sourcePath,
          pythonPath: "/usr/bin/python3",
          cwd: dir,
        });
        payload.timeoutSeconds = 0.05;
        const job: CronJob = {
          id: "authorization-outlives-command-budget",
          agentId: "agent-1",
          name: "authorization outlives command budget",
          enabled: true,
          createdAtMs: 1,
          updatedAtMs: 1,
          schedule: { kind: "every", everyMs: 60_000 },
          sessionTarget: "isolated",
          wakeMode: "now",
          payload,
          delivery: { mode: "none" },
          state: { runningAtMs: 20 },
        };
        const storePath = path.join(dir, "cron.json");
        await saveCronStore(storePath, { version: 1, jobs: [job] });
        const prepared = prepareCronRunReceiptClaim({
          storePath,
          job,
          agentId: "agent-1",
          startedAtMs: 20,
        });
        const runReceipt = runOpenClawStateWriteTransaction(({ db }) =>
          claimCronRunReceiptInDatabase({
            database: db,
            prepared,
            resolveAgentId: () => "agent-1",
          }),
        );
        const runCommandJob = vi.fn(async () => ({ status: "ok" as const }));
        const state = createCronServiceState({
          storePath,
          cronEnabled: true,
          cronConfig: { executionAuthorization: { command: "sigil-automation" } },
          log,
          enqueueSystemEvent: vi.fn(),
          requestHeartbeat: vi.fn(),
          runCommandJob,
          runIsolatedAgentJob: vi.fn(async () => ({ status: "ok" as const })),
        });
        const reservationIdentity = reserveQueuedCronRun(state, job.id, 20, { runReceipt });
        try {
          await run({ job, runReceipt, runCommandJob, state });
        } finally {
          releaseQueuedCronRun(state, job.id, reservationIdentity);
          finishCronRunReceipt({
            handle: runReceipt,
            status: "skipped",
            finishedAtMs: 200,
            error: "test cleanup",
          });
        }
      }),
  );
}

describe("authorized command timeout ownership", () => {
  it("does not spend the command process timeout while waiting for authorization", async () => {
    installDelayedDenial(150);
    await withFixture(async ({ job, runReceipt, runCommandJob, state }) => {
      await expect(
        executeJobCoreWithTimeout(state, job, { runReceipt, runClass: "scheduled" }),
      ).resolves.toMatchObject({ status: "skipped", error: "owner declined" });
      expect(runCommandJob).not.toHaveBeenCalled();
    });
  });

  it("classifies authorizer failures as pre-execution and non-retryable", async () => {
    installResolver(async () => {
      throw new Error("authorizer unavailable");
    });
    await withFixture(async ({ job, runReceipt, runCommandJob, state }) => {
      await expect(
        executeJobCoreWithTimeout(state, job, { runReceipt, runClass: "scheduled" }),
      ).resolves.toMatchObject({
        status: "error",
        errorClassification: { kind: "permanent" },
        failureNotificationDetail: { kind: "command-authorization", outcome: "failed" },
        diagnostics: {
          entries: [expect.objectContaining({ source: "cron-preflight" })],
        },
      });
      expect(runCommandJob).not.toHaveBeenCalled();
    });
  });
});
