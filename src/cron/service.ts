import { authorizeCronCommandActivation } from "./execution-authorization.js";
/** Stateful CronService facade around the locked service operation helpers. */
import type {
  CronServiceContract,
  CronServiceRunOptions,
  CronServiceRunResult,
} from "./service-contract.js";
import type { CronListPageOptions } from "./service/list-page-types.js";
import * as lifecycleOps from "./service/ops-lifecycle.js";
import * as mutationOps from "./service/ops-mutations.js";
import * as readOps from "./service/ops-read.js";
import * as runOps from "./service/ops-run.js";
import { resolveCurrentDefaultAgentId, resolveEffectiveJobAgentId } from "./service/ops-shared.js";
import {
  type CronAddOptions,
  type CronServiceDeps,
  type CronRunMode,
  type CronUpdatePrecondition,
  type CronUpdateOptions,
  type CronWakeMode,
  createCronServiceState,
} from "./service/state.js";
import type { CronJob, CronJobCreate, CronJobPatch } from "./types.js";

export type { CronEvent } from "./service/state.js";

/** Public cron service facade that owns mutable scheduler state and delegates to locked ops. */
export class CronService implements CronServiceContract {
  stopAndDrain?: () => Promise<void>;
  private readonly state;
  private startInProgress = 0;
  private startState: { generation: number; promise: Promise<void> } | null = null;
  private readonly commandAuthorizationAttempts = new Map<
    string,
    {
      controller: AbortController;
      promise: Promise<void>;
      providerId: string;
      authorityRevision: string;
      definitionDigest: string;
    }
  >();

  constructor(deps: CronServiceDeps) {
    this.state = createCronServiceState(deps);
  }

  async start() {
    const generation = this.state.lifecycleGeneration;
    const pending = this.startState;
    if (pending) {
      try {
        await pending.promise;
      } catch (err) {
        if (pending.generation === generation) {
          throw err;
        }
      }
      if (pending.generation === generation) {
        return;
      }
      await this.start();
      return;
    }
    const promise = this.startOnce(generation);
    this.startState = { generation, promise };
    try {
      await promise;
    } finally {
      if (this.startState?.promise === promise) {
        this.startState = null;
      }
    }
  }

  private async startOnce(generation: number) {
    this.startInProgress += 1;
    this.state.schedulerStarted = false;
    try {
      await lifecycleOps.start(this.state);
      if (generation !== this.state.lifecycleGeneration) {
        lifecycleOps.stop(this.state);
        return;
      }
      this.state.schedulerStarted = !this.state.stopped;
      for (const job of this.state.store?.jobs ?? []) {
        this.reconcileCommandAuthorization(job);
      }
    } finally {
      this.startInProgress -= 1;
    }
  }

  stop() {
    for (const attempt of this.commandAuthorizationAttempts.values()) {
      attempt.controller.abort(new Error("cron service stopped"));
    }
    this.commandAuthorizationAttempts.clear();
    lifecycleOps.stop(this.state);
  }

  pauseScheduling() {
    lifecycleOps.pauseScheduling(this.state);
  }

  resumeScheduling() {
    lifecycleOps.resumeScheduling(this.state);
  }

  getSuspensionBlockerCount() {
    return this.startInProgress;
  }

  async status() {
    return await readOps.status(this.state);
  }

  async list(opts?: { includeDisabled?: boolean }) {
    return await readOps.list(this.state, opts);
  }

  async listPage(opts?: CronListPageOptions) {
    return await readOps.listPage(this.state, opts);
  }

  async add(input: CronJobCreate, opts?: CronAddOptions) {
    const result = await mutationOps.add(this.state, input, opts);
    this.reconcileCommandAuthorization("job" in result ? result.job : result);
    return result;
  }

  async removeStaleJobFamily(
    family: { declarationKey: string; name: string; ownerPluginTag: string },
    opts?: { commitGuard?: () => void },
  ) {
    const removed = await mutationOps.removeStaleJobFamily(this.state, family, opts);
    this.pruneCommandAuthorizationAttempts();
    return removed;
  }

  async update(id: string, patch: CronJobPatch, opts?: CronUpdateOptions) {
    const result = await mutationOps.update(this.state, id, patch, opts);
    this.reconcileCommandAuthorization(result);
    return result;
  }

  async updateWithPrecondition(
    id: string,
    patch: CronJobPatch,
    precondition: CronUpdatePrecondition,
    opts?: CronUpdateOptions,
  ) {
    const result = await mutationOps.updateWithPrecondition(
      this.state,
      id,
      patch,
      precondition,
      opts,
    );
    this.reconcileCommandAuthorization(result);
    return result;
  }

  private reconcileCommandAuthorization(job: CronJob): void {
    const staged = job.state.commandAuthorization;
    const active = this.commandAuthorizationAttempts.get(job.id);
    if (!staged || staged.status !== "required" || job.payload.kind !== "command") {
      if (active) {
        active.controller.abort(new Error("cron command authorization no longer required"));
        this.commandAuthorizationAttempts.delete(job.id);
      }
      return;
    }
    if (
      active?.providerId === staged.providerId &&
      active.authorityRevision === staged.authorityRevision &&
      active.definitionDigest === staged.definitionDigest
    ) {
      return;
    }
    if (active) {
      active.controller.abort(new Error("cron command authorization definition changed"));
      this.commandAuthorizationAttempts.delete(job.id);
    }

    const controller = new AbortController();
    const snapshot = structuredClone(job);
    const agentId = resolveEffectiveJobAgentId(snapshot, resolveCurrentDefaultAgentId(this.state));
    const authorize = async () => {
      const result = await authorizeCronCommandActivation({
        job: snapshot,
        agentId,
        providerId: staged.providerId,
        signal: controller.signal,
      });
      if (controller.signal.aborted) {
        return;
      }
      if (result.kind === "ready") {
        await mutationOps.completeCommandAuthorization(this.state, {
          jobId: snapshot.id,
          providerId: result.providerId,
          authorityRevision: result.authorityRevision,
          definitionDigest: result.definitionDigest,
          allowed: true,
          decisionRef: result.decisionRef,
          proofRef: result.proofRef,
        });
        return;
      }
      await mutationOps.completeCommandAuthorization(this.state, {
        jobId: snapshot.id,
        providerId: staged.providerId,
        authorityRevision: staged.authorityRevision,
        definitionDigest: staged.definitionDigest,
        allowed: false,
        reason:
          result.kind === "denied"
            ? result.denialKind === "authorization-required"
              ? "standing authorization required"
              : result.error
            : "command authorizer is no longer configured",
      });
    };
    const promise = (
      this.state.deps.runSchedulerOwned ? this.state.deps.runSchedulerOwned(authorize) : authorize()
    )
      .catch((error: unknown) => {
        this.state.deps.log.warn(
          { jobId: snapshot.id, err: String(error) },
          "cron: command activation authorization failed",
        );
      })
      .finally(() => {
        const currentAttempt = this.commandAuthorizationAttempts.get(snapshot.id);
        if (currentAttempt?.controller === controller) {
          this.commandAuthorizationAttempts.delete(snapshot.id);
        }
      });
    this.commandAuthorizationAttempts.set(job.id, {
      controller,
      promise,
      providerId: staged.providerId,
      authorityRevision: staged.authorityRevision,
      definitionDigest: staged.definitionDigest,
    });
  }

  async remove(id: string, opts?: { systemOwned?: boolean; commitGuard?: () => void }) {
    const removed = await mutationOps.remove(this.state, id, opts);
    if (removed.removed) {
      const active = this.commandAuthorizationAttempts.get(id);
      active?.controller.abort(new Error("cron job removed"));
      this.commandAuthorizationAttempts.delete(id);
    }
    return removed;
  }

  async removeAgentJobsTransactional<T>(agentId: string, commit: () => Promise<T>): Promise<T> {
    const result = await mutationOps.removeAgentJobsTransactional(this.state, agentId, commit);
    this.pruneCommandAuthorizationAttempts();
    return result;
  }

  private pruneCommandAuthorizationAttempts(): void {
    const existingJobIds = new Set((this.state.store?.jobs ?? []).map((job) => job.id));
    for (const [jobId, active] of this.commandAuthorizationAttempts) {
      if (existingJobIds.has(jobId)) {
        continue;
      }
      active.controller.abort(new Error("cron job removed"));
      this.commandAuthorizationAttempts.delete(jobId);
    }
  }

  async quiesceJobs(jobs: readonly { id: string; revision: string }[], commitGuard: () => void) {
    await mutationOps.quiesceJobs(this.state, jobs, commitGuard);
  }

  async run(
    id: string,
    mode?: CronRunMode,
    opts?: CronServiceRunOptions,
  ): Promise<CronServiceRunResult> {
    return await runOps.run(this.state, id, mode, opts);
  }

  async enqueueRun(
    id: string,
    mode?: CronRunMode,
    opts?: { commitGuard?: () => void },
  ): Promise<CronServiceRunResult> {
    const result = await runOps.enqueueRun(this.state, id, mode, opts);
    if (result.ok && "runnable" in result) {
      // ops.enqueueRun resolves runnable dispositions before crossing the
      // public facade; leaking one would expose an internal scheduler detail.
      throw new Error("cron enqueueRun returned unresolved runnable disposition");
    }
    return result;
  }

  getJob(id: string): CronJob | undefined {
    return this.state.store?.jobs.find((job) => job.id === id);
  }

  /** In-memory job snapshot; undefined until the store is loaded. */
  getLoadedJobs(): readonly CronJob[] | undefined {
    return this.state.store?.jobs;
  }

  async readJob(id: string): Promise<CronJob | undefined> {
    return await readOps.readJob(this.state, id);
  }

  async readScratch(id: string) {
    return await readOps.readScratch(this.state, id);
  }

  async writeScratch(
    id: string,
    params: {
      content: string | null;
      expectedRevision?: number;
      sourceSha256?: string;
      commitGuard?: () => void;
    },
  ) {
    return await readOps.writeScratch(this.state, id, params);
  }

  async recordExternalFailure(
    id: string,
    error: string,
    statePatch: Partial<CronJob["state"]>,
    source?: { scheduleKey: string; identity: string },
  ): Promise<void> {
    await readOps.recordExternalFailure(this.state, id, error, statePatch, source);
  }

  async updateExternalState(
    id: string,
    streamScheduleKey: string,
    streamSourceIdentity: string,
    statePatch: Partial<CronJob["state"]>,
  ): Promise<boolean> {
    return await readOps.updateExternalState(
      this.state,
      id,
      streamScheduleKey,
      streamSourceIdentity,
      statePatch,
    );
  }

  async retireExternalStreamSource(
    id: string,
    streamScheduleKey: string,
    streamSourceIdentity: string,
  ): Promise<string | undefined> {
    return await readOps.retireExternalStreamSource(
      this.state,
      id,
      streamScheduleKey,
      streamSourceIdentity,
    );
  }

  async updateExternalCounters(
    id: string,
    counters: Pick<CronJob["state"], "streamDroppedBatches" | "streamCoalescedBatches">,
  ): Promise<void> {
    await readOps.updateExternalCounters(this.state, id, counters);
  }

  getDefaultAgentId(): string | undefined {
    return this.state.deps.resolveDefaultAgentId
      ? this.state.deps.resolveDefaultAgentId()
      : this.state.deps.defaultAgentId;
  }

  wake(opts: { mode: CronWakeMode; text: string; sessionKey?: string; agentId?: string }) {
    return runOps.wakeNow(this.state, opts);
  }
}
