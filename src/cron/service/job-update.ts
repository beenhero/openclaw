import { isDeepStrictEqual } from "node:util";
import {
  isCronJobActive,
  noteActiveCronJobScheduleMutation,
  noteActiveCronJobTriggerMutation,
  requestActiveCronJobCancellation,
} from "../active-jobs.js";
import { resolveCronJobConfigRevision } from "../config-revision.js";
import { cronSchedulingInputsEqual } from "../schedule-identity.js";
import { createCronStreamSourceIdentity, cronStreamScheduleKey } from "../stream-schedule.js";
import type { CronJob, CronJobPatch } from "../types.js";
import { computeJobNextRunAtMs, hasScheduledNextRunAtMs, isJobEnabled } from "./jobs-scheduling.js";
import { resolveCurrentDefaultAgentId, resolveEffectiveJobAgentId } from "./ops-shared.js";
import { cronRunReceiptOwnerMutationHooks } from "./run-receipts.js";
import { emit, type CronServiceState } from "./state.js";
import { persistOrRestore, type CronRollbackSnapshot } from "./store.js";
import { armTimer } from "./timer.js";

export function normalizeUpdatedEverySchedule(params: {
  job: CronJob;
  nextJob: CronJob;
  now: number;
  scheduleChanged: boolean;
}): void {
  const { job, nextJob, now } = params;
  if (nextJob.schedule.kind === "every") {
    const anchor = nextJob.schedule.anchorMs;
    if (typeof anchor !== "number" || !Number.isFinite(anchor)) {
      // Inherit the previous cadence anchor only for an unchanged-interval
      // re-save (UIs resubmit the schedule without the internal anchorMs).
      // Without this an idempotent edit re-phases the job to now, shifting
      // every future fire time and skipping an already-due slot. A genuine
      // interval change still anchors to the edit time so the new cadence
      // starts now, matching the prior update semantics.
      const previousAnchorMs =
        job.schedule.kind === "every" &&
        job.schedule.everyMs === nextJob.schedule.everyMs &&
        typeof job.schedule.anchorMs === "number" &&
        Number.isFinite(job.schedule.anchorMs)
          ? job.schedule.anchorMs
          : undefined;
      const fallbackAnchorMs =
        previousAnchorMs ??
        (params.scheduleChanged
          ? now
          : typeof nextJob.createdAtMs === "number" && Number.isFinite(nextJob.createdAtMs)
            ? nextJob.createdAtMs
            : now);
      nextJob.schedule = {
        ...nextJob.schedule,
        anchorMs: Math.max(0, Math.floor(fallbackAnchorMs)),
      };
    }
  }
}

function reconcileStreamSourceIdentity(job: CronJob, nextJob: CronJob): void {
  if (nextJob.schedule.kind !== "stream") {
    nextJob.state.streamSourceIdentity = undefined;
    return;
  }
  const sourceChanged =
    job.schedule.kind !== "stream" ||
    cronStreamScheduleKey(job.schedule) !== cronStreamScheduleKey(nextJob.schedule) ||
    isJobEnabled(job) !== isJobEnabled(nextJob);
  const currentIdentity =
    job.schedule.kind === "stream" ? job.state.streamSourceIdentity : undefined;
  nextJob.state.streamSourceIdentity =
    sourceChanged || !currentIdentity ? createCronStreamSourceIdentity() : currentIdentity;
}

export function finalizeUpdatedJob(params: {
  job: CronJob;
  nextJob: CronJob;
  now: number;
  schedulingInputsRequested: boolean;
  scheduleChanged: boolean;
  explicitTriggerState?: CronJobPatch["state"];
}) {
  const { job, nextJob, now } = params;
  normalizeUpdatedEverySchedule(params);
  // Source identity belongs to the durable job mutation, not the process
  // watcher. Equivalent resaves preserve it; disable/enable and source changes
  // rotate it in the same write that changes the public job definition.
  reconcileStreamSourceIdentity(job, nextJob);

  const previousScript = job.payload.kind === "script" ? job.payload.script : undefined;
  const nextScript = nextJob.payload.kind === "script" ? nextJob.payload.script : undefined;
  if (!isDeepStrictEqual(job.trigger, nextJob.trigger) || previousScript !== nextScript) {
    // Trigger and payload scripts share one durable state slot. Exact persisted
    // definitions own it, matching in-flight ownership; explicit replacements win.
    for (const field of [
      "triggerState",
      "triggerEvalCount",
      "lastTriggerEvalAtMs",
      "lastTriggerFireAtMs",
    ] as const) {
      if (params.explicitTriggerState && Object.hasOwn(params.explicitTriggerState, field)) {
        Object.assign(nextJob.state, { [field]: params.explicitTriggerState[field] });
      } else {
        delete nextJob.state[field];
      }
    }
  }

  // Only advance a recurring job's next run when the schedule/enabled inputs
  // actually changed. An idempotent re-save (same schedule, or re-enabling an
  // already-enabled job) must preserve a still-due slot, matching the
  // add/remove maintenance recompute; otherwise the pending run is dropped.
  const schedulingInputsChanged =
    params.schedulingInputsRequested && !cronSchedulingInputsEqual(job, nextJob);

  if (params.scheduleChanged && nextJob.schedule.kind === "cron" && !isJobEnabled(nextJob)) {
    computeJobNextRunAtMs({ ...nextJob, enabled: true }, now);
  }

  nextJob.updatedAtMs = now;
  if (schedulingInputsChanged) {
    // Anchor restart catch-up to the new inputs. Without this, startup replays a
    // slot the previous schedule never had, because lastRunAtMs still belongs to
    // the old one and looks perpetually stale against the new slots (#91944).
    nextJob.state.scheduleActivatedAtMs = now;
    nextJob.state.startupCatchupAtMs = undefined;
    // A paced timestamp is owned by the exact schedule, pacing bounds, and
    // trigger mode that produced it. Configuration changes release both the
    // slot and its provenance so natural schedule math can take ownership.
    nextJob.state.pacedNextRunAtMs = undefined;
    nextJob.state.forcePreservedNextRunAtMs = undefined;
    if (isJobEnabled(nextJob)) {
      nextJob.state.nextRunAtMs = computeJobNextRunAtMs(nextJob, now);
    } else {
      nextJob.state.nextRunAtMs = undefined;
      nextJob.state.queuedAtMs = undefined;
      // Preserve only genuine execution. Queued reservations must clear so a
      // disabled job can accept a later force run with the same timestamp.
      if (!isCronJobActive(nextJob.id)) {
        nextJob.state.runningAtMs = undefined;
      }
    }
  } else if (isJobEnabled(nextJob) && !hasScheduledNextRunAtMs(nextJob.state.nextRunAtMs)) {
    nextJob.state.nextRunAtMs = computeJobNextRunAtMs(nextJob, now);
  }
}

export async function persistUpdatedJob(params: {
  state: CronServiceState;
  snapshot: CronRollbackSnapshot;
  previousJob: CronJob;
  nextJob: CronJob;
}) {
  const { state, snapshot, previousJob, nextJob } = params;
  if (
    nextJob.state.queuedAtMs !== undefined &&
    resolveCronJobConfigRevision(previousJob) !== resolveCronJobConfigRevision(nextJob)
  ) {
    // Retire the occurrence with its owning edit; A→B→A cannot revive a queued snapshot.
    delete nextJob.state.queuedAtMs;
  }
  if (state.store) {
    const index = state.store.jobs.findIndex((entry) => entry.id === nextJob.id);
    if (index >= 0) {
      state.store.jobs[index] = nextJob;
    }
  }

  const defaultAgentId = resolveCurrentDefaultAgentId(state);
  const ownerChanged =
    resolveEffectiveJobAgentId(previousJob, defaultAgentId) !==
    resolveEffectiveJobAgentId(nextJob, defaultAgentId);
  await persistOrRestore(state, snapshot, {
    suppressScheduledJobId: nextJob.id,
    transactionHooks: ownerChanged
      ? cronRunReceiptOwnerMutationHooks({ state, jobId: nextJob.id })
      : undefined,
  });
  if (!cronSchedulingInputsEqual(previousJob, nextJob)) {
    // Mark only committed edits; a failed SQLite write cannot retire the run's
    // schedule ownership, and idempotent re-saves must not create a new claim.
    noteActiveCronJobScheduleMutation(nextJob.id);
  }
  if (isJobEnabled(previousJob) && !isJobEnabled(nextJob)) {
    requestActiveCronJobCancellation(nextJob.id, "Cron job disabled by operator.");
  }
  if (
    !isDeepStrictEqual(previousJob.trigger, nextJob.trigger) ||
    !isDeepStrictEqual(previousJob.state.triggerState, nextJob.state.triggerState) ||
    ((previousJob.payload.kind === "script" || nextJob.payload.kind === "script") &&
      !isDeepStrictEqual(previousJob.payload, nextJob.payload))
  ) {
    // Trigger/script definitions and shared-state edits retire the admitted
    // state writer; otherwise an obsolete evaluation or script wins later.
    noteActiveCronJobTriggerMutation(nextJob.id);
  }
  armTimer(state);
  emit(state, {
    jobId: nextJob.id,
    action: "updated",
    job: nextJob,
    nextRunAtMs: nextJob.state.nextRunAtMs,
  });
}
