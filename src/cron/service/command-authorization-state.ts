import { buildCronCommandAuthorizationDefinition } from "../execution-authorization.js";
import type { CronJob, CronStoredJob } from "../types.js";
import { finalizeUpdatedJob, persistUpdatedJob } from "./job-update.js";
import { locked } from "./locked.js";
import { resolveCurrentDefaultAgentId, resolveEffectiveJobAgentId } from "./ops-shared.js";
import type { CronServiceState } from "./state.js";
import { ensureLoadedForOperation, snapshotStoreForRollback } from "./store.js";

/** Persist an exact authority request before a protected command can be scheduled. */
export function stageCommandAuthorization(params: {
  state: CronServiceState;
  previousJob?: CronJob;
  nextJob: CronStoredJob;
  explicitlyDisabled?: boolean;
}): boolean {
  const { state, previousJob, nextJob } = params;
  const providerId = state.deps.cronConfig?.executionAuthorization?.command?.trim();
  if (params.explicitlyDisabled) {
    delete nextJob.state.commandAuthorization;
    return false;
  }
  if (!providerId || nextJob.payload.kind !== "command") {
    delete nextJob.state.commandAuthorization;
    return false;
  }
  const previousAuthorization = previousJob?.state.commandAuthorization;
  const activationRequested = nextJob.enabled || previousAuthorization?.status === "required";
  if (!activationRequested) {
    return false;
  }

  const agentId = resolveEffectiveJobAgentId(nextJob, resolveCurrentDefaultAgentId(state));
  const nextAuthority = buildCronCommandAuthorizationDefinition({ job: nextJob, agentId });
  const sameAuthorization =
    previousAuthorization?.providerId === providerId &&
    previousAuthorization.authorityRevision === nextAuthority.authorityRevision &&
    previousAuthorization.definitionDigest === nextAuthority.definition.definitionDigest;
  if (sameAuthorization && previousAuthorization?.status === "ready") {
    nextJob.state.commandAuthorization = previousAuthorization;
    return false;
  }

  const schedulingWasActive =
    nextJob.enabled ||
    nextJob.state.nextRunAtMs !== undefined ||
    nextJob.state.queuedAtMs !== undefined;
  nextJob.enabled = false;
  nextJob.state.nextRunAtMs = undefined;
  nextJob.state.queuedAtMs = undefined;
  nextJob.state.commandAuthorization =
    sameAuthorization && previousAuthorization?.status === "required"
      ? previousAuthorization
      : {
          status: "required",
          providerId,
          authorityRevision: nextAuthority.authorityRevision,
          definitionDigest: nextAuthority.definition.definitionDigest,
          updatedAtMs: state.deps.nowMs(),
        };
  return !sameAuthorization || schedulingWasActive;
}

/** Complete a non-executing command authorization against the exact staged authority. */
export async function completeCommandAuthorization(
  state: CronServiceState,
  params: {
    jobId: string;
    providerId: string;
    authorityRevision: string;
    definitionDigest: string;
    allowed: boolean;
    decisionRef?: string;
    proofRef?: string;
    reason?: string;
  },
): Promise<CronJob | undefined> {
  return await locked(state, async () => {
    await ensureLoadedForOperation(state);
    const current = state.store?.jobs.find((job) => job.id === params.jobId);
    const staged = current?.state.commandAuthorization;
    if (
      !current ||
      !staged ||
      staged.providerId !== params.providerId ||
      staged.authorityRevision !== params.authorityRevision ||
      staged.definitionDigest !== params.definitionDigest
    ) {
      return undefined;
    }
    const agentId = resolveEffectiveJobAgentId(current, resolveCurrentDefaultAgentId(state));
    const authority = buildCronCommandAuthorizationDefinition({ job: current, agentId });
    if (
      authority.authorityRevision !== params.authorityRevision ||
      authority.definition.definitionDigest !== params.definitionDigest
    ) {
      return undefined;
    }

    const now = state.deps.nowMs();
    const nextJob = structuredClone(current);
    if (params.allowed) {
      if (!params.decisionRef || !params.proofRef) {
        throw new Error("completed command authorization is missing its durable proof reference");
      }
      nextJob.enabled = true;
      nextJob.state.commandAuthorization = {
        status: "ready",
        providerId: params.providerId,
        authorityRevision: params.authorityRevision,
        definitionDigest: params.definitionDigest,
        decisionRef: params.decisionRef,
        proofRef: params.proofRef,
        updatedAtMs: now,
      };
      delete nextJob.state.autoDisabled;
      nextJob.state.consecutiveErrors = 0;
      nextJob.state.scheduleErrorCount = 0;
      finalizeUpdatedJob({
        job: current,
        nextJob,
        now,
        schedulingInputsRequested: true,
        scheduleChanged: false,
      });
    } else {
      nextJob.enabled = false;
      nextJob.state.nextRunAtMs = undefined;
      nextJob.state.commandAuthorization = {
        ...staged,
        updatedAtMs: now,
        ...(params.reason ? { reason: params.reason } : {}),
      };
      nextJob.updatedAtMs = now;
    }
    const snapshot = snapshotStoreForRollback(state);
    await persistUpdatedJob({
      state,
      snapshot,
      previousJob: current,
      nextJob,
    });
    return nextJob;
  });
}
