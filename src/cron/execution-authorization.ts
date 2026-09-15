import crypto from "node:crypto";
import path from "node:path";
import { OPENCLAW_CLI_ENV_VAR } from "../infra/openclaw-exec-env.js";
import { getApprovalResolverForScope } from "../plugins/approval-resolver.js";
import { computeParamsDigest, decideCapabilityApproval } from "../plugins/capability-approval.js";
import type { EffectDescriptor } from "../plugins/host-hooks.js";
import { resolveCommandEnv } from "../process/exec-spawn.js";
import { resolveCronCommandExecutionLimits } from "./command-runner.js";
import { resolveCronJobConfigRevision } from "./config-revision.js";
import { resolveCronDeliveryPlan } from "./delivery-plan.js";
import {
  parsePythonInlineFrame,
  PYTHON_INLINE_ARTIFACT_FORMAT,
  PYTHON_INLINE_BOOTSTRAP_SHA256,
  PYTHON_INLINE_BOOTSTRAP_V1,
} from "./python-inline-artifact.js";
import type { CronRunReceiptHandle } from "./store/run-receipt-store.js";
import { CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES, type CronJob } from "./types.js";

export const CRON_COMMAND_APPROVAL_CAPABILITY = "automation.command" as const;
export const CRON_COMMAND_APPROVAL_TOOL = "automation.execute" as const;
export const DEFAULT_CRON_COMMAND_APPROVAL_TIMEOUT_MS = 5 * 60_000;

export type CronAutomationRunClass = "scheduled" | "startup-catchup" | "manual";

type JsonObject = Record<string, unknown>;

export type CronCommandExecutionDefinition = {
  version: 1;
  capability: typeof CRON_COMMAND_APPROVAL_CAPABILITY;
  definitionDigest: string;
  [key: string]: unknown;
};

export type CronCommandExecutionPlan = {
  version: 1;
  definition: CronCommandExecutionDefinition;
  invocation: {
    runClass: CronAutomationRunClass;
    occurrenceId: string;
    runReceiptId: string;
  };
  executionDigest: string;
  [key: string]: unknown;
};

export type CronCommandAuthorization = {
  providerId: string;
  decisionRef: string;
  proofRef: string;
  paramsDigest: string;
  plan: CronCommandExecutionPlan;
  job: CronJob;
};

export type CronCommandAuthorizationResult =
  | { kind: "unprotected"; job: CronJob }
  | { kind: "allowed"; authorization: CronCommandAuthorization }
  | {
      kind: "denied";
      error: string;
      failureDisposition?: "failed" | "timed_out";
    };

function asJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function assertAuthorizedCronCommandShape(job: CronJob): asserts job is CronJob & {
  payload: Extract<CronJob["payload"], { kind: "command" }>;
} {
  if (job.payload.kind !== "command") {
    throw new Error("automation authorization requires a command payload");
  }
  const payload = job.payload;
  if (job.sessionTarget === "main") {
    throw new Error("authorized command automations require a detached session target");
  }
  if (job.trigger) {
    throw new Error("authorized command automations do not support pre-authorization triggers");
  }
  if (job.schedule.kind === "stream" || job.schedule.kind === "on-exit") {
    throw new Error("authorized command automations require a time-based schedule");
  }
  if (payload.envMode !== "replace") {
    throw new Error('authorized command payload requires envMode="replace"');
  }
  if (!payload.cwd || !path.isAbsolute(payload.cwd)) {
    throw new Error("authorized command payload requires an absolute cwd");
  }
  if (
    !Array.isArray(payload.argv) ||
    payload.argv.length === 0 ||
    !path.isAbsolute(payload.argv[0]!)
  ) {
    throw new Error("authorized command payload requires an absolute executable argv[0]");
  }
  if (!payload.artifact || payload.artifact.format !== PYTHON_INLINE_ARTIFACT_FORMAT) {
    throw new Error("authorized command payload requires an immutable Python artifact");
  }
  if (typeof payload.input !== "string") {
    throw new Error("authorized command payload requires its frozen stdin frame");
  }
  if (
    payload.argv.length !== 5 ||
    payload.argv[1] !== "-I" ||
    payload.argv[2] !== "-S" ||
    payload.argv[3] !== "-c" ||
    payload.argv[4] !== PYTHON_INLINE_BOOTSTRAP_V1
  ) {
    throw new Error("authorized Python command does not use the fixed bootstrap");
  }
  const frame = parsePythonInlineFrame(payload.input);
  const artifact = payload.artifact;
  if (
    artifact.bootstrapSha256 !== PYTHON_INLINE_BOOTSTRAP_SHA256 ||
    artifact.sourceSha256 !== frame.sourceSha256 ||
    artifact.sourceBytes !== frame.sourceBytes ||
    artifact.virtualFilename !== frame.virtualFilename ||
    artifact.displayPath !== frame.displayPath
  ) {
    throw new Error("authorized Python artifact metadata does not match its stdin frame");
  }
  if (payload.continuation) {
    const continuation = payload.continuation;
    if (
      continuation.kind !== "agentTurn" ||
      continuation.on !== "command-success" ||
      continuation.input !== "stdout" ||
      continuation.inputTrust !== "external" ||
      !continuation.instructions.trim() ||
      !Number.isSafeInteger(continuation.inputMaxBytes) ||
      continuation.inputMaxBytes < 1 ||
      continuation.inputMaxBytes > CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES ||
      !Array.isArray(continuation.toolsAllow)
    ) {
      throw new Error("authorized command continuation is not a closed external-content plan");
    }
  }
}

/** Build the exact versioned definition and per-occurrence invocation plan. */
export function buildCronCommandExecutionPlan(params: {
  job: CronJob;
  runReceipt: CronRunReceiptHandle;
  runClass: CronAutomationRunClass;
}): { plan: CronCommandExecutionPlan; evidence: JsonObject; job: CronJob } {
  const job = structuredClone(params.job);
  assertAuthorizedCronCommandShape(job);
  if (params.runReceipt.jobId !== job.id) {
    throw new Error("cron run receipt does not own this job");
  }
  if (resolveCronJobConfigRevision(job) !== params.runReceipt.configRevision) {
    throw new Error("cron execution snapshot does not match its run receipt revision");
  }
  const payload = job.payload;
  const consequences =
    payload.consequences ??
    ({
      summary: "Run the exact published command with the Gateway OS account's ambient access.",
      filesystem: { access: "ambient-host-user", disclosures: [] },
      network: { access: "ambient-host-user", disclosures: [] },
      dependencies: [],
    } as const);
  const finalEnvironment = resolveCommandEnv({
    argv: payload.argv,
    baseEnv: {},
    env: payload.env,
  });
  // Keep the marker explicit in the signed definition even if the process
  // implementation later refactors its helper.
  finalEnvironment[OPENCLAW_CLI_ENV_VAR] = "1";
  const input = payload.input!;
  const limits = resolveCronCommandExecutionLimits(payload);
  const definitionWithoutDigest = asJson({
    version: 1,
    capability: CRON_COMMAND_APPROVAL_CAPABILITY,
    job: {
      jobId: job.id,
      createdAtMs: job.createdAtMs,
      configRevision: params.runReceipt.configRevision,
      agentId: params.runReceipt.agentId,
      owner: {
        agentId: job.owner?.agentId ?? params.runReceipt.agentId,
        ...(job.owner?.accountId ? { accountId: job.owner.accountId } : {}),
      },
    },
    automation: {
      schedule: job.schedule,
      ...(job.pacing ? { pacing: job.pacing } : {}),
      sessionTarget: job.sessionTarget,
      wakeMode: job.wakeMode,
      delivery: resolveCronDeliveryPlan(job),
    },
    process: {
      argv: payload.argv,
      cwd: payload.cwd,
      environment: { mode: "replace", values: finalEnvironment },
      stdin: {
        encoding: "utf8",
        sha256: sha256Hex(input),
        bytes: Buffer.byteLength(input, "utf8"),
      },
      timeoutMs: limits.timeoutMs,
      ...(limits.noOutputTimeoutMs !== undefined
        ? { noOutputTimeoutMs: limits.noOutputTimeoutMs }
        : {}),
      maxOutputBytes: limits.maxOutputBytes,
    },
    runtime: {
      profileId: "host-path-only-v1",
      executablePath: payload.argv[0],
      attestation: `path-only:${payload.argv[0]}`,
      dependencyAttestations: consequences.dependencies.map(
        (dependency) => `declared:${dependency}`,
      ),
    },
    artifact: payload.artifact,
    consequences,
    ...(payload.continuation ? { continuation: payload.continuation } : {}),
  });
  const definitionDigest = computeParamsDigest(definitionWithoutDigest as never);
  const definition = {
    ...definitionWithoutDigest,
    definitionDigest,
  } as CronCommandExecutionDefinition;
  const invocation = asJson({
    runClass: params.runClass,
    occurrenceId: `${params.runClass}:${job.state.runningAtMs ?? params.runReceipt.startedAtMs}`,
    runReceiptId: params.runReceipt.receiptId,
  }) as CronCommandExecutionPlan["invocation"];
  const executionDigest = computeParamsDigest({ definitionDigest, invocation } as never);
  const plan = asJson({
    version: 1,
    definition,
    invocation,
    executionDigest,
  }) as CronCommandExecutionPlan;
  return {
    plan,
    evidence: { stdinValue: input },
    job,
  };
}

/**
 * Resolve a configured provider before the runner. Absence preserves legacy
 * command behavior; once configured, every mismatch or resolver failure denies.
 */
export async function authorizeCronCommandExecution(params: {
  job: CronJob;
  runReceipt?: CronRunReceiptHandle;
  runClass: CronAutomationRunClass;
  providerId?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<CronCommandAuthorizationResult> {
  const providerId = params.providerId?.trim();
  if (!providerId) {
    return { kind: "unprotected", job: params.job };
  }
  if (!params.runReceipt) {
    return { kind: "denied", error: "authorized command run is missing its durable receipt" };
  }

  try {
    const entry = getApprovalResolverForScope(CRON_COMMAND_APPROVAL_CAPABILITY);
    let registeredId: string | undefined;
    try {
      registeredId = entry?.registration.id;
    } catch {
      registeredId = undefined;
    }
    if (!entry || registeredId !== providerId) {
      return {
        kind: "denied",
        error: `configured automation authorizer ${JSON.stringify(providerId)} is unavailable`,
        failureDisposition: "failed",
      };
    }
    const built = buildCronCommandExecutionPlan({
      job: params.job,
      runReceipt: params.runReceipt,
      runClass: params.runClass,
    });
    const effect = asJson({
      kind: CRON_COMMAND_APPROVAL_CAPABILITY,
      plan: built.plan,
      evidence: built.evidence,
    }) as unknown as EffectDescriptor;
    const paramsDigest = computeParamsDigest(effect);
    const requestId = crypto.randomUUID();
    const verdict = await decideCapabilityApproval(
      {
        requestId,
        capability: CRON_COMMAND_APPROVAL_CAPABILITY,
        toolName: CRON_COMMAND_APPROVAL_TOOL,
        effects: [effect],
        agentId: params.runReceipt.agentId,
        sessionKey: params.job.sessionKey ?? `cron:${params.job.id}`,
        runId: params.runReceipt.receiptId,
        paramsDigest,
        subject: params.job.name,
        origin: `cron:${params.runClass}`,
      },
      {
        deadlineMs: params.timeoutMs ?? DEFAULT_CRON_COMMAND_APPROVAL_TIMEOUT_MS,
        signal: params.signal,
      },
    );
    if (verdict.kind !== "allow") {
      return {
        kind: "denied",
        error:
          verdict.kind === "fallthrough"
            ? "configured automation authorizer did not claim the request"
            : (verdict.reason ?? "automation execution was not authorized"),
        ...(verdict.kind === "deny" && verdict.failureDisposition
          ? { failureDisposition: verdict.failureDisposition }
          : {}),
      };
    }
    if (!verdict.proofRef) {
      return {
        kind: "denied",
        error: "configured automation authorizer returned no durable proof reference",
        failureDisposition: "failed",
      };
    }
    return {
      kind: "allowed",
      authorization: {
        providerId,
        decisionRef: verdict.requestId,
        proofRef: verdict.proofRef,
        paramsDigest,
        plan: built.plan,
        job: built.job,
      },
    };
  } catch (error) {
    return {
      kind: "denied",
      error: error instanceof Error ? error.message : String(error),
      failureDisposition: "failed",
    };
  }
}
