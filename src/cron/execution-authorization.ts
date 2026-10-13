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
  version: 2;
  capability: typeof CRON_COMMAND_APPROVAL_CAPABILITY;
  definitionDigest: string;
  [key: string]: unknown;
};

export type CronCommandExecutionPlan = {
  version: 2;
  definition: CronCommandExecutionDefinition;
  invocation: {
    runClass: CronAutomationRunClass;
    occurrenceId: string;
    runReceiptId: string;
    configRevision: string;
  };
  executionDigest: string;
  [key: string]: unknown;
};

export type CronCommandActivationPlan = {
  version: 2;
  definition: CronCommandExecutionDefinition;
  activation: {
    activationId: string;
    configRevision: string;
  };
  activationDigest: string;
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
      denialKind?: "policy" | "authorization-required";
      failureDisposition?: "failed" | "timed_out";
    };

export type CronCommandActivationResult =
  | { kind: "unprotected"; job: CronJob }
  | {
      kind: "ready";
      job: CronJob;
      providerId: string;
      authorityRevision: string;
      definitionDigest: string;
      decisionRef: string;
      proofRef: string;
    }
  | Extract<CronCommandAuthorizationResult, { kind: "denied" }>;

function asJson<T>(value: T): T {
  // Callers pass closed data-only snapshots before hashing or storage.
  // SAFETY: the JSON round trip only strips prototypes and undefined fields.
  // oxlint-disable-next-line unicorn/prefer-structured-clone -- Preserve exact JSON transport semantics.
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

/** Build the authority-bearing definition independently from any occurrence. */
export function buildCronCommandAuthorizationDefinition(params: {
  job: CronJob;
  agentId: string;
}): {
  definition: CronCommandExecutionDefinition;
  evidence: JsonObject;
  job: CronJob;
  configRevision: string;
  authorityRevision: string;
} {
  const job = structuredClone(params.job);
  assertAuthorizedCronCommandShape(job);
  const configRevision = resolveCronJobConfigRevision(job);
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
  const authoritySections = asJson({
    capability: CRON_COMMAND_APPROVAL_CAPABILITY,
    job: {
      jobId: job.id,
      createdAtMs: job.createdAtMs,
      agentId: params.agentId,
      owner: {
        agentId: job.owner?.agentId ?? params.agentId,
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
  const authorityRevision = computeParamsDigest({
    version: 1,
    ...authoritySections,
    // SAFETY: authoritySections crossed the closed asJson boundary above.
  } as never);
  const definitionWithoutDigest = asJson({
    version: 2,
    ...authoritySections,
    job: {
      ...authoritySections.job,
      authorityRevision,
    },
  });
  // asJson produced a closed JSON value.
  // SAFETY: the cast narrows only the canonical digest helper's recursive JSON contract.
  const definitionDigest = computeParamsDigest(definitionWithoutDigest as never);
  const definition = {
    ...definitionWithoutDigest,
    definitionDigest,
    // The remaining keys are deliberately extensible.
    // SAFETY: the literals and freshly computed digest satisfy every required field.
  } as CronCommandExecutionDefinition;
  return {
    definition,
    evidence: { stdinValue: input },
    job,
    configRevision,
    authorityRevision,
  };
}

/** Build the exact versioned definition and per-occurrence invocation plan. */
export function buildCronCommandExecutionPlan(params: {
  job: CronJob;
  runReceipt: CronRunReceiptHandle;
  runClass: CronAutomationRunClass;
}): { plan: CronCommandExecutionPlan; evidence: JsonObject; job: CronJob } {
  if (params.runReceipt.jobId !== params.job.id) {
    throw new Error("cron run receipt does not own this job");
  }
  const built = buildCronCommandAuthorizationDefinition({
    job: params.job,
    agentId: params.runReceipt.agentId,
  });
  if (built.configRevision !== params.runReceipt.configRevision) {
    throw new Error("cron execution snapshot does not match its run receipt revision");
  }
  const invocation = asJson({
    runClass: params.runClass,
    occurrenceId: `${params.runClass}:${built.job.state.runningAtMs ?? params.runReceipt.startedAtMs}`,
    runReceiptId: params.runReceipt.receiptId,
    configRevision: params.runReceipt.configRevision,
    // SAFETY: asJson preserves all three required scalar fields in this closed object.
  }) as CronCommandExecutionPlan["invocation"];
  // SAFETY: both members are validated JSON values created above.
  const executionDigest = computeParamsDigest({
    definitionDigest: built.definition.definitionDigest,
    invocation,
    // SAFETY: the digest input contains only the validated definition digest and closed invocation.
  } as never);
  const plan = asJson({
    version: 2,
    definition: built.definition,
    invocation,
    executionDigest,
    // SAFETY: asJson preserves every required field of this finalized, digested plan.
  }) as CronCommandExecutionPlan;
  return {
    plan,
    evidence: built.evidence,
    job: built.job,
  };
}

/** Build a non-executing plan used to acquire or verify standing authority. */
export function buildCronCommandActivationPlan(params: {
  job: CronJob;
  agentId: string;
  activationId?: string;
}): {
  plan: CronCommandActivationPlan;
  evidence: JsonObject;
  job: CronJob;
  authorityRevision: string;
} {
  const built = buildCronCommandAuthorizationDefinition(params);
  const activation = asJson({
    activationId: params.activationId ?? crypto.randomUUID(),
    configRevision: built.configRevision,
    // SAFETY: both required activation fields are closed strings after the asJson boundary.
  }) as CronCommandActivationPlan["activation"];
  const activationDigest = computeParamsDigest({
    definitionDigest: built.definition.definitionDigest,
    activation,
    // SAFETY: the digest input contains only the validated definition digest and closed activation.
  } as never);
  return {
    plan: asJson({
      version: 2,
      definition: built.definition,
      activation,
      activationDigest,
      // SAFETY: every required plan member is validated and the remaining shape is closed by asJson.
    }) as CronCommandActivationPlan,
    evidence: built.evidence,
    job: built.job,
    authorityRevision: built.authorityRevision,
  };
}

/** Acquire or reuse standing authority without executing the command. */
export async function authorizeCronCommandActivation(params: {
  job: CronJob;
  agentId: string;
  providerId?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<CronCommandActivationResult> {
  const providerId = params.providerId?.trim();
  if (!providerId) {
    return { kind: "unprotected", job: params.job };
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
    const built = buildCronCommandActivationPlan({ job: params.job, agentId: params.agentId });
    const effect = asJson({
      kind: CRON_COMMAND_APPROVAL_CAPABILITY,
      plan: built.plan,
      evidence: built.evidence,
      // SAFETY: this closed automation.command value extends EffectDescriptor's base JSON shape.
    }) as unknown as EffectDescriptor;
    const paramsDigest = computeParamsDigest(effect);
    const requestId = crypto.randomUUID();
    const verdict = await decideCapabilityApproval(
      {
        requestId,
        capability: CRON_COMMAND_APPROVAL_CAPABILITY,
        toolName: "automation.authorize",
        effects: [effect],
        agentId: params.agentId,
        sessionKey: params.job.sessionKey ?? `cron:${params.job.id}`,
        runId: built.plan.activation.activationId,
        paramsDigest,
        subject: params.job.name,
        origin: "cron:activation",
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
            ? "configured automation authorizer did not claim the activation request"
            : (verdict.reason ?? "automation activation was not authorized"),
        ...(verdict.kind === "deny" && verdict.failureDisposition
          ? { failureDisposition: verdict.failureDisposition }
          : {}),
        ...(verdict.kind === "deny" && verdict.denialKind
          ? { denialKind: verdict.denialKind }
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
      kind: "ready",
      job: built.job,
      providerId,
      authorityRevision: built.authorityRevision,
      definitionDigest: built.plan.definition.definitionDigest,
      decisionRef: verdict.requestId,
      proofRef: verdict.proofRef,
    };
  } catch (error) {
    return {
      kind: "denied",
      error: error instanceof Error ? error.message : String(error),
      failureDisposition: "failed",
    };
  }
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
      // The closed automation.command descriptor extends EffectDescriptor's base shape.
      // SAFETY: every nested value came from the validated asJson boundary above.
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
            : verdict.denialKind === "authorization-required"
              ? "cron: command authorization required before execution"
              : (verdict.reason ?? "automation execution was not authorized"),
        ...(verdict.kind === "deny" && verdict.failureDisposition
          ? { failureDisposition: verdict.failureDisposition }
          : {}),
        ...(verdict.kind === "deny" && verdict.denialKind
          ? { denialKind: verdict.denialKind }
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
