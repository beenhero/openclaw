/**
 * Layer 4, Dispatch A — native front-stage resolver helpers.
 *
 * Provides the classify→pickOwner→decide→HookOutcome pipeline that runs
 * BEFORE the trusted-policy block (~:1637) and plugin-hook block (~:1720) in
 * runBeforeToolCallHook. These helpers are intentionally kept pure and
 * composable so each task (L4.1–L4.5) can be unit-tested in isolation.
 *
 * Insertion point: src/agents/agent-tools.before-tool-call.ts ~:1536 (after
 * loop-detection close at :1535, before getGlobalHookRunner at :1537).
 *
 * Fail-closed invariants:
 *  - classifyEffects throw → SUPERSET_EFFECTS (never [])
 *  - no resolver for capability → return undefined (fallthrough, byte-unchanged)
 *  - decideCapabilityApproval deny → blocked veto/failure outcome
 *  - params MUST be non-undefined on blocked outcomes
 *
 * Note on pickOwner vs approval-bridge.ts ~:590:
 * The codex approval-bridge uses the same process.exec-wins rule. These two
 * implementations are intentionally kept separate (different call sites, different
 * import paths); a future de-dup slice may unify them.
 */

import crypto from "node:crypto";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { hasApprovalResolverForScope } from "../plugins/approval-resolver.js";
import { decideCapabilityApproval } from "../plugins/capability-approval.js";
import {
  classifyEffects,
  SUPERSET_EFFECTS,
  digestForEffects,
} from "../plugins/effect-classifier.js";
import type { EffectDescriptor, ApprovalRequest } from "../plugins/host-hooks.js";

/**
 * Minimal HookContext fields consumed by the front-stage resolver.
 * Mirrors agent-tools.before-tool-call.ts:HookContext without importing from
 * that module (avoids a circular dependency when before-tool-call imports us).
 */
type FrontStageCtx = {
  agentId?: string;
  config?: OpenClawConfig;
  sessionKey?: string;
  runId?: string;
};

/**
 * Mirrors BeforeToolCallFailureDisposition from agent-tools.before-tool-call.ts
 * without importing from it. Values: "blocked" | "failed" | "cancelled" | "timed_out".
 */
type FrontStageFailureDisposition = "blocked" | "failed" | "cancelled" | "timed_out";

// ---------------------------------------------------------------------------
// L4.2 — default timeout
// ---------------------------------------------------------------------------

/**
 * Conservative default for the front-stage resolver decision timeout.
 * Overridable via config.approvals.frontStageResolverTimeoutMs.
 */
export const DEFAULT_FRONT_STAGE_RESOLVER_TIMEOUT_MS = 500;

// ---------------------------------------------------------------------------
// L4.3 — pickOwner: one-command-one-decision
// ---------------------------------------------------------------------------

/**
 * Select the single "owner" capability for a classified effect set.
 *
 * Rule: process.exec wins when present (strictly broader capability — you cannot
 * egress without executing the process). Otherwise the first effect's kind is
 * used (only one egress capability expected in the non-curl case).
 *
 * NOTE: This mirrors the approval-bridge.ts ~:590 rule exactly. A future
 * de-dup slice may unify them into a shared helper in effect-classifier.ts.
 *
 * @param effects - The classified EffectDescriptor set (non-empty).
 * @returns The capability kind string that should own the decision.
 */
export function pickOwner(effects: readonly EffectDescriptor[]): string {
  if (effects.some((e) => e.kind === "process.exec")) {
    return "process.exec";
  }
  return effects[0]?.kind ?? "net.egress";
}

// ---------------------------------------------------------------------------
// L4.4 — buildFrontStageApprovalRequest
// ---------------------------------------------------------------------------

/**
 * Build the ApprovalRequest for the front-stage resolver.
 *
 * @param effects   - Classified EffectDescriptor set (from classifyEffects or SUPERSET).
 * @param toolName  - Already-normalized tool name (from runBeforeToolCallHook).
 * @param ctx       - FrontStageCtx (for agentId/sessionKey/runId).
 * @param toolCallId - Optional tool call id; used as requestId when present.
 */
export function buildFrontStageApprovalRequest(
  effects: readonly EffectDescriptor[],
  toolName: string,
  ctx: Pick<FrontStageCtx, "agentId" | "sessionKey" | "runId"> | undefined | null,
  toolCallId: string | undefined,
): ApprovalRequest {
  const requestId = toolCallId ?? crypto.randomUUID();
  return {
    requestId,
    capability: pickOwner(effects),
    toolName,
    effects,
    paramsDigest: digestForEffects(effects),
    ...(ctx?.agentId ? { agentId: ctx.agentId } : {}),
    ...(ctx?.sessionKey ? { sessionKey: ctx.sessionKey } : {}),
    ...(ctx?.runId ? { runId: ctx.runId } : {}),
    ...(toolCallId ? { toolCallId } : {}),
  };
}

// ---------------------------------------------------------------------------
// HookOutcome shape (local, mirrors before-tool-call.ts types)
// ---------------------------------------------------------------------------

/**
 * The subset of HookOutcome we can return from the front-stage resolver.
 * Mirrors the two blocked shapes at ~:1637-1644 and ~:1720-1727.
 */
type FrontStageBlockedOutcome =
  | {
      blocked: true;
      kind: "veto";
      deniedReason: "capability-resolver";
      reason: string;
      params: unknown;
    }
  | {
      blocked: true;
      kind: "failure";
      disposition: FrontStageFailureDisposition;
      deniedReason: "capability-resolver";
      reason: string;
      params: unknown;
    };

// ---------------------------------------------------------------------------
// L4.5 — runFrontStageResolver
// ---------------------------------------------------------------------------

/**
 * Classify the tool call → pick the owner capability → check if a resolver
 * is registered → decide → map the verdict to a HookOutcome.
 *
 * Returns:
 *  - `undefined`              — allow or fallthrough (chain continues unchanged)
 *  - `FrontStageBlockedOutcome` — deny (veto or failure; caller must `return` it)
 *
 * Fail-closed invariants enforced here:
 *  1. classifyEffects throw → SUPERSET_EFFECTS (never [])
 *  2. no resolver for capability → return undefined (no-op, byte-unchanged)
 *  3. decideCapabilityApproval deny → blocked outcome with params carried
 *  4. params is ALWAYS the original `params` argument on blocked outcomes
 */
export async function runFrontStageResolver(args: {
  toolName: string;
  params: unknown;
  ctx: FrontStageCtx | undefined | null;
  signal: AbortSignal | undefined;
  toolCallId?: string;
}): Promise<FrontStageBlockedOutcome | undefined> {
  const { toolName, params, ctx, signal, toolCallId } = args;

  // --- 1. Classify effects (fail-closed on throw) ---
  let effects: readonly EffectDescriptor[];
  try {
    effects = await classifyEffects(
      // harness arg: undefined is safe (Tier-A ignores it currently)
      undefined,
      toolName,
      params,
      ctx,
    );
  } catch {
    // Fail-closed: classifier threw → use broadest possible effect set.
    effects = SUPERSET_EFFECTS;
  }

  // --- 2. Pick the single owner capability ---
  const capability = pickOwner(effects);

  // --- 3. No-resolver gate: short-circuit before any decide call ---
  if (!hasApprovalResolverForScope(capability)) {
    return undefined;
  }

  // --- 4. Build the approval request ---
  const req = buildFrontStageApprovalRequest(effects, toolName, ctx, toolCallId);

  // --- 5. Resolve timeout ---
  const timeoutMs =
    typeof ctx?.config?.approvals?.frontStageResolverTimeoutMs === "number" &&
    ctx.config.approvals.frontStageResolverTimeoutMs > 0
      ? ctx.config.approvals.frontStageResolverTimeoutMs
      : DEFAULT_FRONT_STAGE_RESOLVER_TIMEOUT_MS;

  // --- 6. Decide ---
  let verdict: Awaited<ReturnType<typeof decideCapabilityApproval>>;
  try {
    verdict = await decideCapabilityApproval(req, { deadlineMs: timeoutMs, signal });
  } catch (err) {
    // Fail-closed: unexpected throw from decideCapabilityApproval → deny/failed
    return {
      blocked: true,
      kind: "failure",
      disposition: "failed",
      deniedReason: "capability-resolver",
      reason: String(err),
      params,
    };
  }

  // --- 7. Map verdict → HookOutcome ---
  switch (verdict.kind) {
    case "allow":
      // Allow: let the existing chain execute (trusted-policy + plugin-hook still run).
      return undefined;

    case "fallthrough":
      // No resolver owned the capability (defensive: hasApprovalResolverForScope gated above,
      // but decideCapabilityApproval may still return fallthrough on internal TOCTOU).
      return undefined;

    case "deny": {
      const reason = verdict.reason ?? "Capability resolver denied";
      if (verdict.failureDisposition) {
        return {
          blocked: true,
          kind: "failure",
          disposition: verdict.failureDisposition,
          deniedReason: "capability-resolver",
          reason,
          params,
        };
      }
      return {
        blocked: true,
        kind: "veto",
        deniedReason: "capability-resolver",
        reason,
        params,
      };
    }
  }
}
