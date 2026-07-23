/**
 * Layer 5, Dispatch A — ACP server-mode resolver-first helper.
 *
 * Provides the classify→pickOwner→build-ApprovalRequest pipeline for the ACP
 * translator's runApprovalRelay. This is the isolated helper (L5.1) that is
 * wired into translator.ts between the isApprovalRelayActive guard and
 * buildAcpPermissionRequest (L5.2).
 *
 * Fail-closed invariants (mirrors approval-bridge.ts pattern):
 *  - classifyEffects throw → SUPERSET_EFFECTS (never [])
 *  - no resolver for capability → caller falls through to existing ACP relay
 *  - decideCapabilityApproval deny (graceful or failureDisposition) → 'deny'
 *  - allow → 'allow-once' (conservative single-use, mirrors codex adapter)
 *  - decideCapabilityApproval throw → log + fallthrough to human (NOT deny)
 */
import { randomUUID } from "node:crypto";
import { hasApprovalResolverForScope } from "../plugins/approval-resolver.js";
import { decideCapabilityApproval } from "../plugins/capability-approval.js";
import {
  classifyEffects,
  digestForEffects,
  SUPERSET_EFFECTS,
} from "../plugins/effect-classifier.js";
import type { ApprovalRequest } from "../plugins/host-hooks.js";
import type { GatewayExecApprovalDetails, GatewayExecApprovalEvent } from "./permission-relay.js";

/** Deadline for the resolver decision in the ACP gateway context (5 s). */
export const ACP_RESOLVER_DECISION_DEADLINE_MS = 5_000;

/**
 * Hydrate the command text from the approval details, falling back to the
 * raw approval event's command field.
 *
 * Mirrors the priority used by buildAcpPermissionRequest in permission-relay.ts:
 * details.commandText → details.commandPreview → event.command.
 */
function resolveCommandText(
  details: GatewayExecApprovalDetails | null | undefined,
  approvalEvent: GatewayExecApprovalEvent,
): string | undefined {
  const commandText =
    typeof details?.commandText === "string" && details.commandText.trim().length > 0
      ? details.commandText
      : undefined;
  const commandPreview =
    typeof details?.commandPreview === "string" && details.commandPreview.trim().length > 0
      ? details.commandPreview
      : undefined;
  return commandText ?? commandPreview ?? approvalEvent.command;
}

/**
 * pickOwner: process.exec wins when present (strictly broader capability —
 * you cannot egress without executing the process). Otherwise the first
 * effect's kind is used.
 *
 * Mirrors the rule in approval-bridge.ts ~:590 and front-stage-resolver.ts:80.
 *
 * Exported so client-helpers.ts can reuse the identical logic on the client
 * path (L5.4) without duplicating the rule.
 */
export function pickOwner(effects: readonly { kind: string }[]): string {
  if (effects.some((e) => e.kind === "process.exec")) {
    return "process.exec";
  }
  return effects[0]?.kind ?? "process.exec";
}

export type AcpServerApprovalRequest = {
  effects: Awaited<ReturnType<typeof classifyEffects>>;
  capability: string;
  req: ApprovalRequest;
};

/**
 * Classify the ACP exec approval event + hydrated details into an ApprovalRequest.
 *
 * Returns `undefined` when:
 *  - No command text is available (safe: the existing relay will handle it).
 *  - `hasApprovalResolverForScope` is false for the resolved capability (fast
 *    short-circuit so we never build a request the resolver won't consume).
 *
 * FAIL-CLOSED: classifyEffects throw → SUPERSET_EFFECTS (not []).
 *
 * @param details      - Hydrated Gateway exec approval details (commandText/Preview).
 * @param approvalEvent - Raw approval event (fallback command + toolCallId).
 * @param sessionKey   - Session key for the request (optional).
 * @param runId        - Run id for the request (optional).
 */
export async function buildAcpServerApprovalRequest(
  details: GatewayExecApprovalDetails | null | undefined,
  approvalEvent: GatewayExecApprovalEvent,
  sessionKey?: string,
  runId?: string,
): Promise<AcpServerApprovalRequest | undefined> {
  const commandText = resolveCommandText(details, approvalEvent);
  const host =
    typeof details?.host === "string" && details.host.trim().length > 0
      ? details.host
      : approvalEvent.host;

  const classifyParams: Record<string, string> = {};
  if (commandText) classifyParams.command = commandText;
  if (host) classifyParams.host = host;

  // FAIL-CLOSED: classifier throw → SUPERSET (broadest gate, never empty).
  const effects = await classifyEffects("acp", "exec", classifyParams, undefined).catch(
    () => SUPERSET_EFFECTS,
  );

  if (!effects.length) {
    // Soundness invariant: classifyEffects guarantees non-empty via its floor +
    // SUPERSET_EFFECTS catch above. This branch is a belt-and-suspenders guard.
    throw new Error(
      "buildAcpServerApprovalRequest: classifyEffects returned empty effect set — soundness invariant violated",
    );
  }

  const capability = pickOwner(effects);

  // Short-circuit: if no resolver owns this capability, skip building the full
  // request (the caller should fall through to the existing ACP relay).
  if (!hasApprovalResolverForScope(capability)) {
    return undefined;
  }

  const requestId = randomUUID();
  const req: ApprovalRequest = {
    requestId,
    capability,
    toolName: "exec",
    effects,
    paramsDigest: digestForEffects(effects),
    ...(sessionKey ? { sessionKey } : {}),
    ...(runId ? { runId } : {}),
    ...(approvalEvent.toolCallId
      ? { toolCallId: approvalEvent.toolCallId }
      : { toolCallId: `exec:${approvalEvent.approvalId}` }),
  };

  return { effects, capability, req };
}

/**
 * Maps a CapabilityApprovalVerdict to a Gateway exec approval decision.
 *
 * - allow  → 'allow-once' (conservative single-use; mirrors codex adapter)
 * - deny   → 'deny' (both clean-policy and failureDisposition-carrying denies)
 * - fallthrough → undefined (caller should proceed to existing ACP relay)
 *
 * Re-exported so translator.ts can use this without duplicating the mapping.
 */
export function mapVerdictToGatewayDecision(
  verdict: Awaited<ReturnType<typeof decideCapabilityApproval>>,
): "allow-once" | "deny" | undefined {
  if (verdict.kind === "allow") {
    return "allow-once";
  }
  if (verdict.kind === "deny") {
    return "deny";
  }
  // fallthrough — no resolver owned this request; defer to existing relay.
  return undefined;
}
