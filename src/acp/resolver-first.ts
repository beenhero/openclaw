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
 *
 * ---------------------------------------------------------------------------
 * L5.6 surface-#1 residual — resolver exclusivity is ORDERING-BASED, not
 * create-site-suppressed (documented tap-race).
 * ---------------------------------------------------------------------------
 * L5.A (this module + translator.ts:1031-1064) closes surface #2: on a resolver
 * decision the translator resolves the gateway approval and SKIPS the ACP client
 * tap (this.connection.requestPermission). That is fully closed and tested.
 *
 * Surface #1 is the operator APPROVALS_SCOPE broadcast. The gateway mints the
 * exec approval record and broadcasts `exec.approval.requested` to APPROVALS_SCOPE
 * at the CREATE site (src/gateway/server-methods/exec-approval.ts:399-411 →
 * approval-shared.ts:454-478). That single broadcast is consumed by BOTH:
 *   (a) operator taps (Telegram /approve, iOS) — which CAN authorize via
 *       exec.approval.resolve, so surface #1 IS an authorization surface; and
 *   (b) the ACP translator relay itself, which connects as an APPROVALS_SCOPE
 *       client (src/acp/server.ts:143-165) and is TRIGGERED by that same
 *       `exec.approval.requested` event (translator.ts:342-354 →
 *       handleExecApprovalRequestEvent → startApprovalRelay).
 *
 * THE RESIDUAL: there is a window between the create-broadcast and the
 * translator's resolver decision (which runs later, after a
 * getGatewayApprovalDetails round-trip). If an operator tap calls
 * exec.approval.resolve('allow') inside that window, it wins — the gateway
 * manager.resolve is single-shot / first-resolve-wins (approval-shared.ts:686-708),
 * so a non-resolver surface could authorize an in-scope request before the
 * resolver decides. In PRACTICE the resolver's own resolveGatewayApproval nearly
 * always lands first (it fires without human latency), so the race is narrow —
 * but it is NOT byte-suppressed and is therefore a real exclusivity residual.
 *
 * WHY NOT create-site suppression (Approach A) here: setting suppressDelivery=true
 * at the create site would suppress the ENTIRE `exec.approval.requested`
 * broadcast — which is ALSO the ACP relay's trigger (b). That would starve the
 * resolver of its own event and BREAK L5.A (the resolver would never decide).
 * A correct fix must be SELECTIVE: deliver the event to the ACP relay (so the
 * resolver runs) while excluding operator taps. That requires a NEW discriminator
 * on the ACP relay connection (today it connects with the generic
 * GATEWAY_CLIENT_NAMES.CLI, indistinguishable from an operator tap at the create
 * site) on the HOT shared APPROVALS_SCOPE path — a high-regression-risk change
 * across every approval consumer.
 *
 * NOTE (follow-up seam): the ACP relay also has a SECOND, session-scoped trigger
 * — the `agent` event with stream:"approval" (translator.ts:830-844,850-856;
 * emitted at embedded-agent-subscribe.handlers.tools.ts:1692-1700), which is
 * broadcast on READ_SCOPE via SESSION_SUBSCRIPTION_EVENTS, independent of the
 * APPROVALS_SCOPE `exec.approval.requested` broadcast. If a live drill CONFIRMS
 * that this session-stream trigger reliably reaches the ACP relay in every
 * production ACP host config, then a targeted create-site suppression of ONLY
 * the operator `exec.approval.requested` broadcast (gated on
 * hasApprovalResolverForScope) becomes viable WITHOUT starving the resolver.
 * That dual-trigger invariant is UNVERIFIED here and must not be assumed — a
 * wrong assumption would fail OPEN on the security gate (resolver never runs).
 * Hence L5.6 ships the ordering-based exclusivity + this residual note, and
 * defers full surface-#1 closure to that verified follow-up.
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
