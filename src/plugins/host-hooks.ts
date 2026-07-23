/** Public host-hook type contracts exposed to plugin runtimes. */
import type { OperatorScope } from "../gateway/operator-scopes.js";
import type { AgentEventPayload, AgentEventStream } from "../infra/agent-events.js";
import type {
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookToolContext,
} from "./hook-types.js";
import type { PluginJsonValue } from "./host-hook-json.js";
import type {
  PluginAgentTurnPrepareResult,
  PluginNextTurnInjectionPlacement,
  PluginNextTurnInjectionRecord,
} from "./host-hook-turn-types.js";

export { isPluginJsonValue } from "./host-hook-json.js";
export type { PluginJsonValue } from "./host-hook-json.js";
export type {
  PluginAgentTurnPrepareEvent,
  PluginAgentTurnPrepareResult,
  PluginHeartbeatPromptContributionEvent,
  PluginHeartbeatPromptContributionResult,
  PluginNextTurnInjection,
  PluginNextTurnInjectionEnqueueResult,
  PluginNextTurnInjectionRecord,
} from "./host-hook-turn-types.js";

/** Reason passed to plugin cleanup callbacks when host-owned state changes. */
export type PluginHostCleanupReason = "disable" | "reset" | "delete" | "restart";

type PluginSessionExtensionProjectionContext = {
  sessionKey: string;
  sessionId?: string;
  state: PluginJsonValue | undefined;
};

/** Session extension registration owned by a plugin namespace. */
export type PluginSessionExtensionRegistration = {
  namespace: string;
  description: string;
  project?: (ctx: PluginSessionExtensionProjectionContext) => PluginJsonValue | undefined;
  cleanup?: (ctx: { reason: PluginHostCleanupReason; sessionKey?: string }) => void | Promise<void>;
  /**
   * When set, after every successful `patchSessionExtension` the projected
   * value is mirrored to `SessionEntry[<slotKey>]` so non-plugin readers
   * can consume the typed slot without reaching into
   * `pluginExtensions[pluginId][namespace]`.
   *
   * The slot is a read-only mirror: writes always go through
   * `patchSessionExtension`; the host overwrites the slot value on every
   * subsequent patch.
   */
  sessionEntrySlotKey?: string;
  /**
   * Optional JSON-compatible schema describing the projected slot value.
   * Purely informational at this layer; clients may use it to validate the
   * mirrored slot against a contract.
   */
  sessionEntrySlotSchema?: PluginJsonValue;
};

export type PluginSessionExtensionProjection = {
  pluginId: string;
  namespace: string;
  value: PluginJsonValue;
};

type PluginToolPolicyDecision =
  | PluginHookBeforeToolCallResult
  | {
      allow?: boolean;
      reason?: string;
    };

export type PluginTrustedToolPolicyRegistration = {
  id: string;
  description: string;
  evaluate: (
    event: PluginHookBeforeToolCallEvent,
    ctx: PluginHookToolContext,
  ) => PluginToolPolicyDecision | void | Promise<PluginToolPolicyDecision | void>;
};

/**
 * Capability namespace a plugin approval resolver can claim. An open validated
 * string — only `"process.exec"` is wired today; any other capability is
 * rejected at registration time (fail-closed, design §4.1/§7).
 */
export type ApprovalCapability = string;

/**
 * The set of capabilities wired in Layers 1+3. The registrar hard-throws on any
 * capability NOT in this set, so a plugin cannot silently believe it gates a
 * surface OpenClaw does not yet enforce.
 *
 * Wired capabilities:
 *   "process.exec"  — shell/exec gate (Layer 1). EffectDescriptor shape:
 *                     { kind: "process.exec", command: string, cwd?: string, argv?: string[] }
 *
 *   "net.egress"    — outbound network gate (Layer 3). EffectDescriptor shape:
 *                     { kind: "net.egress", hosts: string[], ports?: number[], url?: string }
 *
 *                   IMPORTANT — hosts: ['*'] means "unknown/any host" and MUST be treated
 *                   as deny-by-default. A resolver MUST NEVER treat the literal string '*'
 *                   as an allowlistable host pattern. It is the conservative superset marker
 *                   emitted when the target host cannot be determined (e.g. unparseable argv,
 *                   indirect redirect). Deny or prompt the user; do not allow.
 *
 *                   Convention: hosts are sorted, lowercased, port-stripped. ports are sorted
 *                   ascending. url is a human-UX hint only — resolvers decide on hosts/ports,
 *                   not the raw url string.
 *
 *   "fs.write"     — filesystem write gate (Layer 6). EffectDescriptor shape:
 *                     { kind: "fs.write", paths: string[] }
 *
 *                   IMPORTANT — paths: ['*'] means "unknown/any path" and MUST be treated
 *                   as deny-by-default. A resolver MUST NEVER treat the literal string '*'
 *                   as an allowlistable glob pattern. It is the conservative superset marker
 *                   emitted when the target path cannot be determined (e.g. unparseable argv,
 *                   write command with no path argument). Deny or prompt the user; do not allow.
 *
 *                   Convention: paths are sorted. Tier-C refines paths from shell argv;
 *                   a native write-tool's params.path / params.file_path also resolves here.
 *                   fs.write is emitted ALONGSIDE process.exec for shell write commands
 *                   (e.g. `touch /x` → [process.exec, fs.write paths:['/x']]).
 *                   fs.write is NOT added to SUPERSET_EFFECTS — an unparseable op is
 *                   process.exec+net.egress (the existing superset floor); we do not add
 *                   fs.write to avoid over-classifying every unknown op as a writer.
 */
export const KNOWN_CAPABILITIES: ReadonlySet<string> = new Set([
  "process.exec",
  "net.egress",
  "fs.write",
]);

/** Static scope declaration for an approval resolver. */
export type ApprovalScope = {
  capabilities: ApprovalCapability[];
};

/**
 * An opaque effect bag keyed by the open capability string. Carries all
 * capability-specific fields; providers read these; the core primitive treats
 * the bag as opaque (other than `kind`). Values are JSON-compatible so the
 * bag can be fingerprinted by `computeParamsDigest`.
 *
 * process.exec effect: `{ kind: "process.exec", command, cwd?, argv? }`
 */
export type EffectDescriptor = { kind: ApprovalCapability; [key: string]: PluginJsonValue };

/**
 * A single approval request handed to a registered resolver. `paramsDigest`
 * is computed gateway-side over `effects` and binds the returned decision to
 * this request (replay/substitution guard).
 */
export type ApprovalRequest = {
  requestId: string;
  capability: ApprovalCapability;
  toolName: string;
  /**
   * The classified effect set for this approval request. Contains one or more
   * EffectDescriptors — typically one (process.exec) for a plain command, two
   * (net.egress + process.exec) for a curl command.
   *
   * paramsDigest is computed via digestForEffects(effects): for a single-effect
   * set, digests the lone object (byte-identical to the legacy single-effect path);
   * for multi-effect sets, digests the sorted array (branch B, fail-closed re-approval).
   */
  effects: readonly EffectDescriptor[];
  agentId?: string;
  sessionKey?: string;
  runId?: string;
  toolCallId?: string;
  paramsDigest: string;
  /** Optional human-readable subject hint for the resolver UX. */
  subject?: string;
  /** Optional origin context (e.g. agent id, run id label). */
  origin?: string;
  /** Optional Unix-ms expiry hint (informational; core ignores it). */
  expiresAt?: number;
};

/**
 * A resolver's decision. `proof` is an optional recorded-proof token; the
 * gateway enforces structural single-use/replay on it (crypto validation is
 * provider-internal, design §4).
 */
export type ApprovalDecision = {
  requestId: string;
  decision: "allow" | "deny";
  reason?: string;
  proof?: string;
};

/**
 * A capability-scoped approval resolver. Called with an abort signal and a
 * deadline; the returned Promise is the async hold (e.g. wallet-sign). It
 * must resolve to an `ApprovalDecision` echoing the request's `requestId`.
 */
export type ApprovalResolver = (
  req: ApprovalRequest,
  opts: { signal: AbortSignal; deadlineMs: number },
) => Promise<ApprovalDecision>;

/**
 * Registration payload for a capability-scoped approval resolver. `exclusive`
 * is `true`: a registered resolver takes exclusive ownership of decisions in
 * its scope (design §4.3). Installed (non-bundled) plugins must declare the
 * resolver id in `contracts.approvalResolvers`.
 */
export type PluginApprovalResolverRegistration = {
  id: string;
  description: string;
  scope: ApprovalScope;
  exclusive: true;
  resolve: ApprovalResolver;
};

export type PluginToolMetadataRegistration = {
  toolName: string;
  displayName?: string;
  description?: string;
  risk?: "low" | "medium" | "high";
  tags?: string[];
  /**
   * Optional capability declarations for this tool (L3.6 — Tier-B classifier).
   *
   * A plugin owning a custom net-touching tool can declare `capabilities:['net.egress']`
   * here so core classifies it WITHOUT Tier-A hardcoding. Declarations are ADDITIVE to
   * Tier-A (a plugin cannot drop a Tier-A effect by declaring fewer capabilities).
   *
   * Validation at registration (registry-registrars-host.ts) rejects any capability
   * not in KNOWN_CAPABILITIES — fail-closed, same guard as the resolver registrar.
   *
   * Wired capabilities: "process.exec", "net.egress" (see KNOWN_CAPABILITIES).
   */
  capabilities?: ApprovalCapability[];
};

type PluginControlUiTabGroup = "control" | "agent";

export type PluginControlUiDescriptor = {
  id: string;
  /** "tab" adds a sidebar tab; "widget" advertises a trusted dashboard renderer. */
  surface: "session" | "tool" | "run" | "settings" | "tab" | "widget";
  label: string;
  description?: string;
  placement?: string;
  schema?: PluginJsonValue;
  requiredScopes?: OperatorScope[];
  /** Icon name hint for tab descriptors; unknown names fall back to a generic icon. */
  icon?: string;
  /**
   * Gateway HTTP path (e.g. /plugins/<id>/panel) rendered in a sandboxed frame
   * when the Control UI has no bundled view for this tab.
   */
  path?: string;
  /** Sidebar group for tab descriptors; defaults to "control". */
  group?: PluginControlUiTabGroup;
  /** Sort order among plugin tabs; lower renders first. */
  order?: number;
};

export type PluginSessionActionContext = {
  pluginId: string;
  actionId: string;
  sessionKey?: string;
  payload?: PluginJsonValue;
  client?: {
    connId?: string;
    scopes: string[];
  };
};

export type PluginSessionActionResult =
  | {
      ok?: true;
      result?: PluginJsonValue;
      reply?: PluginJsonValue;
      continueAgent?: boolean;
    }
  | {
      ok: false;
      error: string;
      code?: string;
      details?: PluginJsonValue;
    };

export type PluginSessionActionRegistration = {
  id: string;
  description?: string;
  schema?: PluginJsonValue;
  requiredScopes?: OperatorScope[];
  handler: (
    ctx: PluginSessionActionContext,
  ) => PluginSessionActionResult | void | Promise<PluginSessionActionResult | void>;
};

export type PluginRuntimeLifecycleRegistration = {
  id: string;
  description?: string;
  cleanup?: (ctx: {
    reason: PluginHostCleanupReason;
    sessionKey?: string;
    runId?: string;
  }) => void | Promise<void>;
};

export type PluginAgentEventSubscriptionRegistration = {
  id: string;
  description?: string;
  streams?: AgentEventStream[];
  handle: (
    event: AgentEventPayload,
    ctx: {
      // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- Run-context JSON reads are caller-typed by namespace.
      getRunContext: <T extends PluginJsonValue = PluginJsonValue>(
        namespace: string,
      ) => T | undefined;
      setRunContext: (namespace: string, value: PluginJsonValue) => void;
      clearRunContext: (namespace?: string) => void;
    },
  ) => void | Promise<void>;
};

export type PluginAgentEventEmitParams = {
  runId: string;
  stream: AgentEventStream;
  data: PluginJsonValue;
  sessionKey?: string;
};

export type PluginAgentEventEmitResult =
  | { emitted: true; stream: AgentEventStream }
  | { emitted: false; reason: string };

export type PluginRunContextPatch = {
  runId: string;
  namespace: string;
  value?: PluginJsonValue;
  unset?: boolean;
};

export type PluginRunContextGetParams = {
  runId: string;
  namespace: string;
};

export type PluginSessionSchedulerJobRegistration = {
  id: string;
  sessionKey: string;
  kind: string;
  description?: string;
  cleanup?: (ctx: {
    reason: PluginHostCleanupReason;
    sessionKey: string;
    jobId: string;
  }) => void | Promise<void>;
};

export type PluginSessionSchedulerJobHandle = {
  id: string;
  pluginId: string;
  sessionKey: string;
  kind: string;
};

type PluginSessionAttachmentFile = {
  path: string;
};

export type PluginAttachmentChannelHints = {
  parseMode?: "HTML";
  silent?: boolean;
  /** Require host detection to match this MIME before forcing document delivery. */
  forceDocumentMime?: string;
  threadId?: string | number;
  /** @deprecated Put portable attachment hints directly on `channelHints`. */
  telegram?: {
    parseMode?: "HTML";
    disableNotification?: boolean;
    /**
     * Require host-side detection to match this MIME before forcing document delivery.
     * Mismatched files are rejected before the outbound adapter is called.
     */
    forceDocumentMime?: string;
  };
  /** @deprecated Use `channelHints.threadId`. */
  slack?: {
    threadTs?: string;
  };
};

export type PluginSessionAttachmentCaptionFormat = "plain" | "html" | "markdown";

export type PluginSessionAttachmentParams = {
  sessionKey: string;
  files: PluginSessionAttachmentFile[];
  text?: string;
  threadId?: string | number;
  forceDocument?: boolean;
  maxBytes?: number;
  captionFormat?: PluginSessionAttachmentCaptionFormat;
  channelHints?: PluginAttachmentChannelHints;
};

export type PluginSessionAttachmentResult =
  | {
      ok: true;
      channel: string;
      deliveredTo: string;
      count: number;
    }
  | { ok: false; error: string };

type PluginSessionTurnScheduleCommonParams = {
  sessionKey: string;
  message: string;
  agentId?: string;
  deliveryMode?: "none" | "announce";
  name?: string;
  /** Optional cleanup tag. Reserved cron-name delimiters like `:` are rejected. */
  tag?: string;
};

export type PluginSessionTurnScheduleParams =
  | ({
      at: string | number | Date;
      deleteAfterRun?: boolean;
    } & PluginSessionTurnScheduleCommonParams)
  | ({
      delayMs: number;
      deleteAfterRun?: boolean;
    } & PluginSessionTurnScheduleCommonParams)
  | ({
      cron: string;
      tz?: string;
      deleteAfterRun?: false;
    } & PluginSessionTurnScheduleCommonParams);

export type PluginSessionTurnUnscheduleByTagParams = {
  sessionKey: string;
  tag: string;
};

export type PluginSessionTurnUnscheduleByTagResult = {
  removed: number;
  failed: number;
};

export function normalizePluginHostHookId(value: string | undefined): string {
  return (value ?? "").trim();
}

function normalizeQueuedInjectionText(
  entry: PluginNextTurnInjectionRecord,
  placement: PluginNextTurnInjectionPlacement,
): string | undefined {
  const candidate = entry as {
    placement?: unknown;
    text?: unknown;
  };
  if (candidate.placement !== placement || typeof candidate.text !== "string") {
    return undefined;
  }
  const text = candidate.text.trim();
  return text || undefined;
}

export function buildPluginAgentTurnPrepareContext(params: {
  queuedInjections: PluginNextTurnInjectionRecord[];
}): PluginAgentTurnPrepareResult {
  const prepend = params.queuedInjections
    .map((entry) => normalizeQueuedInjectionText(entry, "prepend_context"))
    .filter(Boolean);
  const append = params.queuedInjections
    .map((entry) => normalizeQueuedInjectionText(entry, "append_context"))
    .filter(Boolean);
  return {
    ...(prepend.length > 0 ? { prependContext: prepend.join("\n\n") } : {}),
    ...(append.length > 0 ? { appendContext: append.join("\n\n") } : {}),
  };
}
