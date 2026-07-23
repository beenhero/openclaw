/**
 * Classifies ACP tool permission requests into auto-approved and prompt-required risk buckets.
 *
 * EXEC/NET CAPABILITY SOURCE (L3.12):
 *   The exec/net capability decision is now DERIVED from the shared core
 *   classifyEffectsSync (Tier-A + Tier-B) in src/plugins/effect-classifier.ts.
 *   The local EXEC_CAPABLE_TOOL_IDS duplicate has been removed; the single
 *   source of truth is EXEC_CAPABLE_TOOL_NAMES in the core classifier.
 *
 *   ACP-SPECIFIC LOGIC (not subsumable by the core classifier) is PRESERVED:
 *     - CWD-scoped auto-approve for reads/search (isToolPathScopedToCwd)
 *     - SAFE_SEARCH_TOOL_IDS / CONTROL_PLANE_TOOL_IDS checks
 *     - The interactive class, fail-closed 'other'/'unknown'
 *     - resolveToolNameForPermission spoof handling
 *
 *   FAIL-CLOSED GUARANTEE: if classifyEffectsSync throws, the caller treats the
 *   tool as exec_capable (most restrictive), never auto-approves.
 */
import { homedir } from "node:os";
import path from "node:path";
import { asRecord } from "@openclaw/acp-core/record-shared";
import {
  normalizeLowercaseStringOrEmpty,
  normalizeOptionalString,
} from "@openclaw/normalization-core/string-coerce";
import { isKnownCoreToolId } from "../agents/tool-catalog.js";
import { isMutatingToolCall } from "../agents/tool-mutation.js";
import { isPathInside } from "../infra/path-guards.js";
import { classifyEffectsSync } from "../plugins/effect-classifier.js";
import { readTrimmedStringAlias } from "../utils/string-readers.js";

// ACP-local sets: these have no capability analog in the core effect table.
// SAFE_SEARCH_TOOL_IDS / CONTROL_PLANE_TOOL_IDS are ACP routing concerns.
// The exec-capable discriminator (formerly EXEC_CAPABLE_TOOL_IDS) is now
// derived from classifyEffectsSync → EXEC_CAPABLE_TOOL_NAMES in effect-classifier.ts.
const SAFE_SEARCH_TOOL_IDS = new Set(["search", "web_search", "memory_search"]);
const TRUSTED_SAFE_TOOL_ALIASES = new Set(["search"]);
const CONTROL_PLANE_TOOL_IDS = new Set([
  "cron",
  "gateway",
  "sessions_spawn",
  "sessions_send",
  "session_status",
]);

export type AcpApprovalClass =
  | "readonly_scoped"
  | "readonly_search"
  | "mutating"
  | "exec_capable"
  | "control_plane"
  | "interactive"
  | "other"
  | "unknown";

type AcpApprovalClassification = {
  toolName?: string;
  approvalClass: AcpApprovalClass;
  autoApprove: boolean;
};

type AcpApprovalToolCall = {
  title?: string | null;
  _meta?: unknown;
  rawInput?: unknown;
  locations?: unknown;
};

function readFirstStringValue(
  source: Record<string, unknown> | undefined,
  keys: string[],
): string | undefined {
  if (!source) {
    return undefined;
  }
  return readTrimmedStringAlias(source, keys);
}

function normalizeToolName(value: string): string | undefined {
  const normalized = normalizeLowercaseStringOrEmpty(value);
  if (!normalized || normalized.length > 128) {
    return undefined;
  }
  return /^[a-z0-9._-]+$/.test(normalized) ? normalized : undefined;
}

function parseToolNameFromTitle(title: string | undefined | null): string | undefined {
  if (!title) {
    return undefined;
  }
  const head = normalizeOptionalString(title.split(":", 1)[0]);
  return head ? normalizeToolName(head) : undefined;
}

function resolveToolNameForPermission(params: {
  toolCall?: {
    title?: string | null;
    _meta?: unknown;
    rawInput?: unknown;
  };
}): string | undefined {
  const toolCall = params.toolCall;
  const toolMeta = asRecord(toolCall?.["_meta"]);
  const rawInput = asRecord(toolCall?.rawInput);

  const fromMeta = readFirstStringValue(toolMeta, ["toolName", "tool_name", "name"]);
  const fromRawInput = readFirstStringValue(rawInput, ["tool", "toolName", "tool_name", "name"]);
  const fromTitle = parseToolNameFromTitle(toolCall?.title);
  const metaName = fromMeta ? normalizeToolName(fromMeta) : undefined;
  const rawInputName = fromRawInput ? normalizeToolName(fromRawInput) : undefined;
  const titleName = fromTitle;
  if ((fromMeta && !metaName) || (fromRawInput && !rawInputName)) {
    return undefined;
  }
  if (metaName && titleName && metaName !== titleName) {
    return undefined;
  }
  if (rawInputName && metaName && rawInputName !== metaName) {
    return undefined;
  }
  if (rawInputName && titleName && rawInputName !== titleName) {
    return undefined;
  }
  return metaName ?? titleName ?? rawInputName;
}

function extractPathFromToolTitle(
  toolTitle: string | undefined,
  toolName: string | undefined,
): string | undefined {
  if (!toolTitle) {
    return undefined;
  }
  const separator = toolTitle.indexOf(":");
  if (separator < 0) {
    return undefined;
  }
  const tail = toolTitle.slice(separator + 1).trim();
  if (!tail) {
    return undefined;
  }
  const keyedMatch =
    toolName === "read"
      ? tail.match(/(?:^|,\s*)(?:path|file_path|filePath)\s*:\s*([^,]+)/)
      : tail.match(/^(?:path|file_path|filePath)\s*:\s*([^,]+)/);
  if (keyedMatch?.[1]) {
    return keyedMatch[1].trim();
  }
  return toolName === "read" ? tail : undefined;
}

function readLocationPaths(locations: unknown): string[] {
  if (!Array.isArray(locations)) {
    return [];
  }
  const paths: string[] = [];
  for (const location of locations) {
    const pathValue = readFirstStringValue(asRecord(location), ["path", "file_path", "filePath"]);
    if (pathValue) {
      paths.push(pathValue);
    }
  }
  return paths;
}

function resolveToolPathCandidates(params: {
  includeLocations?: boolean;
  toolCall?: AcpApprovalToolCall;
  toolName: string | undefined;
  toolTitle: string | undefined;
}): string[] {
  const rawInput = asRecord(params.toolCall?.rawInput);
  return [
    readFirstStringValue(rawInput, ["path", "file_path", "filePath"]),
    extractPathFromToolTitle(params.toolTitle, params.toolName),
    ...(params.includeLocations ? readLocationPaths(params.toolCall?.locations) : []),
  ].filter((value): value is string => value !== undefined);
}

function resolveAbsoluteScopedPath(value: string, cwd: string): string | undefined {
  let candidate = value.trim();
  if (!candidate) {
    return undefined;
  }
  if (candidate.startsWith("file://")) {
    try {
      const parsed = new URL(candidate);
      candidate = decodeURIComponent(parsed.pathname || "");
    } catch {
      return undefined;
    }
  }
  if (candidate === "~") {
    candidate = homedir();
  } else if (candidate.startsWith("~/")) {
    candidate = path.join(homedir(), candidate.slice(2));
  }
  return path.isAbsolute(candidate) ? path.normalize(candidate) : path.resolve(cwd, candidate);
}

function isToolPathScopedToCwd(rawPath: string, cwd: string): boolean {
  const absolutePath = resolveAbsoluteScopedPath(rawPath, cwd);
  if (!absolutePath) {
    return false;
  }
  return isPathInside(path.resolve(cwd), absolutePath);
}

/** Resolves the ACP approval class for one tool call, failing closed on spoofed tool identity. */
export function classifyAcpToolApproval(params: {
  toolCall?: AcpApprovalToolCall;
  cwd: string;
}): AcpApprovalClassification {
  const toolName = resolveToolNameForPermission(params);
  if (!toolName) {
    return { toolName: undefined, approvalClass: "unknown", autoApprove: false };
  }

  const isTrustedToolId = isKnownCoreToolId(toolName) || TRUSTED_SAFE_TOOL_ALIASES.has(toolName);
  if (toolName === "read" && isTrustedToolId) {
    const rawPaths = resolveToolPathCandidates({
      includeLocations: false,
      toolCall: params.toolCall,
      toolName,
      toolTitle: params.toolCall?.title ?? undefined,
    });
    const autoApprove =
      rawPaths.length > 0 &&
      rawPaths.every((rawPath) => isToolPathScopedToCwd(rawPath, params.cwd));
    return {
      toolName,
      approvalClass: autoApprove ? "readonly_scoped" : "other",
      autoApprove,
    };
  }
  if (SAFE_SEARCH_TOOL_IDS.has(toolName) && isTrustedToolId) {
    const rawPaths = resolveToolPathCandidates({
      includeLocations: true,
      toolCall: params.toolCall,
      toolName,
      toolTitle: params.toolCall?.title ?? undefined,
    });
    if (rawPaths.some((rawPath) => !isToolPathScopedToCwd(rawPath, params.cwd))) {
      return { toolName, approvalClass: "other", autoApprove: false };
    }
    return { toolName, approvalClass: "readonly_search", autoApprove: true };
  }
  // --- Derive exec/net capability from the shared core table (L3.12) ---
  //
  // classifyEffectsSync (Tier-A + Tier-B sync slice) is the single source of
  // truth for exec/net capability identity. It replaces the former local
  // EXEC_CAPABLE_TOOL_IDS set, which duplicated the core table.
  //
  // SUPERSET FLOOR DETECTION: when both Tier-A and Tier-B return [] (tool
  // identity unknown), classifyEffectsSync returns the conservative superset
  // [{kind:'process.exec', unparseable:true}, {kind:'net.egress', hosts:['*']}].
  // We detect the floor by the presence of unparseable:true and skip the exec/
  // net check, falling through to CONTROL_PLANE / mutating / other below.
  // This ensures control_plane tools (cron, gateway, etc.) are NOT incorrectly
  // elevated to exec_capable by the superset floor.
  //
  // FAIL-CLOSED ON THROW: if classifyEffectsSync throws for any reason, treat
  // the tool as exec_capable (most restrictive), never auto-approve.
  let coreEffects: ReturnType<typeof classifyEffectsSync>;
  try {
    coreEffects = classifyEffectsSync(null, toolName, params.toolCall?.rawInput);
  } catch {
    // Fail-closed: on any classifier error, treat as exec_capable (prompt-required)
    return { toolName, approvalClass: "exec_capable", autoApprove: false };
  }
  const isSuperset = coreEffects.some((e) => e["unparseable"] === true);
  if (!isSuperset) {
    // Legitimate capability match from the core table (Tier-A or Tier-B).
    const hasExec = coreEffects.some((e) => e.kind === "process.exec");
    const hasNet = coreEffects.some((e) => e.kind === "net.egress");
    if (hasExec) {
      // Exec-capable: any process.exec in effects → exec_capable (prompt-required)
      return { toolName, approvalClass: "exec_capable", autoApprove: false };
    }
    if (hasNet) {
      // Net-egress (Tier-B declared, e.g. plugin custom tool with capabilities:['net.egress']).
      // net.egress is NEVER auto-approved. Route to exec_capable (prompt-required).
      // This is net-new behavior (L3.12): previously fell to heuristic 'other'.
      // 'other' is also autoApprove:false, but routing to exec_capable makes the
      // net.egress identity explicit in the ACP approval class.
      return { toolName, approvalClass: "exec_capable", autoApprove: false };
    }
  }
  // --- ACP-local: control_plane (cron, gateway, sessions_*, session_status) ---
  if (CONTROL_PLANE_TOOL_IDS.has(toolName)) {
    return { toolName, approvalClass: "control_plane", autoApprove: false };
  }
  if (isMutatingToolCall(toolName, params.toolCall?.rawInput)) {
    return { toolName, approvalClass: "mutating", autoApprove: false };
  }
  return { toolName, approvalClass: "other", autoApprove: false };
}
