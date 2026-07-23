/**
 * Effect-set canonicalization primitives + 3-tier effect classifier (Layer 3).
 *
 * DISPATCH A (L3.3–L3.4) — pure sync helpers (shipped already):
 *   sortEffects(effects)      — canonical order by kind (localeCompare)
 *   dedupeByKind(effects)     — THROWS on duplicate kind (invalid input)
 *   digestForEffects(effects) — behavior-preserving digest (branch A)
 *
 * DISPATCH B (L3.5–L3.8) — 3-tier classifier added here:
 *   EXEC_CAPABLE_TOOL_NAMES / NET_EGRESS_TOOL_NAMES — single source of truth
 *   classifyTierA(harness, toolName, params)  — hardcoded exec/net identity table
 *   classifyTierB(toolName)                   — declarative tool-metadata capabilities
 *   refineTierC(effects, toolName, params)    — argv/param refiner (curl → net.egress)
 *   classifyEffects(harness, toolName, params, ctx) — async orchestrator + floor
 *   classifyEffectsSync(harness, toolName, params)  — sync Tier-A+B slice (L3.12 prep)
 *   SUPERSET_EFFECTS — conservative [{process.exec, unparseable}, {net.egress, hosts:['*']}]
 *
 * SOUNDNESS INVARIANT (non-negotiable):
 *   classifyEffects(...) MUST return a NON-EMPTY EffectDescriptor[].
 *   Empty = silent bypass = the #97152 failure mode. The floor catches every empty path.
 *
 * TIER MONOTONICITY:
 *   Each tier is WIDEN-only. Tier-B adds to Tier-A (union), never removes.
 *   Tier-C adds precision, never removes effects.
 *   assertSuperset(deduped) catches any remaining empty.
 *
 * PURITY CONSTRAINTS (same as capability-approval.ts):
 *   - NO imports from src/agents/embedded-agent-runner/* or src/gateway/*
 *   - Tier-A/B/C are pure sync; classifyEffects is async (barrel contract)
 *   - Safe to import from any harness (codex adapter, native L4, tests)
 */

import { computeParamsDigest } from "./capability-approval.js";
import { extractWebFetchEgress, refineCurlNetEgress } from "./effect-refiners/net-egress.js";
import { KNOWN_CAPABILITIES } from "./host-hooks.js";
import type { EffectDescriptor } from "./host-hooks.js";
import { getActivePluginRegistry } from "./runtime.js";

// ---------------------------------------------------------------------------
// sortEffects (L3.3)
// ---------------------------------------------------------------------------

/**
 * Return a new array of EffectDescriptors sorted by `kind` (localeCompare).
 *
 * Sorting is required before digesting a multi-effect set so that the digest
 * is order-independent regardless of the union order produced by Tier-A/B/C.
 * `stableStringify` treats arrays positionally and does NOT sort elements, so
 * the caller MUST canonicalize order here before hashing.
 */
export function sortEffects(effects: readonly EffectDescriptor[]): EffectDescriptor[] {
  return [...effects].sort((a, b) => a.kind.localeCompare(b.kind));
}

// ---------------------------------------------------------------------------
// dedupeByKind (L3.3)
// ---------------------------------------------------------------------------

/**
 * Validate that a set of EffectDescriptors has at most one entry per `kind`.
 *
 * THROWS if a duplicate kind is present — emitting two effects with the same
 * kind is a CLASSIFIER BUG (invalid input). A canonical effect set has exactly
 * one descriptor per capability. Fail loudly so the bug surfaces in tests/CI
 * rather than silently collapsing to last-wins (which would be a security
 * regression: the wrong descriptor could be digested and used to key the
 * proof-ledger single-use entry).
 *
 * Returns the original array unchanged when valid (no duplicate kinds).
 */
export function dedupeByKind(effects: readonly EffectDescriptor[]): EffectDescriptor[] {
  const seen = new Set<string>();
  for (const effect of effects) {
    if (seen.has(effect.kind)) {
      throw new Error(
        `effect-classifier: duplicate effect kind "${effect.kind}" — a canonical effect set must have at most one descriptor per kind; this is a classifier bug`,
      );
    }
    seen.add(effect.kind);
  }
  return [...effects];
}

// ---------------------------------------------------------------------------
// digestForEffects — behavior-preservation branch A (L3.4)
// ---------------------------------------------------------------------------

/**
 * Compute the paramsDigest for an effect set, preserving byte-identical output
 * for the single-effect case (branch A).
 *
 * BRANCH A (single-effect): digest the lone OBJECT directly.
 *   digestForEffects([effect]) === computeParamsDigest(effect)
 *
 * This is byte-identical to today's `computeParamsDigest(effect)` used at
 * approval-bridge.ts line 581. ZERO behavior change for all current traffic,
 * which is 100% single-effect (process.exec only). Proof-ledger single-use
 * keys {requestId, paramsDigest} stay stable across the L3 deploy.
 *
 * BRANCH B (multi-effect): digest the SORTED ARRAY.
 *   digestForEffects([e1, e2]) === computeParamsDigest(sortEffects([e1, e2]))
 *
 * Adding a SECOND effect to a previously-single-effect tool intentionally flips
 * it onto the array-digest path → re-approval required. This looks like a bug
 * but IS DELIBERATE: the capability set changed, so the old single-use key must
 * not cover the new wider surface. Fail-closed re-approval is the correct
 * behavior. Document this at every call site that adds a second effect.
 *
 * GOLDEN REGRESSION NOTE: the single-effect golden hex for
 * { kind: 'process.exec', command: '/bin/ls', cwd: '/tmp' } is:
 *   sha256:a67944b5693d9183e0504f89d4ad43f0b9128adee162a1d63ca00c57c98a7fed
 * This is frozen in effect-classifier.test.ts. A future refactor that silently
 * switches to the array-digest path WILL break that test — that is the intent.
 */
export function digestForEffects(effects: readonly EffectDescriptor[]): string {
  if (effects.length === 1) {
    // Branch A: single-effect — digest the lone object (byte-identical to today's
    // computeParamsDigest(effect) at the bridge). Zero behavior change for all
    // current process.exec traffic.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return computeParamsDigest(effects[0]!);
  }
  // Branch B: multi-effect — digest the sorted array. Order-independent because
  // sortEffects canonicalizes by kind before hashing.
  return computeParamsDigest(sortEffects(effects));
}

// ---------------------------------------------------------------------------
// TOOLNAME_TO_BASE_EFFECTS — single source of truth (L3.5)
// ---------------------------------------------------------------------------
//
// Lifted from ACP's EXEC_CAPABLE_TOOL_IDS (approval-classifier.ts:16-24) and
// web_fetch/curl-shaped tool names. Both the codex path and the ACP reconciliation
// path (L3.12) read this table instead of their own hardcoded sets.
//
// Convention: lower-cased normalized tool names only.

/** Tool names that map to a base process.exec effect. Lifted from ACP approval-classifier.ts. */
export const EXEC_CAPABLE_TOOL_NAMES: ReadonlySet<string> = new Set([
  // From ACP EXEC_CAPABLE_TOOL_IDS (approval-classifier.ts:16-24)
  "exec",
  "spawn",
  "shell",
  "bash",
  "process",
  "code_execution",
  "nodes",
  // Common exec aliases not in the ACP set but clearly exec-capable
  "run",
  "execute",
  "cmd",
  "command",
]);

/** Tool names that map to a base net.egress effect (no process.exec). */
export const NET_EGRESS_TOOL_NAMES: ReadonlySet<string> = new Set([
  "web_fetch",
  "http_fetch",
  "fetch",
  "curl",
  "wget",
  "http",
  "https",
  "browser_navigate",
  "browser_fetch",
]);

// ---------------------------------------------------------------------------
// Soundness constants (L3.8)
// ---------------------------------------------------------------------------

/**
 * The conservative superset returned when classifyEffects cannot classify
 * the operation at all (no Tier-A/B/C match). Contains BOTH process.exec and
 * net.egress — the broadest possible effect set.
 *
 * This ensures the approval pipeline is fail-CLOSED-but-live: the operation
 * is PROMPTED under the broadest owner, not silently allowed.
 *
 * IMPORTANT — hosts: ['*'] means "unknown/any host" and MUST be treated as
 * deny-by-default. A resolver MUST NEVER treat the literal string '*' as an
 * allowlistable host pattern. Deny or prompt the user; do not allow.
 */
export const SUPERSET_EFFECTS: readonly EffectDescriptor[] = Object.freeze([
  Object.freeze({ kind: "process.exec", command: "<unparsed>", unparseable: true }),
  Object.freeze({ kind: "net.egress", hosts: ["*"] }),
] as EffectDescriptor[]);

// ---------------------------------------------------------------------------
// Tier-A — harness-native discriminator (L3.5)
// ---------------------------------------------------------------------------

/**
 * Normalize a tool name for classification: lowercase, trim, reject if invalid.
 * Mirrors resolveToolNameForPermission's fail-closed-on-spoof logic from
 * approval-classifier.ts:99-111.
 */
function normalizeToolNameForClassification(toolName: unknown): string | undefined {
  if (typeof toolName !== "string") return undefined;
  const normalized = toolName.toLowerCase().trim();
  // Reject empty, too long, or containing non-tool characters
  if (!normalized || normalized.length > 128) return undefined;
  if (!/^[a-z0-9._\-/]+$/.test(normalized)) return undefined;
  return normalized;
}

/**
 * Tier-A: harness-native discriminator.
 *
 * Maps tool names to their base EffectDescriptors using the authoritative
 * EXEC_CAPABLE_TOOL_NAMES / NET_EGRESS_TOOL_NAMES tables (single source of
 * truth, lifted from ACP's EXEC_CAPABLE_TOOL_IDS).
 *
 * Returns:
 *   - [{kind:'process.exec', command?, cwd?, argv?}] for exec-capable tools
 *   - [{kind:'net.egress', hosts:['*']}] for net-egress tools (Tier-C refines hosts)
 *   - [] for unrecognized tools (the L3.8 floor handles empties)
 *
 * Fail-closed on ambiguous/spoofed tool identity: if toolName cannot be
 * normalized to a valid identifier, returns [] (pre-floor).
 *
 * @param _harness - reserved for harness-specific dispatch (future use)
 * @param toolName - the raw tool name from the approval request
 * @param params   - the raw params (command/cwd/argv extraction for exec tools)
 */
export function classifyTierA(
  _harness: unknown,
  toolName: unknown,
  params: unknown,
): EffectDescriptor[] {
  const name = normalizeToolNameForClassification(toolName);
  if (!name) {
    // Spoofed or invalid tool name — fail-closed, return [] (floor catches)
    return [];
  }

  if (EXEC_CAPABLE_TOOL_NAMES.has(name)) {
    // Exec-capable tool: extract command/cwd/argv from params if available
    const p = params && typeof params === "object" ? (params as Record<string, unknown>) : {};
    const command =
      typeof p["command"] === "string"
        ? p["command"]
        : typeof p["cmd"] === "string"
          ? p["cmd"]
          : undefined;
    const cwd = typeof p["cwd"] === "string" ? p["cwd"] : undefined;
    const argv = Array.isArray(p["argv"])
      ? (p["argv"] as unknown[]).filter((x): x is string => typeof x === "string")
      : undefined;

    const effect: EffectDescriptor = { kind: "process.exec" };
    if (command !== undefined) effect["command"] = command;
    if (cwd !== undefined) effect["cwd"] = cwd;
    if (argv !== undefined) effect["argv"] = argv;
    return [effect];
  }

  if (NET_EGRESS_TOOL_NAMES.has(name)) {
    // Net-egress tool: return base effect with hosts:['*'] (Tier-C refines)
    return [{ kind: "net.egress", hosts: ["*"] }];
  }

  // Unrecognized tool — return [] (floor in classifyEffects handles this)
  return [];
}

// ---------------------------------------------------------------------------
// Tier-B — declarative tool-metadata capabilities (L3.6)
// ---------------------------------------------------------------------------

/**
 * Tier-B: read plugin-declared capabilities from the tool metadata registry.
 *
 * A plugin that registers a custom net-touching tool via registerToolMetadata
 * with capabilities:['net.egress'] causes core to classify it without Tier-A
 * hardcoding. Tier-B is additive-only (union with Tier-A), never subtractive.
 *
 * Reads from the active plugin registry (getActivePluginRegistry). Returns []
 * if no metadata is found or the registry is unavailable.
 *
 * Validation at registration rejects any capability not in KNOWN_CAPABILITIES,
 * so we trust what's in the registry.
 */
export function classifyTierB(toolName: unknown): EffectDescriptor[] {
  const name = normalizeToolNameForClassification(toolName);
  if (!name) return [];

  let registry: ReturnType<typeof getActivePluginRegistry>;
  try {
    registry = getActivePluginRegistry();
  } catch {
    return [];
  }
  if (!registry) return [];

  let toolMetadata: { metadata: { toolName: string; capabilities?: string[] } }[];
  try {
    toolMetadata = registry.toolMetadata as typeof toolMetadata;
  } catch {
    return [];
  }

  const entry = toolMetadata.find((e) => {
    try {
      return e.metadata.toolName === name;
    } catch {
      return false;
    }
  });

  if (!entry) return [];

  const capabilities = entry.metadata.capabilities;
  if (!Array.isArray(capabilities) || capabilities.length === 0) return [];

  const effects: EffectDescriptor[] = [];
  for (const cap of capabilities) {
    if (typeof cap !== "string") continue;
    if (!KNOWN_CAPABILITIES.has(cap)) continue; // double-check (registration already validated)
    if (cap === "process.exec") {
      effects.push({ kind: "process.exec" });
    } else if (cap === "net.egress") {
      effects.push({ kind: "net.egress", hosts: ["*"] });
    }
  }
  return effects;
}

// ---------------------------------------------------------------------------
// Tier-C — host argv/param refiner (L3.7)
// ---------------------------------------------------------------------------

/**
 * Tier-C: refine/widen the effect set based on raw params.
 *
 * For a process.exec effect whose command parses as curl/wget/http:
 *   - PUSH a net.egress effect with extracted host+port info.
 *
 * For a net.egress base effect (web_fetch shape):
 *   - REFINE hosts/ports/url from params.url.
 *
 * REFINE/WIDEN-ONLY: on parse failure return effects unchanged, NEVER shrink.
 * Guarantees: refineTierC(effects, ...).length >= effects.length
 */
export function refineTierC(
  effects: readonly EffectDescriptor[],
  _toolName: unknown,
  params: unknown,
): EffectDescriptor[] {
  const refined = [...effects];
  const p = params && typeof params === "object" ? (params as Record<string, unknown>) : {};

  // Check if we already have process.exec or net.egress effects
  const execIndex = refined.findIndex((e) => e.kind === "process.exec");
  const egressIndex = refined.findIndex((e) => e.kind === "net.egress");

  if (execIndex !== -1) {
    // We have a process.exec effect. Try to parse the command as curl/wget/http.
    const execEffect = refined[execIndex];
    if (!execEffect) return refined;

    // Extract command from the effect descriptor or from params
    const commandFromEffect =
      typeof execEffect["command"] === "string" ? execEffect["command"] : undefined;
    const argvFromEffect = Array.isArray(execEffect["argv"])
      ? (execEffect["argv"] as string[])
      : undefined;
    const commandFromParams = typeof p["command"] === "string" ? p["command"] : undefined;

    const command = commandFromEffect ?? argvFromEffect ?? commandFromParams;

    if (command !== undefined) {
      const curlResult = refineCurlNetEgress(command);
      if (curlResult !== undefined && egressIndex === -1) {
        // It's a fetch command and no existing net.egress — push a new one
        const egressEffect: EffectDescriptor = {
          kind: "net.egress",
          hosts: curlResult.hosts,
        };
        if (curlResult.ports.length > 0) egressEffect["ports"] = curlResult.ports;
        if (curlResult.url !== undefined) egressEffect["url"] = curlResult.url;
        refined.push(egressEffect);
      }
    }
  } else if (egressIndex !== -1) {
    // We have a net.egress effect (e.g. web_fetch). Refine from params.url.
    const url = typeof p["url"] === "string" ? p["url"] : undefined;
    if (url !== undefined) {
      const target = extractWebFetchEgress(url);
      // Replace the net.egress effect with a refined one (hosts/ports/url from URL)
      const refinedEgress: EffectDescriptor = {
        kind: "net.egress",
        hosts: target.hosts,
      };
      if (target.ports && target.ports.length > 0) refinedEgress["ports"] = target.ports;
      if (target.url !== undefined) refinedEgress["url"] = target.url;
      refined[egressIndex] = refinedEgress;
    }
  }

  return refined;
}

// ---------------------------------------------------------------------------
// assertSuperset — soundness floor (L3.8)
// ---------------------------------------------------------------------------

/**
 * Soundness floor: if the effect set is empty, return the conservative SUPERSET.
 *
 * RETURN (not throw): returning the superset keeps the pipeline fail-CLOSED-but-LIVE.
 * The caller still builds an ApprovalRequest, so an unparseable op is PROMPTED
 * under the broadest owner, not silently allowed AND not crash-blocked.
 *
 * The SUPERSET contains BOTH process.exec AND net.egress — the widest possible
 * effect set — ensuring maximum gate coverage for unknown operations.
 */
function assertSuperset(effects: readonly EffectDescriptor[]): readonly EffectDescriptor[] {
  if (effects.length === 0) {
    return SUPERSET_EFFECTS;
  }
  return effects;
}

// ---------------------------------------------------------------------------
// classifyEffects — main orchestrator (L3.8)
// ---------------------------------------------------------------------------

/**
 * Classify the effects of a tool call using the 3-tier classifier.
 *
 * SIGNATURE (core, harness-neutral):
 *   classifyEffects(harness, toolName, params, ctx) → Promise<readonly EffectDescriptor[]>
 *
 * COMPOSITION:
 *   Tier-A union Tier-B → Tier-C refinement → assertSuperset (NEVER returns [])
 *
 * SOUNDNESS INVARIANT: the result ALWAYS has length >= 1.
 *   - Tier-A/B/C may each return [] individually (pre-floor)
 *   - Their union is refined by Tier-C
 *   - assertSuperset catches any remaining empty → returns SUPERSET_EFFECTS
 *
 * @param harness  - the active AgentHarness (passed to Tier-A for future dispatch)
 * @param toolName - the tool name from the approval request
 * @param params   - the raw params (command/cwd/argv for exec; url for web_fetch)
 * @param _ctx     - HookContext (reserved for future tiers)
 */
export async function classifyEffects(
  harness: unknown,
  toolName: unknown,
  params: unknown,
  _ctx?: unknown,
): Promise<readonly EffectDescriptor[]> {
  // --- Tier-A: harness-native discriminator ---
  const tierA = classifyTierA(harness, toolName, params);

  // --- Tier-B: declarative tool-metadata capabilities ---
  const tierB = classifyTierB(toolName);

  // --- Merge Tier-A + Tier-B (union, additive-only) ---
  // Tier-B adds effects whose kind is NOT already present in Tier-A.
  // Tier-A is authoritative; Tier-B supplements custom plugin tools.
  const tierAKinds = new Set(tierA.map((e) => e.kind));
  const merged: EffectDescriptor[] = [...tierA];
  for (const effect of tierB) {
    if (!tierAKinds.has(effect.kind)) {
      merged.push(effect);
    }
  }

  // --- Tier-C: refine/widen ---
  const refined = refineTierC(merged, toolName, params);

  // --- Deduplicate (last-wins, resilient) ---
  // Tier-C should not produce duplicates, but we dedup here for safety.
  // Callers that need strict dedup should use dedupeByKind (throws on duplicate).
  const seen = new Map<string, EffectDescriptor>();
  for (const effect of refined) {
    seen.set(effect.kind, effect);
  }
  const deduped = [...seen.values()];

  // --- Floor: NEVER return [] ---
  return assertSuperset(deduped);
}

// ---------------------------------------------------------------------------
// classifyEffectsSync — sync slice for ACP reconciliation (L3.12 prep)
// ---------------------------------------------------------------------------

/**
 * Synchronous Tier-A+Tier-B classifier slice (no Tier-C, no async, no ledger).
 *
 * Used by the ACP reconciliation path (L3.12) where async is not available.
 * Returns the same effects as classifyEffects for inputs where Tier-C adds
 * nothing (non-curl exec tools, web_fetch without params.url refinement).
 *
 * The floor (assertSuperset) still applies — never returns [].
 *
 * Behavior invariant: classifyEffectsSync and classifyEffects return the same
 * effects for the same inputs on NON-curl exec commands and all non-exec tools.
 * For curl commands, classifyEffects returns MORE (adds net.egress via Tier-C).
 */
export function classifyEffectsSync(
  harness: unknown,
  toolName: unknown,
  params?: unknown,
): readonly EffectDescriptor[] {
  const tierA = classifyTierA(harness, toolName, params ?? {});
  const tierB = classifyTierB(toolName);

  const tierAKinds = new Set(tierA.map((e) => e.kind));
  const merged: EffectDescriptor[] = [...tierA];
  for (const effect of tierB) {
    if (!tierAKinds.has(effect.kind)) {
      merged.push(effect);
    }
  }

  const seen = new Map<string, EffectDescriptor>();
  for (const effect of merged) {
    seen.set(effect.kind, effect);
  }
  const deduped = [...seen.values()];

  return assertSuperset(deduped);
}
