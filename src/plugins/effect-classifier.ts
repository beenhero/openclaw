/**
 * Effect-set canonicalization primitives for the 3-tier effect classifier (Layer 3).
 *
 * This file contains ONLY the pure, sync, no-async helpers needed as the
 * foundational layer (Dispatch A: L3.1–L3.4):
 *
 *   sortEffects(effects)    — canonical order by kind (localeCompare)
 *   dedupeByKind(effects)   — THROWS on duplicate kind (invalid input)
 *   digestForEffects(effects) — behavior-preserving digest (branch A)
 *
 * Dispatch B (L3.5–L3.8) adds the 3-tier classifyEffects orchestrator
 * on top of these primitives. Do NOT add tier logic here.
 *
 * Purity constraints (same as capability-approval.ts):
 *   - NO imports from src/agents/embedded-agent-runner/* or src/gateway/*
 *   - NO side effects, no async, no I/O
 *   - Safe to import from any harness (codex adapter, native L4, tests)
 */

import { computeParamsDigest } from "./capability-approval.js";
import type { EffectDescriptor } from "./host-hooks.js";

// ---------------------------------------------------------------------------
// sortEffects
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
// dedupeByKind
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
// digestForEffects — behavior-preservation branch A
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
