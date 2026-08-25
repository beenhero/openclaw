/**
 * Shared, stable JSON fingerprinting for Codex app-server digests.
 *
 * `fingerprintJson`/`stableStringify` were previously private to
 * plugin-thread-config.ts (thread-binding + prompt-cache fingerprints).
 * They are hoisted here unchanged so the approval-resolver paramsDigest
 * can reuse the exact same process-stable hashing.
 */
import crypto from "node:crypto";
import { getApprovalResolverForScope, hasApprovalResolverForScope } from "./approval-resolver.js";
import type { PluginJsonValue } from "./host-hook-json.js";
import type { ApprovalRequest } from "./host-hooks.js";
import {
  __resetDefaultProofLedgerForTest,
  getDefaultProofLedger,
  proofKey,
  type ProofLedger,
} from "./proof-ledger.js";

export function fingerprintJson(value: PluginJsonValue): string {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

export function stableStringify(value: PluginJsonValue | undefined): string {
  // Fingerprints must be process-stable across object insertion order so prompt
  // cache and thread-binding comparisons do not churn between runs.
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * Gateway-side digest of the exact params Codex will run. The `sha256:`
 * prefix is a convention layered on the bare hex so the digest is
 * self-describing on the wire (ApprovalRequest.paramsDigest).
 */
export function computeParamsDigest(params: PluginJsonValue): string {
  return `sha256:${fingerprintJson(params)}`;
}

/**
 * In-memory recorded-proof registry for the capability approval resolver seam.
 * Enforces two STRUCTURAL invariants (no crypto — signature validation stays
 * provider-internal):
 *
 *   1. single-use: a {requestId, paramsDigest} pair can be consumed at most
 *      once, so a resolver "allow" cannot release the same parked exec twice.
 *   2. replay: an opaque proof string is rejected on any second sighting, so a
 *      proof captured for one parked request cannot be replayed onto another.
 *
 * LIMITATION: state lives only in this process. It does NOT survive a gateway
 * restart, so single-use / replay rejection is not durable across restarts
 * (same caveat as the plugin file-store nonce path). Fail-closed callers must
 * treat a restart as a fresh registry.
 */

type ProofKey = string; // `${requestId.length}:${requestId}\0${paramsDigest}` — length-prefixed + null-byte, injective

type ProofRecord = {
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  proof?: string;
  consumedAt: number;
};

const consumedRecords = new Map<ProofKey, ProofRecord>();
const seenProofs = new Set<string>();

/**
 * Records and consumes a resolver decision keyed by {requestId, paramsDigest}.
 * Returns `already_consumed` if the same key was already consumed (single-use),
 * otherwise records it and returns ok. Structural only — does not inspect proof
 * contents.
 */
export function recordAndConsumeProof(rec: {
  requestId: string;
  paramsDigest: string;
  outcome: "allow" | "deny";
  proof?: string;
}): { ok: true } | { ok: false; reason: "already_consumed" | "invalid_identifier" } {
  if (!rec.requestId) {
    return { ok: false, reason: "invalid_identifier" };
  }
  if (!rec.paramsDigest) {
    return { ok: false, reason: "invalid_identifier" };
  }
  const key = proofKey(rec.requestId, rec.paramsDigest);
  if (consumedRecords.has(key)) {
    return { ok: false, reason: "already_consumed" };
  }
  consumedRecords.set(key, { ...rec, consumedAt: Date.now() });
  return { ok: true };
}

/**
 * Rejects a proof string that has been seen before (cross-request replay).
 * An undefined proof is treated as fresh and is NOT recorded, so an
 * absent-proof provider is not accidentally single-shotted.
 */
export function assertProofFresh(
  proof: string | undefined,
): { ok: true } | { ok: false; reason: "replayed" | "invalid_identifier" } {
  if (proof === undefined) {
    return { ok: true };
  }
  if (proof === "") {
    return { ok: false, reason: "invalid_identifier" };
  }
  if (seenProofs.has(proof)) {
    return { ok: false, reason: "replayed" };
  }
  seenProofs.add(proof);
  return { ok: true };
}

/** Clears both structures. Test-only. Also resets the default ledger singleton. */
export function __resetProofRegistryForTest(): void {
  consumedRecords.clear();
  seenProofs.clear();
  __resetDefaultProofLedgerForTest();
}

// ---------------------------------------------------------------------------
// decideCapabilityApproval — harness-neutral core primitive
// ---------------------------------------------------------------------------

/**
 * Verdict returned by the core capability-approval decision loop.
 * - `allow`: the resolver approved this request; `requestId` echoes the minted id.
 * - `deny`:  fail-closed decline. Two flavours, disambiguated by `failureDisposition`:
 *            • CLEAN POLICY DENY — the resolver returned a well-formed
 *              `decision:'deny'` with a matching requestId. This is a DECISION,
 *              not a failure, so `failureDisposition` is ABSENT and the caller
 *              should surface a graceful block (e.g. the front-stage veto path /
 *              a codex "decline"), mirroring a codex curl-deny.
 *            • FAILURE DENY — something went wrong (timeout, requestId mismatch,
 *              malformed decision value, resolver threw, ledger unavailable,
 *              proof replay/consume, abort). `failureDisposition` is SET
 *              (`timed_out` for deadline/abort-timeout, `failed` otherwise) so
 *              callers can surface the right error UX. Still fail-closed.
 * - `fallthrough`: no exclusive resolver owns `req.capability` so the caller
 *                  should proceed to the next decision stage (e.g. human tap).
 *
 * FAIL-CLOSED INVARIANT: the ONLY allow path is a matching-requestId
 * `decision:'allow'` that also passes proof-freshness + single-use consume.
 * Every other outcome — including a clean policy deny — denies.
 */
export type CapabilityApprovalVerdict =
  | { kind: "allow"; requestId: string }
  | {
      kind: "deny";
      requestId: string;
      reason?: string;
      failureDisposition?: "failed" | "timed_out";
    }
  | { kind: "fallthrough" };

/**
 * Runs the capability-scoped approval resolver decision loop for the supplied
 * pre-built `ApprovalRequest`.  The function is harness-neutral: it touches
 * only the active plugin registry and the in-process proof state; it never
 * references any Codex / app-server types.
 *
 * Fail-closed matrix:
 *  - no resolver              → fallthrough
 *  - poisoned entry           → deny (failed)  [TOCTOU guard]
 *  - resolver throws / catch  → deny (failed)
 *  - deadline expires         → deny (timed_out)
 *  - external signal aborted  → deny (timed_out)
 *  - verdict undefined        → deny (failed)
 *  - requestId mismatch       → deny (failed)    [protocol failure]
 *  - decision === "deny"      → deny (NO disposition)  [CLEAN policy deny → graceful block]
 *  - decision !∈ {allow,deny} → deny (failed)    [malformed → fail-closed]
 *  - proof replayed           → deny (failed)
 *  - pair already consumed    → deny (failed)
 *  - all guards pass          → allow
 */
export async function decideCapabilityApproval(
  req: ApprovalRequest,
  opts: { deadlineMs: number; signal?: AbortSignal; ledger?: ProofLedger },
): Promise<CapabilityApprovalVerdict> {
  // Step 1: check whether the scope is owned by any resolver.
  // hasApprovalResolverForScope is fail-closed: a poisoned entry returns true
  // so the gate engages rather than falling through.
  if (!hasApprovalResolverForScope(req.capability)) {
    return { kind: "fallthrough" };
  }

  // Step 2: fetch the entry.  A TOCTOU window exists between the has* and get*
  // calls; getApprovalResolverForScope returns the poisoned entry (rather than
  // undefined) so the throwing getter is hit below → fail-closed deny.
  const resolverEntry = getApprovalResolverForScope(req.capability);
  if (!resolverEntry) {
    // has* returned true but get* returned undefined — rare TOCTOU race;
    // treat as unavailable → deny (fail-closed, same as bridge line 565-571).
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: "approval resolver unavailable",
      failureDisposition: "failed",
    };
  }

  // Step 3: obtain the resolve fn.  If the entry is poisoned the getter throws;
  // catch → fail-closed deny.
  let resolveFn: (typeof resolverEntry.registration)["resolve"];
  try {
    resolveFn = resolverEntry.registration.resolve;
  } catch {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: "approval resolver unavailable",
      failureDisposition: "failed",
    };
  }

  // Step 4: build a combined abort controller so the deadline timer can abort
  // the resolver the same way an externally-cancelled signal can.
  const resolverAbort = new AbortController();
  const onRunAbort = () => resolverAbort.abort();
  if (opts.signal) {
    if (opts.signal.aborted) {
      resolverAbort.abort();
    } else {
      opts.signal.addEventListener("abort", onRunAbort, { once: true });
    }
  }

  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  let verdict: import("./host-hooks.js").ApprovalDecision | undefined;
  let timedOut = false;

  try {
    const resolvePromise = resolveFn(req, {
      signal: resolverAbort.signal,
      deadlineMs: opts.deadlineMs,
    });

    // Bridge-enforced deadline: a resolver that never resolves cannot park the
    // approval forever.  The timeout rejects; the catch below maps it to
    // denied/timed_out.  Aborting the resolver signal lets a cooperative
    // resolver stop waiting early.
    const deadlinePromise = new Promise<never>((_, reject) => {
      deadlineTimer = setTimeout(() => {
        timedOut = true;
        resolverAbort.abort();
        reject(new Error("approval resolver timed out"));
      }, opts.deadlineMs);
    });

    verdict = await Promise.race([resolvePromise, deadlinePromise]);
  } catch {
    verdict = undefined;
  } finally {
    if (deadlineTimer !== undefined) {
      clearTimeout(deadlineTimer);
    }
    if (opts.signal) {
      opts.signal.removeEventListener("abort", onRunAbort);
    }
  }

  // Step 5: map the outcome → verdict type.

  // Deadline expiry.
  if (timedOut) {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: "approval resolver timed out",
      failureDisposition: "timed_out",
    };
  }

  // External abort or no verdict from resolver (threw or returned undefined).
  if (opts.signal?.aborted === true || !verdict) {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: verdict?.reason ?? "approval resolver denied",
      failureDisposition: opts.signal?.aborted === true ? "timed_out" : "failed",
    };
  }

  // Allow-LIST — the ONLY allow path is a matching-requestId `decision:'allow'`.
  // Everything else denies (fail-closed). We split the deny reasons so a CLEAN
  // policy deny surfaces as a graceful block, while genuine protocol failures
  // keep a failureDisposition.

  // requestId mismatch = protocol failure (resolver echoed the wrong id).
  // Checked FIRST so a `decision:'deny'` with a mismatched id is still a failure,
  // not mistaken for a clean policy decision about THIS request.
  if (verdict.requestId !== req.requestId) {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: verdict.reason ?? "approval resolver requestId mismatch",
      failureDisposition: "failed",
    };
  }

  // Clean policy DENY (matching requestId) = a DECISION, not a failure.
  // Emit NO failureDisposition → the caller's graceful-block branch (front-stage
  // veto / codex "decline") fires, mirroring a codex curl-deny.
  if (verdict.decision === "deny") {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: verdict.reason ?? "denied by resolver",
    };
  }

  // Any decision value that is neither "allow" nor "deny" = malformed →
  // fail-closed failure (do NOT trust an unrecognized decision).
  if (verdict.decision !== "allow") {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: verdict.reason ?? "approval resolver returned an invalid decision",
      failureDisposition: "failed",
    };
  }

  // decision === "allow" with matching requestId → continue to the
  // proof-freshness / single-use consume check below (unchanged).

  // Structural single-use + cross-request replay rejection via durable ledger.
  // One atomic consumeOnce under a proper-lockfile advisory lock replaces the
  // old two-op (assertProofFresh + recordAndConsumeProof) TOCTOU window.
  const ledger = opts.ledger ?? getDefaultProofLedger();
  let ledgerResult: import("./proof-ledger.js").LedgerConsumeResult;
  try {
    ledgerResult = ledger.consumeOnce(verdict.proof, req.requestId, req.paramsDigest, "allow");
  } catch {
    // Ledger unavailable / corrupt / locked / audit-unwritable — FAIL CLOSED.
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: "approval proof ledger unavailable",
      failureDisposition: "failed",
    };
  }
  if (!ledgerResult.ok) {
    return {
      kind: "deny",
      requestId: req.requestId,
      reason: "approval proof rejected",
      failureDisposition: "failed",
    };
  }

  return { kind: "allow", requestId: req.requestId };
}
