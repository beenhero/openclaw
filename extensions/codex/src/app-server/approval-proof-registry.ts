/**
 * In-memory recorded-proof registry for the codex process.exec approval
 * resolver seam. Enforces two STRUCTURAL invariants (no crypto — signature
 * validation stays provider-internal):
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

function proofKey(requestId: string, paramsDigest: string): ProofKey {
  // Use a length-prefix encoding to avoid key ambiguity:
  // ("a b","c") and ("a","b c") must not produce the same composite key.
  return `${requestId.length}:${requestId}\0${paramsDigest}`;
}

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

/** Clears both structures. Test-only. */
export function __resetProofRegistryForTest(): void {
  consumedRecords.clear();
  seenProofs.clear();
}
