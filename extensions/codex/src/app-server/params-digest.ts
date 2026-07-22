/**
 * Shared, stable JSON fingerprinting for Codex app-server digests.
 *
 * `fingerprintJson`/`stableStringify` were previously private to
 * plugin-thread-config.ts (thread-binding + prompt-cache fingerprints).
 * They are hoisted here unchanged so the approval-resolver paramsDigest
 * can reuse the exact same process-stable hashing.
 */
import crypto from "node:crypto";
import type { JsonValue } from "./protocol.js";

export function fingerprintJson(value: JsonValue): string {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

export function stableStringify(value: JsonValue | undefined): string {
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
export function computeParamsDigest(params: JsonValue): string {
  return `sha256:${fingerprintJson(params)}`;
}
