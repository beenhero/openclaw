// Core capability-approval proof registry — structural replay + single-use enforcement.
import { beforeEach, describe, expect, it } from "vitest";
import {
  __resetProofRegistryForTest,
  assertProofFresh,
  computeParamsDigest,
  fingerprintJson,
  recordAndConsumeProof,
} from "./capability-approval.js";
import type { PluginJsonValue } from "./host-hook-json.js";

describe("Codex approval-proof registry", () => {
  beforeEach(() => {
    __resetProofRegistryForTest();
  });

  it("consumes a {requestId,paramsDigest} key exactly once", () => {
    const rec = {
      requestId: "req-1",
      paramsDigest: "sha256:aaaa",
      outcome: "allow" as const,
    };

    expect(recordAndConsumeProof(rec)).toEqual({ ok: true });
    expect(recordAndConsumeProof(rec)).toEqual({
      ok: false,
      reason: "already_consumed",
    });
  });

  it("treats a different requestId or paramsDigest as a distinct key", () => {
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });

    // Same digest, different request id -> new key -> ok.
    expect(
      recordAndConsumeProof({
        requestId: "req-2",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });

    // Same request id, different digest -> new key -> ok.
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:bbbb",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
  });

  it("does not let a null-byte in requestId collide across the key separator", () => {
    // Guard against `${a} ${b}` key ambiguity: ("a b","c") vs ("a","b c").
    expect(
      recordAndConsumeProof({
        requestId: "a b",
        paramsDigest: "c",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
    expect(
      recordAndConsumeProof({
        requestId: "a",
        paramsDigest: "b c",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
  });

  it("marks a proof string replayed on the second sighting", () => {
    expect(assertProofFresh("proof-abc")).toEqual({ ok: true });
    expect(assertProofFresh("proof-abc")).toEqual({
      ok: false,
      reason: "replayed",
    });
  });

  it("treats an undefined proof as fresh without recording it", () => {
    expect(assertProofFresh(undefined)).toEqual({ ok: true });
    expect(assertProofFresh(undefined)).toEqual({ ok: true });
  });

  it("rejects recordAndConsumeProof when requestId is empty", () => {
    expect(
      recordAndConsumeProof({
        requestId: "",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: false, reason: "invalid_identifier" });
  });

  it("rejects recordAndConsumeProof when paramsDigest is empty", () => {
    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "",
        outcome: "allow",
      }),
    ).toEqual({ ok: false, reason: "invalid_identifier" });
  });

  it("rejects assertProofFresh when proof is an empty string", () => {
    expect(assertProofFresh("")).toEqual({
      ok: false,
      reason: "invalid_identifier",
    });
  });

  it("__resetProofRegistryForTest clears both the consumed keys and the seen proofs", () => {
    recordAndConsumeProof({
      requestId: "req-1",
      paramsDigest: "sha256:aaaa",
      outcome: "allow",
    });
    assertProofFresh("proof-abc");

    __resetProofRegistryForTest();

    expect(
      recordAndConsumeProof({
        requestId: "req-1",
        paramsDigest: "sha256:aaaa",
        outcome: "allow",
      }),
    ).toEqual({ ok: true });
    expect(assertProofFresh("proof-abc")).toEqual({ ok: true });
  });
});

describe("params-digest", () => {
  it("computeParamsDigest is key-order independent and sha256-prefixed", () => {
    const a: PluginJsonValue = { command: "/bin/ls", cwd: "/tmp", approval: { id: 1 } };
    const b: PluginJsonValue = { approval: { id: 1 }, cwd: "/tmp", command: "/bin/ls" };
    const digestA = computeParamsDigest(a);
    const digestB = computeParamsDigest(b);
    expect(digestA).toBe(digestB);
    expect(digestA).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("different command → different digest", () => {
    const base: PluginJsonValue = { command: "/bin/ls", cwd: "/tmp" };
    const other: PluginJsonValue = { command: "/bin/rm -rf /tmp/x", cwd: "/tmp" };
    expect(computeParamsDigest(base)).not.toBe(computeParamsDigest(other));
  });

  it("fingerprintJson returns bare 64-char hex (no prefix)", () => {
    const hex = fingerprintJson({ a: 1, b: [2, 3], c: null } satisfies PluginJsonValue);
    expect(hex).toMatch(/^[a-f0-9]{64}$/);
    // computeParamsDigest is exactly the prefixed form of fingerprintJson.
    expect(computeParamsDigest({ a: 1, b: [2, 3], c: null })).toBe(`sha256:${hex}`);
  });

  it("stableStringify semantics preserved: nested arrays keep order, object keys sort", () => {
    // Arrays are order-sensitive; only object keys are sorted.
    const ordered: PluginJsonValue = { list: [1, 2, 3] };
    const reordered: PluginJsonValue = { list: [3, 2, 1] };
    expect(fingerprintJson(ordered)).not.toBe(fingerprintJson(reordered));
  });

  it("computeParamsDigest pins a literal golden digest (algorithm-drift guard)", () => {
    // Computed once: stableStringify({command:"/bin/ls",cwd:"/tmp"}) →
    //   '{"command":"/bin/ls","cwd":"/tmp"}' (keys sort: command < cwd)
    // sha256 of that UTF-8 string = the hex below.
    // If this test ever breaks, the hashing algorithm or key-sort changed —
    // treat that as a breaking change to the wire format (paramsDigest).
    expect(computeParamsDigest({ command: "/bin/ls", cwd: "/tmp" })).toBe(
      "sha256:5c83d9f79f812871296758a1e01f42dcd28738c6bf45080f5fc577caa3aca01e",
    );
  });
});
