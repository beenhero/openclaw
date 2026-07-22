// Codex tests cover the recorded-proof registry structural replay + single-use enforcement.
import { beforeEach, describe, expect, it } from "vitest";
import {
  __resetProofRegistryForTest,
  assertProofFresh,
  recordAndConsumeProof,
} from "./approval-proof-registry.js";

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
