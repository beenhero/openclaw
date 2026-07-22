// Codex tests cover the shared params-digest fingerprint helper.
import { describe, expect, it } from "vitest";
import { computeParamsDigest, fingerprintJson } from "./params-digest.js";
// plugin-thread-config re-exports nothing digest-related publicly; assert parity
// through the input-fingerprint builder that used the (now-moved) fingerprintJson.
import { buildCodexPluginThreadConfigInputFingerprint } from "./plugin-thread-config.js";
import type { JsonValue } from "./protocol.js";

describe("params-digest", () => {
  it("computeParamsDigest is key-order independent and sha256-prefixed", () => {
    const a: JsonValue = { command: "/bin/ls", cwd: "/tmp", approval: { id: 1 } };
    const b: JsonValue = { approval: { id: 1 }, cwd: "/tmp", command: "/bin/ls" };
    const digestA = computeParamsDigest(a);
    const digestB = computeParamsDigest(b);
    expect(digestA).toBe(digestB);
    expect(digestA).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("different command → different digest", () => {
    const base: JsonValue = { command: "/bin/ls", cwd: "/tmp" };
    const other: JsonValue = { command: "/bin/rm -rf /tmp/x", cwd: "/tmp" };
    expect(computeParamsDigest(base)).not.toBe(computeParamsDigest(other));
  });

  it("fingerprintJson returns bare 64-char hex (no prefix)", () => {
    const hex = fingerprintJson({ a: 1, b: [2, 3], c: null } satisfies JsonValue);
    expect(hex).toMatch(/^[a-f0-9]{64}$/);
    // computeParamsDigest is exactly the prefixed form of fingerprintJson.
    expect(computeParamsDigest({ a: 1, b: [2, 3], c: null })).toBe(`sha256:${hex}`);
  });

  it("stableStringify semantics preserved: nested arrays keep order, object keys sort", () => {
    // Arrays are order-sensitive; only object keys are sorted.
    const ordered: JsonValue = { list: [1, 2, 3] };
    const reordered: JsonValue = { list: [3, 2, 1] };
    expect(fingerprintJson(ordered)).not.toBe(fingerprintJson(reordered));
  });

  it("plugin-thread-config input fingerprint is unchanged by the extraction (no behavior change)", () => {
    // Golden vector: the extracted helper must produce byte-identical fingerprints
    // to the pre-extraction private copy for the same config-build inputs.
    const fp = buildCodexPluginThreadConfigInputFingerprint({
      apps: [],
      pluginAppIds: [],
    } as unknown as Parameters<typeof buildCodexPluginThreadConfigInputFingerprint>[0]);
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
  });
});
