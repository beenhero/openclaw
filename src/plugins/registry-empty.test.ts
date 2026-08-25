// Covers the empty plugin registry seam.
import { describe, expect, it } from "vitest";
import { createEmptyPluginRegistry } from "./registry-empty.js";

describe("createEmptyPluginRegistry", () => {
  it("exposes an empty approvalResolvers array", () => {
    const registry = createEmptyPluginRegistry();
    expect(registry.approvalResolvers).toEqual([]);
  });
});
