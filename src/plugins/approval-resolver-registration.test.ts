// Approval-resolver registration gate: soft diagnostics for duplicate/contract/enabled
// failures, and a HARD throw for any capability not in KNOWN_CAPABILITIES (fail-closed, §4.1/§7).
// L3.1: KNOWN_CAPABILITIES = {"process.exec", "net.egress"}. net.egress tests added below.
import {
  createPluginRegistryFixture,
  registerTestPlugin,
} from "openclaw/plugin-sdk/plugin-test-contracts";
import { describe, expect, it } from "vitest";
import type {
  ApprovalDecision,
  ApprovalRequest,
  PluginApprovalResolverRegistration,
} from "./host-hooks.js";
import { KNOWN_CAPABILITIES } from "./host-hooks.js";
import { createPluginRecord } from "./status.test-fixtures.js";

const noopResolve = async (_req: ApprovalRequest): Promise<ApprovalDecision> => ({
  requestId: _req.requestId,
  decision: "deny",
});

function execResolver(
  overrides: Partial<PluginApprovalResolverRegistration> = {},
): PluginApprovalResolverRegistration {
  return {
    id: "sigil-exec",
    description: "Sigil wallet-signed exec approval",
    scope: { capabilities: ["process.exec"] },
    exclusive: true,
    resolve: noopResolve,
    ...overrides,
  };
}

describe("registerApprovalResolver host registrar", () => {
  it("registers a valid process.exec resolver into registry.approvalResolvers", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
      register(api) {
        api.registerApprovalResolver(execResolver());
      },
    });

    expect(registry.registry.approvalResolvers).toEqual([
      expect.objectContaining({
        pluginId: "sigil",
        pluginName: "Sigil",
        registration: expect.objectContaining({
          id: "sigil-exec",
          description: "Sigil wallet-signed exec approval",
          scope: { capabilities: ["process.exec"] },
          exclusive: true,
        }),
      }),
    ]);
    expect(registry.registry.diagnostics).toEqual([]);
  });

  it("THROWS (hard fail-closed) when scope.capabilities is empty (zero capabilities claimed)", () => {
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({
              id: "sigil-empty",
              scope: { capabilities: [] as never },
            }),
          );
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
    expect(registry.registry.approvalResolvers).toEqual([]);
  });

  it("THROWS (hard fail-closed) when scope.capabilities includes a capability NOT in KNOWN_CAPABILITIES", () => {
    // L3.1: KNOWN_CAPABILITIES = {"process.exec", "net.egress", "fs.write"} (L6.1 adds fs.write).
    // An unknown capability like "http.request" must hard-throw — guard is 'not in KNOWN_CAPABILITIES'.
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({
              id: "sigil-http",
              scope: { capabilities: ["process.exec", "http.request"] as never },
            }),
          );
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
    expect(registry.registry.approvalResolvers).toEqual([]);
  });

  it("registers an fs.write resolver now that fs.write is in KNOWN_CAPABILITIES (L6.1)", () => {
    // L6.1 adds "fs.write" to KNOWN_CAPABILITIES — a resolver claiming it must no longer throw.
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
      register(api) {
        api.registerApprovalResolver(
          execResolver({
            id: "sigil-fs",
            scope: { capabilities: ["fs.write"] as unknown as ["process.exec"] },
          }),
        );
      },
    });
    expect(registry.registry.approvalResolvers).toHaveLength(1);
    expect(registry.registry.diagnostics).toEqual([]);
  });

  it("soft-rejects a duplicate pluginId+id (diagnostic, no second entry, no throw)", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
      register(api) {
        api.registerApprovalResolver(execResolver());
        api.registerApprovalResolver(execResolver({ description: "second attempt" }));
      },
    });

    expect(registry.registry.approvalResolvers).toHaveLength(1);
    expect(registry.registry.approvalResolvers[0]?.registration.description).toBe(
      "Sigil wallet-signed exec approval",
    );
    expect(registry.registry.diagnostics).toEqual([
      expect.objectContaining({
        level: "error",
        pluginId: "sigil",
        message: expect.stringContaining("approval resolver already registered: sigil-exec"),
      }),
    ]);
  });

  it("soft-rejects an installed plugin that does not declare contracts.approvalResolvers", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "sigil",
        name: "Sigil",
        origin: "workspace",
        contracts: { approvalResolvers: [] },
      }),
      register(api) {
        api.registerApprovalResolver(execResolver());
      },
    });

    expect(registry.registry.approvalResolvers).toEqual([]);
    expect(registry.registry.diagnostics).toEqual([
      expect.objectContaining({
        level: "error",
        pluginId: "sigil",
        message: expect.stringContaining(
          "plugin must declare contracts.approvalResolvers for: sigil-exec",
        ),
      }),
    ]);
  });

  it("soft-rejects an installed plugin that is not explicitly enabled", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "sigil",
        name: "Sigil",
        origin: "workspace",
        enabled: true,
        explicitlyEnabled: false,
        contracts: { approvalResolvers: ["sigil-exec"] },
      }),
      register(api) {
        api.registerApprovalResolver(execResolver());
      },
    });

    expect(registry.registry.approvalResolvers).toEqual([]);
    expect(registry.registry.diagnostics).toEqual([
      expect.objectContaining({
        level: "error",
        pluginId: "sigil",
        message: expect.stringContaining(
          "plugin must be explicitly enabled to register approval resolver: sigil-exec",
        ),
      }),
    ]);
  });

  it("L3.1: registers a net.egress resolver cleanly (net.egress is now in KNOWN_CAPABILITIES)", () => {
    // L3.1: net.egress added to KNOWN_CAPABILITIES. A resolver declaring capabilities:['net.egress']
    // must now register without throwing.
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({ id: "sigil-net-plugin", name: "Sigil Net", origin: "bundled" }),
      register(api) {
        api.registerApprovalResolver(
          execResolver({
            id: "sigil-net-resolver",
            scope: { capabilities: ["net.egress"] },
          }),
        );
      },
    });
    expect(registry.registry.approvalResolvers).toHaveLength(1);
    expect(registry.registry.approvalResolvers[0]?.registration.scope.capabilities).toEqual([
      "net.egress",
    ]);
    expect(registry.registry.diagnostics).toEqual([]);
  });

  it("L3.1: THROWS for a capability NOT in KNOWN_CAPABILITIES (e.g. 'mcp.invoke')", () => {
    // KNOWN_CAPABILITIES = {"process.exec", "net.egress", "fs.write"} (L6.1). Anything else hard-throws.
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({
              id: "sigil-mcp",
              scope: { capabilities: ["mcp.invoke"] as never },
            }),
          );
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
    expect(registry.registry.approvalResolvers).toEqual([]);
  });

  it("L3.1 + L6.1: KNOWN_CAPABILITIES Set membership — process.exec, net.egress, and fs.write are members", () => {
    // L3.1 established process.exec + net.egress; L6.1 adds fs.write.
    expect(KNOWN_CAPABILITIES.has("process.exec")).toBe(true);
    expect(KNOWN_CAPABILITIES.has("net.egress")).toBe(true);
    expect(KNOWN_CAPABILITIES.has("fs.write")).toBe(true);
    // Unknown capabilities remain outside the set
    expect(KNOWN_CAPABILITIES.has("http.request")).toBe(false);
    expect(KNOWN_CAPABILITIES.has("mcp.invoke")).toBe(false);
  });

  it("STILL registers process.exec after the KNOWN_CAPABILITIES contract reshape (regression)", () => {
    // process.exec is in KNOWN_CAPABILITIES and must still register cleanly.
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
      register(api) {
        api.registerApprovalResolver(execResolver());
      },
    });
    expect(registry.registry.approvalResolvers).toHaveLength(1);
    expect(registry.registry.diagnostics).toEqual([]);
  });

  // ---------------------------------------------------------------------------
  // L3.2 — per-capability owner-conflict guard
  // ---------------------------------------------------------------------------
  describe("L3.2 per-capability owner-conflict guard", () => {
    it("soft-rejects a second resolver from a DIFFERENT plugin claiming the same capability", () => {
      // Two bundled plugins both claim process.exec → second is rejected with owner-conflict diagnostic.
      const { config, registry } = createPluginRegistryFixture();
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "plugin-a", name: "Plugin A", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(execResolver({ id: "resolver-a" }));
        },
      });
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "plugin-b", name: "Plugin B", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(execResolver({ id: "resolver-b" }));
        },
      });

      // Only the first resolver should be registered.
      expect(registry.registry.approvalResolvers).toHaveLength(1);
      expect(registry.registry.approvalResolvers[0]?.pluginId).toBe("plugin-a");
      expect(registry.registry.diagnostics).toEqual([
        expect.objectContaining({
          level: "error",
          pluginId: "plugin-b",
          message: expect.stringContaining("capability process.exec already owned by plugin-a"),
        }),
      ]);
    });

    it("allows a resolver claiming a currently-free capability (net.egress) to register fine", () => {
      // First resolver claims process.exec; second resolver claims net.egress (different capability — no conflict).
      const { config, registry } = createPluginRegistryFixture();
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "plugin-exec", name: "Exec Plugin", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(execResolver({ id: "exec-resolver" }));
        },
      });
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "plugin-net", name: "Net Plugin", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({ id: "net-resolver", scope: { capabilities: ["net.egress"] } }),
          );
        },
      });

      expect(registry.registry.approvalResolvers).toHaveLength(2);
      expect(registry.registry.diagnostics).toEqual([]);
    });

    it("same-plugin re-register still hits the existing (pluginId,id) dedup path, not the owner-conflict path", () => {
      // Same plugin, same id — hits the dedup guard before the owner-conflict guard.
      const { config, registry } = createPluginRegistryFixture();
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(execResolver());
          api.registerApprovalResolver(execResolver({ description: "second attempt" }));
        },
      });

      expect(registry.registry.approvalResolvers).toHaveLength(1);
      // Must match the dedup message, NOT the owner-conflict message.
      expect(registry.registry.diagnostics).toEqual([
        expect.objectContaining({
          level: "error",
          pluginId: "sigil",
          message: expect.stringContaining("approval resolver already registered: sigil-exec"),
        }),
      ]);
      // Confirm the owner-conflict diagnostic was NOT emitted.
      expect(registry.registry.diagnostics[0]?.message).not.toMatch(/already owned by/);
    });
  });
});

// ---------------------------------------------------------------------------
// L3.6 — Tier-B: registerToolMetadata capabilities validation
// ---------------------------------------------------------------------------

describe("registerToolMetadata capabilities validation (L3.6 Tier-B)", () => {
  it("registers tool metadata with valid capabilities:['net.egress']", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "my-plugin",
        name: "My Plugin",
        origin: "workspace",
        contracts: { tools: ["my_fetch_tool"] },
      }),
      register(api) {
        api.registerToolMetadata({
          toolName: "my_fetch_tool",
          displayName: "My Fetch Tool",
          capabilities: ["net.egress"],
        });
      },
    });

    expect(registry.registry.toolMetadata).toHaveLength(1);
    const meta = registry.registry.toolMetadata[0]?.metadata;
    expect(meta?.toolName).toBe("my_fetch_tool");
    expect(meta?.capabilities).toEqual(["net.egress"]);
    expect(registry.registry.diagnostics).toHaveLength(0);
  });

  it("registers tool metadata with valid capabilities:['process.exec']", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "my-plugin",
        name: "My Plugin",
        origin: "workspace",
        contracts: { tools: ["my_exec_tool"] },
      }),
      register(api) {
        api.registerToolMetadata({
          toolName: "my_exec_tool",
          capabilities: ["process.exec"],
        });
      },
    });

    expect(registry.registry.toolMetadata).toHaveLength(1);
    expect(registry.registry.toolMetadata[0]?.metadata.capabilities).toEqual(["process.exec"]);
    expect(registry.registry.diagnostics).toHaveLength(0);
  });

  it("registers tool metadata with capabilities=['fs.write'] now that fs.write is in KNOWN_CAPABILITIES (L6.1)", () => {
    // L6.1 adds "fs.write" to KNOWN_CAPABILITIES — registerToolMetadata with fs.write must succeed.
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "my-plugin",
        name: "My Plugin",
        origin: "workspace",
        contracts: { tools: ["my_tool"] },
      }),
      register(api) {
        api.registerToolMetadata({
          toolName: "my_tool",
          displayName: "My Write Tool",
          capabilities: ["fs.write"] as unknown as ["process.exec"],
        });
      },
    });
    expect(registry.registry.toolMetadata).toHaveLength(1);
    expect(registry.registry.diagnostics).toHaveLength(0);
  });

  it("THROWS (fail-closed) when capabilities includes an unknown capability (e.g. 'mcp.invoke')", () => {
    // 'mcp.invoke' is NOT in KNOWN_CAPABILITIES — must still hard-throw.
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({
          id: "my-plugin",
          name: "My Plugin",
          origin: "workspace",
          contracts: { tools: ["my_tool"] },
        }),
        register(api) {
          api.registerToolMetadata({
            toolName: "my_tool",
            // @ts-expect-error testing invalid capability
            capabilities: ["mcp.invoke"],
          });
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
  });

  it("registers tool metadata without capabilities (undefined → no Tier-B effects)", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "my-plugin",
        name: "My Plugin",
        origin: "workspace",
        contracts: { tools: ["my_tool"] },
      }),
      register(api) {
        api.registerToolMetadata({
          toolName: "my_tool",
          displayName: "My Tool",
          // No capabilities — fine
        });
      },
    });

    expect(registry.registry.toolMetadata).toHaveLength(1);
    expect(registry.registry.toolMetadata[0]?.metadata.capabilities).toBeUndefined();
    expect(registry.registry.diagnostics).toHaveLength(0);
  });

  it("KNOWN_CAPABILITIES contains process.exec, net.egress, and fs.write (L6.1)", () => {
    // L6.1 adds "fs.write" to the wired capability set.
    expect(KNOWN_CAPABILITIES.has("process.exec")).toBe(true);
    expect(KNOWN_CAPABILITIES.has("net.egress")).toBe(true);
    expect(KNOWN_CAPABILITIES.has("fs.write")).toBe(true);
    // Unknown capabilities still outside the set:
    expect(KNOWN_CAPABILITIES.has("http.request")).toBe(false);
    expect(KNOWN_CAPABILITIES.has("mcp.invoke")).toBe(false);
  });

  // SHRINK-1: duplicate capabilities must be deduped at registration
  it("SHRINK-1: registering capabilities:['net.egress','net.egress'] stores ['net.egress'] (deduped)", () => {
    const { config, registry } = createPluginRegistryFixture();
    registerTestPlugin({
      registry,
      config,
      record: createPluginRecord({
        id: "my-plugin",
        name: "My Plugin",
        origin: "workspace",
        contracts: { tools: ["my_fetch_tool"] },
      }),
      register(api) {
        api.registerToolMetadata({
          toolName: "my_fetch_tool",
          displayName: "My Fetch Tool",
          // @ts-expect-error testing duplicate valid capabilities (runtime dedupe)
          capabilities: ["net.egress", "net.egress"],
        });
      },
    });

    expect(registry.registry.toolMetadata).toHaveLength(1);
    const stored = registry.registry.toolMetadata[0]?.metadata.capabilities;
    // Must be deduped: only one 'net.egress'
    expect(stored).toEqual(["net.egress"]);
    expect(registry.registry.diagnostics).toHaveLength(0);
  });
});
