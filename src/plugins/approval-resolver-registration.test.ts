// Approval-resolver registration gate: soft diagnostics for duplicate/contract/enabled
// failures, and a HARD throw for any non-process.exec capability (fail-closed, §4.1/§7).
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

  it("THROWS (hard fail-closed) when scope.capabilities includes a non-process.exec entry", () => {
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({
              id: "sigil-net",
              scope: { capabilities: ["process.exec", "net.egress"] as never },
            }),
          );
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
    expect(registry.registry.approvalResolvers).toEqual([]);
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

  it("THROWS (hard fail-closed) for an unknown capability string (net.egress is not in KNOWN_CAPABILITIES)", () => {
    // L1.4 contract: KNOWN_CAPABILITIES = {"process.exec"} today.
    // Any other string — net.egress, fs.write, etc. — must hard-throw so a
    // plugin cannot silently believe it gates a surface OpenClaw does not enforce.
    const { config, registry } = createPluginRegistryFixture();
    expect(() =>
      registerTestPlugin({
        registry,
        config,
        record: createPluginRecord({ id: "sigil", name: "Sigil", origin: "bundled" }),
        register(api) {
          api.registerApprovalResolver(
            execResolver({
              id: "sigil-net",
              scope: { capabilities: ["net.egress"] as never },
            }),
          );
        },
      }),
    ).toThrow(/KNOWN_CAPABILITIES/);
    expect(registry.registry.approvalResolvers).toEqual([]);
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
});
