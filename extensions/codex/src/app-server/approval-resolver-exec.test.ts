// Codex tests cover app server policy plugin behavior.
import { describe, expect, it } from "vitest";
import { resolveCodexAppServerForOpenClawToolPolicy } from "./app-server-policy.js";
import { readCodexPluginConfig, resolveCodexAppServerRuntimeOptions } from "./config.js";

describe("shouldPromote resolver fold-in", () => {
  // Mirrors the OR term wired at run-attempt-connection.ts:253-255:
  //   shouldPromote = hasBeforeToolCallHook || trustedToolPolicies.length > 0 || hasApprovalResolverForScope
  const shouldPromoteFrom = (policy: {
    hasBeforeToolCallHook: boolean;
    trustedToolPolicies: unknown[];
    hasApprovalResolverForScope: boolean;
  }): boolean =>
    policy.hasBeforeToolCallHook ||
    policy.trustedToolPolicies.length > 0 ||
    policy.hasApprovalResolverForScope;

  it("promotes implicit never->untrusted when only a process.exec resolver is present", () => {
    const appServer = resolveCodexAppServerRuntimeOptions({ env: {}, requirementsToml: null });
    expect(appServer.approvalPolicy).toBe("never");

    const shouldPromote = shouldPromoteFrom({
      hasBeforeToolCallHook: false,
      trustedToolPolicies: [],
      hasApprovalResolverForScope: true, // resolver registered, no hook / no trusted policy
    });
    expect(shouldPromote).toBe(true);

    const resolved = resolveCodexAppServerForOpenClawToolPolicy({
      appServer,
      pluginConfig: readCodexPluginConfig({}),
      env: {},
      shouldPromote,
      canUseUntrustedApprovalPolicy: true,
    });
    expect(resolved.approvalPolicy).toBe("untrusted");
  });

  it("does not promote when no hook, no trusted policy, and no resolver (byte-unchanged)", () => {
    const appServer = resolveCodexAppServerRuntimeOptions({ env: {}, requirementsToml: null });

    const shouldPromote = shouldPromoteFrom({
      hasBeforeToolCallHook: false,
      trustedToolPolicies: [],
      hasApprovalResolverForScope: false,
    });
    expect(shouldPromote).toBe(false);

    const resolved = resolveCodexAppServerForOpenClawToolPolicy({
      appServer,
      pluginConfig: readCodexPluginConfig({}),
      env: {},
      shouldPromote,
      canUseUntrustedApprovalPolicy: true,
    });
    expect(resolved.approvalPolicy).toBe("never");
  });

  it("resolver presence does NOT override an explicit operator approval policy", () => {
    // app-server-policy.ts:35-42 bail-out: an explicit plugin-config approvalPolicy wins
    // even when shouldPromote is true because a resolver is registered.
    const appServer = resolveCodexAppServerRuntimeOptions({ env: {}, requirementsToml: null });

    const resolved = resolveCodexAppServerForOpenClawToolPolicy({
      appServer,
      pluginConfig: readCodexPluginConfig({ appServer: { approvalPolicy: "never" } }),
      env: {},
      shouldPromote: true, // resolver present
      canUseUntrustedApprovalPolicy: true,
    });
    expect(resolved.approvalPolicy).toBe("never"); // operator override preserved
  });
});
