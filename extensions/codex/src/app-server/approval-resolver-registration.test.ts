import {
  createEmptyPluginRegistry,
  setActivePluginRegistry,
} from "openclaw/plugin-sdk/plugin-test-runtime";
import {
  getApprovalResolverForScope,
  hasApprovalResolverForScope,
} from "openclaw/plugins/approval-resolver";
import type {
  ApprovalDecision,
  ApprovalRequest,
  PluginApprovalResolverRegistration,
} from "openclaw/plugins/host-hooks";
import type {
  PluginApprovalResolverRegistryRegistration,
  PluginRegistry,
} from "openclaw/plugins/registry-types";
import { afterEach, describe, expect, it } from "vitest";

function makeResolverRegistration(
  overrides: Partial<PluginApprovalResolverRegistration> = {},
): PluginApprovalResolverRegistration {
  return {
    id: "sigil-exec-resolver",
    description: "Sigil wallet approval for process.exec",
    scope: { capabilities: ["process.exec"] },
    exclusive: true,
    resolve: async (_req: ApprovalRequest): Promise<ApprovalDecision> => ({
      requestId: _req.requestId,
      decision: "allow",
    }),
    ...overrides,
  };
}

function makeRegistryRegistration(
  registration: PluginApprovalResolverRegistration,
): PluginApprovalResolverRegistryRegistration {
  return {
    pluginId: "sigil",
    pluginName: "Sigil",
    registration,
    source: "runtime",
  };
}

function registryWithResolvers(
  entries: PluginApprovalResolverRegistryRegistration[],
): PluginRegistry {
  return { ...createEmptyPluginRegistry(), approvalResolvers: entries };
}

describe("hasApprovalResolverForScope / getApprovalResolverForScope", () => {
  afterEach(() => setActivePluginRegistry(createEmptyPluginRegistry()));

  it("finds a process.exec resolver in the supplied registry", () => {
    const registration = makeResolverRegistration();
    const registry = registryWithResolvers([makeRegistryRegistration(registration)]);
    expect(hasApprovalResolverForScope("process.exec", registry)).toBe(true);
    const found = getApprovalResolverForScope("process.exec", registry);
    expect(found?.registration).toBe(registration);
  });

  it("reads the active registry when none is supplied", () => {
    const registration = makeResolverRegistration();
    setActivePluginRegistry(registryWithResolvers([makeRegistryRegistration(registration)]));
    expect(hasApprovalResolverForScope("process.exec")).toBe(true);
    expect(getApprovalResolverForScope("process.exec")?.registration).toBe(registration);
  });

  it("returns false/undefined when no resolver covers the capability", () => {
    const empty = createEmptyPluginRegistry();
    expect(hasApprovalResolverForScope("process.exec", empty)).toBe(false);
    expect(getApprovalResolverForScope("process.exec", empty)).toBeUndefined();
  });

  it("ignores entries whose scope does not include the capability", () => {
    // A registration whose capabilities array is empty must not match.
    const registration = makeResolverRegistration({ scope: { capabilities: [] } });
    const registry = registryWithResolvers([makeRegistryRegistration(registration)]);
    expect(hasApprovalResolverForScope("process.exec", registry)).toBe(false);
    expect(getApprovalResolverForScope("process.exec", registry)).toBeUndefined();
  });

  it("returns the FIRST matching resolver", () => {
    const first = makeResolverRegistration({ id: "first" });
    const second = makeResolverRegistration({ id: "second" });
    const registry = registryWithResolvers([
      makeRegistryRegistration(first),
      makeRegistryRegistration(second),
    ]);
    expect(getApprovalResolverForScope("process.exec", registry)?.registration.id).toBe("first");
  });

  it("fails closed when the registry field is unreadable (throwing getter)", () => {
    // Fail-closed: unreadable registry → gate ENGAGES (has=true, get returns poisoned entry).
    // The decision site (Task 11) hits the throwing getter on the returned entry and its
    // fail-closed catch denies the command — a registered resolver is NEVER silently bypassed.
    const hostile = {
      ...createEmptyPluginRegistry(),
      get approvalResolvers(): PluginApprovalResolverRegistryRegistration[] {
        throw new Error("approvalResolvers is unreadable");
      },
    } as unknown as PluginRegistry;
    expect(() => hasApprovalResolverForScope("process.exec", hostile)).not.toThrow();
    expect(hasApprovalResolverForScope("process.exec", hostile)).toBe(true);
    const got = getApprovalResolverForScope("process.exec", hostile);
    expect(got).toBeDefined();
    expect(() => got!.registration).toThrow();
  });

  it("fails closed when a single registration is unreadable (throwing scope)", () => {
    // Fail-closed: a poisoned entry terminates the lookup and the gate ENGAGES (has=true,
    // get returns the poisoned entry). The good entry after it is never reached — the
    // authority invariant requires the gate to fire, not skip past the unreadable resolver.
    // The decision site (Task 11) hits the throwing getter and its fail-closed catch denies.
    const good = makeRegistryRegistration(makeResolverRegistration());
    const poison = {
      pluginId: "evil",
      source: "runtime",
      get registration(): PluginApprovalResolverRegistration {
        throw new Error("registration is unreadable");
      },
    } as unknown as PluginApprovalResolverRegistryRegistration;
    const registry = registryWithResolvers([poison, good]);
    expect(() => hasApprovalResolverForScope("process.exec", registry)).not.toThrow();
    expect(hasApprovalResolverForScope("process.exec", registry)).toBe(true);
    const got = getApprovalResolverForScope("process.exec", registry);
    expect(got).toBeDefined();
    expect(() => got!.registration).toThrow();
  });

  it("fails closed on a null registry", () => {
    expect(hasApprovalResolverForScope("process.exec", null)).toBe(false);
    expect(getApprovalResolverForScope("process.exec", null)).toBeUndefined();
  });
});
