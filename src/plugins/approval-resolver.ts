// Resolves capability-scoped approval resolvers from the active plugin registry.
// Mirrors trusted-tool-policy.ts:34-71 (unreadable => fail-closed, no throw escapes).
import type { ApprovalCapability } from "./host-hooks.js";
import type { PluginApprovalResolverRegistration } from "./host-hooks.js";
import type {
  PluginApprovalResolverRegistryRegistration,
  PluginRegistry,
} from "./registry-types.js";
import { getActivePluginRegistry } from "./runtime.js";

type ApprovalResolverRegistry =
  | { approvalResolvers?: PluginRegistry["approvalResolvers"] }
  | null
  | undefined;

function unreadableApprovalResolverRegistration(): PluginApprovalResolverRegistryRegistration {
  return {
    pluginId: "unknown-plugin",
    source: "runtime",
    get registration(): PluginApprovalResolverRegistration {
      throw new Error("approval resolver registration is unreadable");
    },
  };
}

function copyApprovalResolverRegistrations(
  registry: ApprovalResolverRegistry,
): PluginApprovalResolverRegistryRegistration[] {
  let resolvers: unknown;
  try {
    resolvers = registry?.approvalResolvers;
  } catch {
    return [unreadableApprovalResolverRegistration()];
  }
  if (!resolvers) {
    return [];
  }
  try {
    if (!Array.isArray(resolvers)) {
      return [unreadableApprovalResolverRegistration()];
    }
    return resolvers.map((resolver) => resolver);
  } catch {
    return [unreadableApprovalResolverRegistration()];
  }
}

const UNREADABLE = Symbol("unreadable");

function registrationCoversCapability(
  entry: PluginApprovalResolverRegistryRegistration,
  cap: ApprovalCapability,
): boolean | typeof UNREADABLE {
  try {
    const capabilities = entry.registration.scope.capabilities;
    return Array.isArray(capabilities) && capabilities.includes(cap);
  } catch {
    // An unreadable registration is terminal — fail the entire lookup (fail-closed).
    return UNREADABLE;
  }
}

/** True when the supplied or active plugin registry has a resolver covering `cap`. */
export function hasApprovalResolverForScope(
  cap: ApprovalCapability,
  registry: ApprovalResolverRegistry = getActivePluginRegistry(),
): boolean {
  for (const entry of copyApprovalResolverRegistrations(registry)) {
    const result = registrationCoversCapability(entry, cap);
    if (result === UNREADABLE) {
      // Fail-closed: an unreadable registration might cover the capability;
      // assume it does so the gate engages rather than bypassing a registered resolver.
      // Matches the hasTrustedToolPolicies precedent (poisoned array → length > 0 → gate fires).
      return true;
    }
    if (result) {
      return true;
    }
  }
  return false;
}

/**
 * First resolver covering `cap`, or undefined. Exclusivity is enforced at
 * registration (T3), so at most one match survives the register-time guards.
 */
export function getApprovalResolverForScope(
  cap: ApprovalCapability,
  registry: ApprovalResolverRegistry = getActivePluginRegistry(),
): PluginApprovalResolverRegistryRegistration | undefined {
  for (const entry of copyApprovalResolverRegistrations(registry)) {
    const result = registrationCoversCapability(entry, cap);
    if (result === UNREADABLE) {
      // Fail-closed: return the poisoned entry so the decision site (Task 11) hits the
      // throwing getter and its fail-closed catch denies the command.
      // Returning undefined would let Task 11 treat it as "no resolver" and proceed ungated.
      return entry;
    }
    if (result) {
      return entry;
    }
  }
  return undefined;
}
