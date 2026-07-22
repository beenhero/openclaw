// Provider-neutral approval-resolver conformance suite (AgentPass provider-receipt-v1
// core-seam cases). Exported so BOTH the OpenClaw mock-app-server driver (T14) and
// AgentPass's own harness can assert the identical gateway guarantees. Provider-internal
// proof-validity cases (invalid_signature / revoked / crypto) are declared out of scope:
// the gateway seam enforces STRUCTURAL replay/single-use only; cryptographic validity is
// the provider's responsibility.
import type {
  ApprovalDecision,
  ApprovalRequest,
  ApprovalResolver,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import { describe, expect, it } from "vitest";

/**
 * Dependencies a provider supplies to run the shared conformance cases.
 * - registerResolver: install a process.exec resolver into the provider's seam;
 *   the returned handle must dispose (unregister) it.
 * - drive: submit ONE in-scope command-execution escalation through the full seam and
 *   report whether the command actually ran (`ran`) plus the raw decision response.
 * - reset: clear any provider-side state (registry, recorded-proof registry) between cases.
 */
export type ApprovalResolverConformanceDeps = {
  registerResolver(resolve: ApprovalResolver): { dispose(): void };
  drive(input: { command: string; cwd?: string }): Promise<{ response: unknown; ran: boolean }>;
  reset(): void;
};

export function runApprovalResolverConformance(deps: ApprovalResolverConformanceDeps): void {
  describe("approval-resolver conformance (provider-receipt-v1 core seam)", () => {
    // Each case installs its own resolver and disposes it; reset() clears seam state.
    const withResolver = async (
      resolve: ApprovalResolver,
      input: { command: string; cwd?: string },
    ): Promise<{ response: unknown; ran: boolean }> => {
      const handle = deps.registerResolver(resolve);
      try {
        return await deps.drive(input);
      } finally {
        handle.dispose();
        deps.reset();
      }
    };

    // An echoing allow: binds to the exact request it was handed (requestId + paramsDigest).
    const echoAllow = (proof?: string): ApprovalResolver => {
      return async (req: ApprovalRequest): Promise<ApprovalDecision> => ({
        requestId: req.requestId,
        decision: "allow",
        ...(proof === undefined ? {} : { proof }),
      });
    };

    it("valid allow lets the command run", async () => {
      const { response, ran } = await withResolver(echoAllow(), {
        command: "/bin/echo hello",
      });
      expect(ran).toBe(true);
      expect(response).toMatchObject({
        decision: expect.stringMatching(/^(approved|approved-once)$/),
      });
    });

    it("valid deny blocks the command (fail-closed)", async () => {
      const deny: ApprovalResolver = async (req) => ({
        requestId: req.requestId,
        decision: "deny",
        reason: "policy",
      });
      const { response, ran } = await withResolver(deny, { command: "rm -rf /tmp/x" });
      expect(ran).toBe(false);
      expect(response).toMatchObject({ decision: "denied" });
    });

    it("request-binding: a verdict echoing the WRONG requestId is rejected (fail-closed)", async () => {
      const substitute: ApprovalResolver = async () => ({
        requestId: "attacker-controlled-id",
        decision: "allow",
      });
      const { ran, response } = await withResolver(substitute, { command: "/bin/echo bind" });
      expect(ran).toBe(false);
      expect(response).toMatchObject({ decision: "denied" });
    });

    it("exclusive dispatch: with NO resolver the command is not resolver-approved (fall-through byte-unchanged)", async () => {
      // No registerResolver call: the resolver seam must not manufacture an allow.
      const { ran } = await deps.drive({ command: "/bin/echo fallthrough" });
      deps.reset();
      expect(ran).toBe(false);
    });

    it("exclusive dispatch: the in-scope decision reaches ONLY the resolver", async () => {
      let seen = 0;
      const counting: ApprovalResolver = async (req) => {
        seen += 1;
        return { requestId: req.requestId, decision: "deny" };
      };
      const { ran } = await withResolver(counting, { command: "/bin/echo exclusive" });
      expect(seen).toBe(1); // exactly one dispatch, no double-decide with a parallel path
      expect(ran).toBe(false);
    });

    it("deadline: a resolver that never answers fails closed", async () => {
      const stall: ApprovalResolver = (_req, opts) => {
        return new Promise<ApprovalDecision>((_resolve, reject) => {
          // Honor the abort the seam raises at deadlineMs; never allow.
          opts.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        });
      };
      const { ran, response } = await withResolver(stall, { command: "/bin/echo slow" });
      expect(ran).toBe(false);
      expect(response).toMatchObject({ decision: "denied" });
    });

    it("missing/disconnect: a throwing resolver fails closed", async () => {
      const boom: ApprovalResolver = async () => {
        throw new Error("provider unavailable");
      };
      const { ran, response } = await withResolver(boom, { command: "/bin/echo down" });
      expect(ran).toBe(false);
      expect(response).toMatchObject({ decision: "denied" });
    });

    it("recorded-proof single-use: a proof cannot authorize a second command (replay rejected)", async () => {
      const proof = "receipt-abc123";
      const handle = deps.registerResolver(echoAllow(proof));
      try {
        const first = await deps.drive({ command: "/bin/echo once" });
        const second = await deps.drive({ command: "/bin/echo twice" });
        expect(first.ran).toBe(true);
        expect(second.ran).toBe(false); // same proof replayed onto a new request -> denied
        expect(second.response).toMatchObject({ decision: "denied" });
      } finally {
        handle.dispose();
        deps.reset();
      }
    });

    it("budget: denies remain fail-closed under repeated load", async () => {
      const deny: ApprovalResolver = async (req) => ({
        requestId: req.requestId,
        decision: "deny",
      });
      const handle = deps.registerResolver(deny);
      try {
        const results = await Promise.all(
          Array.from({ length: 8 }, (_v, i) => deps.drive({ command: `/bin/echo load-${i}` })),
        );
        expect(results.every((r) => r.ran === false)).toBe(true);
      } finally {
        handle.dispose();
        deps.reset();
      }
    });

    // ---- Provider-internal (OUT of gateway scope): declared, not implemented ----
    it.skip("invalid_signature -> denied (PROVIDER-INTERNAL: crypto validity is provider-owned, not gateway-enforced)", () => {
      // Intentionally unimplemented: the gateway seam validates STRUCTURAL binding
      // (requestId + paramsDigest) and single-use only. Signature validity lives inside
      // the resolver/provider (AgentPass), so this case is asserted in the provider's own suite.
    });

    it.skip("revoked receipt -> denied (PROVIDER-INTERNAL: revocation state is provider-owned)", () => {
      // Intentionally unimplemented: revocation is provider-internal, out of gateway scope.
    });
  });
}
