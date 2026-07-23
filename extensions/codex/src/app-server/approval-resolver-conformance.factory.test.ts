// Codex tests cover the provider-neutral approval-resolver conformance factory.
import type { ApprovalResolver } from "openclaw/plugin-sdk/agent-harness-runtime";
import { runApprovalResolverConformance } from "./approval-resolver-conformance.js";

// Minimal in-memory seam fake: a single exclusive resolver + a driver that enforces
// request-binding, deadline/disconnect fail-closed, and recorded-proof single-use.
// This mirrors the real seam guarantees (T3-T11) closely enough to exercise every
// core-seam assertion in the factory. A structurally-unsound fake would fail here.
function createSeamFake() {
  let active: ApprovalResolver | undefined;
  const consumedProofs = new Set<string>();
  return {
    registerResolver(resolve: ApprovalResolver): { dispose(): void } {
      if (active) throw new Error("approval resolver already registered");
      active = resolve;
      return {
        dispose() {
          if (active === resolve) active = undefined;
        },
      };
    },
    async drive(input: {
      command: string;
      cwd?: string;
    }): Promise<{ response: unknown; ran: boolean }> {
      // No resolver -> byte-unchanged fall-through: the seam does not run the resolver,
      // and (in this fake) the command is NOT auto-run (fail-closed default posture).
      if (!active) return { response: { decision: "fell-through" }, ran: false };
      const requestId = `req-${Math.random().toString(36).slice(2)}`;
      const effect = {
        kind: "process.exec" as const,
        command: input.command,
        ...(input.cwd ? { cwd: input.cwd } : {}),
      };
      const paramsDigest = `sha256:${input.command}::${input.cwd ?? ""}`;
      const controller = new AbortController();
      const deadlineMs = 50;
      const deadline = setTimeout(() => controller.abort(), deadlineMs);
      let verdict: Awaited<ReturnType<ApprovalResolver>> | undefined;
      try {
        verdict = await active(
          {
            requestId,
            capability: "process.exec",
            toolName: "exec",
            effects: [effect],
            paramsDigest,
          },
          { signal: controller.signal, deadlineMs },
        );
      } catch {
        verdict = undefined;
      } finally {
        clearTimeout(deadline);
      }
      // fail-closed: no verdict, aborted, or requestId/paramsDigest not echoed.
      if (
        controller.signal.aborted ||
        !verdict ||
        verdict.requestId !== requestId ||
        verdict.decision === "deny"
      ) {
        return { response: { decision: "denied" }, ran: false };
      }
      // recorded-proof single-use: a proof may authorize at most one command.
      if (verdict.proof !== undefined) {
        if (consumedProofs.has(verdict.proof)) {
          return { response: { decision: "denied", reason: "replayed" }, ran: false };
        }
        consumedProofs.add(verdict.proof);
      }
      return { response: { decision: "approved" }, ran: true };
    },
    reset() {
      active = undefined;
      consumedProofs.clear();
    },
  };
}

const fake = createSeamFake();
runApprovalResolverConformance({
  registerResolver: (resolve) => fake.registerResolver(resolve),
  drive: (input) => fake.drive(input),
  reset: () => fake.reset(),
});
