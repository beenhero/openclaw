// Codex tests cover the provider-neutral approval-resolver conformance factory.
import type { ApprovalResolver } from "openclaw/plugin-sdk/agent-harness-runtime";
import { InMemoryProofLedger } from "../../../../src/plugins/proof-ledger.js";
import type { ConformanceAuditRecord } from "./approval-resolver-conformance.js";
import { runApprovalResolverConformance } from "./approval-resolver-conformance.js";

// Minimal in-memory seam fake: a single exclusive resolver + a driver that enforces
// request-binding, deadline/disconnect fail-closed, and recorded-proof single-use.
// This mirrors the real seam guarantees (T3-T11) closely enough to exercise every
// core-seam assertion in the factory. A structurally-unsound fake would fail here.
//
// L6.3 upgrade:
//   - drive() now returns { response, ran, requestId } so audit-retrieval cases work.
//   - The fake uses InMemoryProofLedger so getAuditRecord is accurate.
//   - getAuditRecord is wired into the deps so the audit-retrieval conformance cases run.
function createSeamFake() {
  let active: ApprovalResolver | undefined;
  const ledger = new InMemoryProofLedger();
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
    }): Promise<{ response: unknown; ran: boolean; requestId?: string }> {
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

      // fail-closed: aborted or no verdict
      if (controller.signal.aborted || !verdict) {
        return { response: { decision: "denied" }, ran: false, requestId };
      }

      // requestId mismatch — protocol failure (failure deny, NOT clean policy deny)
      if (verdict.requestId !== requestId) {
        return {
          response: { decision: "denied", failureDisposition: "failed" },
          ran: false,
          requestId,
        };
      }

      // clean policy DENY — matching requestId, explicit deny decision (NO failureDisposition)
      if (verdict.decision === "deny") {
        return { response: { decision: "denied" }, ran: false, requestId };
      }

      // malformed decision (not allow/deny) — failure deny
      if (verdict.decision !== "allow") {
        return {
          response: { decision: "denied", failureDisposition: "failed" },
          ran: false,
          requestId,
        };
      }

      // decision === "allow" with matching requestId → single-use check via ledger
      const ledgerResult = ledger.consumeOnce(verdict.proof, requestId, paramsDigest, "allow");
      if (!ledgerResult.ok) {
        return { response: { decision: "denied", reason: "replayed" }, ran: false, requestId };
      }
      return { response: { decision: "approved" }, ran: true, requestId };
    },
    reset() {
      active = undefined;
      ledger.clear();
    },
    getAuditRecord(requestId: string): ConformanceAuditRecord[] {
      return ledger.getAuditRecord(requestId);
    },
  };
}

const fake = createSeamFake();
runApprovalResolverConformance({
  registerResolver: (resolve) => fake.registerResolver(resolve),
  drive: (input) => fake.drive(input),
  reset: () => fake.reset(),
  getAuditRecord: (requestId) => fake.getAuditRecord(requestId),
});
