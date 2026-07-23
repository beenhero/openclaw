---
summary: "Full capability approval-resolver seam: contract, fail-closed matrix, per-leg grade table, honest coverage"
title: "Capability approval-resolver seam"
read_when:
  - You are building a resolver plugin (Sigil, AgentPass) and need the full seam contract
  - You need to understand what is live-confirmed vs structural for the approval seam
  - You are auditing the #97152 cross-harness coverage claims
  - You are extending the seam to a new capability or harness
---

This page documents the **full capability approval-resolver seam** — the
cross-harness, by-effect decision primitive that closes openclaw#97152.
It covers the contract, fail-closed matrix, honest per-leg coverage grades,
deliberate divergences from #97152, and open residuals. For the Codex-specific
wiring, see [Codex harness runtime](/plugins/codex-harness-runtime).

## What the seam does

`registerApprovalResolver(...)` lets a bundled or explicitly-enabled plugin
become the **authoritative, exclusive decision owner** for a scoped native
capability. Registered resolvers sit upstream of every other approval path
(human tap, trusted-tool-policy): when a resolver owns a capability and an
in-scope request arrives, the resolver decides, and no other path runs.

The seam realizes the three #97152 properties:

- **Completeness** — cross-harness coverage (codex, native, ACP) × by-effect
  (process.exec, net.egress, fs.write), driven by a sound effect classifier.
- **Authority** — exclusive routing: one resolver per capability; competing
  `/approve` taps, trusted-policy chains, and ACP `request_permission` are
  bypassed for in-scope requests.
- **Integrity** — decisions bound to `{requestId, paramsDigest}`; a durable,
  flock'd proof ledger enforces single-use and cross-request replay rejection;
  consumed decisions are retained as non-repudiable audit records queryable by
  `requestId`.

## Contract

```ts
type ApprovalCapability = string; // open; wired: "process.exec" | "net.egress" | "fs.write"

type EffectDescriptor =
  | { kind: "process.exec"; command?: string; cwd?: string; argv?: string[] }
  | { kind: "net.egress"; hosts: string[]; ports?: number[]; url?: string }
  | { kind: "fs.write"; paths: string[] }
  | { kind: string; [key: string]: unknown }; // future capabilities

interface ApprovalRequest {
  requestId: string; // opaque seam-minted id
  capability: ApprovalCapability; // the capability being gated
  toolName: string; // hint only, never authoritative
  effects: readonly EffectDescriptor[]; // classified effect set (non-empty by invariant)
  paramsDigest: string; // "sha256:" + digestForEffects(effects)
  agentId?: string;
  sessionKey?: string;
  runId?: string;
  toolCallId?: string;
  subject?: string;
  origin?: string;
  expiresAt?: number;
}

interface ApprovalDecision {
  requestId: string; // MUST echo the seam-minted requestId
  decision: "allow" | "deny";
  reason?: string;
  proof?: string; // OPAQUE — core records/enforces, never parses
}

type ApprovalResolver = (
  req: ApprovalRequest,
  opts: { signal: AbortSignal; deadlineMs: number },
) => Promise<ApprovalDecision>;

function registerApprovalResolver(
  resolver: ApprovalResolver,
  options: {
    scope: { capabilities: ApprovalCapability[] };
    exclusive: true;
  },
): { dispose(): void };
```

Registration hard-throws on any capability not in `KNOWN_CAPABILITIES`
(`"process.exec"`, `"net.egress"`, `"fs.write"`). This is fail-closed: a
resolver cannot silently believe it gates a surface OpenClaw does not yet enforce.

## Fail-closed matrix

Every non-`allow` path — including no-decision, timeout, mismatch, throw, and
replay — declines the operation. There is no "no decision means allow" branch.

| Resolver outcome                                                | Seam disposition                                                                |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `{ decision: "allow" }` with matching `requestId` + fresh proof | allow → operation proceeds                                                      |
| `{ decision: "deny" }` with matching `requestId`                | **clean policy deny** — no `failureDisposition`; caller surfaces graceful block |
| resolver throws                                                 | failure deny — `failureDisposition: "failed"`                                   |
| resolver Promise never resolves within `deadlineMs`             | failure deny — `failureDisposition: "timed_out"`                                |
| returned `requestId` does not echo the parked request           | failure deny — `failureDisposition: "failed"`                                   |
| `decision` value is neither `"allow"` nor `"deny"`              | failure deny — `failureDisposition: "failed"`                                   |
| proof already consumed / replayed onto a second request         | failure deny — `failureDisposition: "failed"`                                   |
| ledger unavailable (corrupt/locked/I-O error)                   | failure deny — `failureDisposition: "failed"`                                   |
| no resolver owns the capability                                 | fallthrough — existing path (human tap / trusted-policy) unchanged              |

The **clean-vs-failure deny distinction** matters for UX: a clean policy deny
(resolver explicitly returned `"deny"`) surfaces as a graceful block (mirroring
a codex curl-deny); a failure deny surfaces as an unavailability error. The
conformance suite asserts both: `failureDisposition` must be **absent** on a
clean deny and present on a failure deny.

## Effect classifier

`classifyEffects(harness, toolName, params)` returns a `readonly EffectDescriptor[]`
(non-empty by a soundness invariant — classifier never returns `[]`).

Three tiers:

- **Tier-A** — harness-native discriminator: hardcoded tool-name → effect table
  (`EXEC_CAPABLE_TOOL_NAMES`, `NET_EGRESS_TOOL_NAMES`).
- **Tier-B** — declarative metadata: `registerToolMetadata(..., { capabilities })`
  for custom plugin tools.
- **Tier-C** — argv/param refiner: curl/wget argv → `net.egress` hosts+ports;
  write-command argv → `fs.write` paths.

**Core soundness invariant**: an unparseable operation classifies to the
**superset** `[process.exec (unparseable), net.egress (hosts:['*'])]`, never
`[]`. This keeps the pipeline fail-closed-but-live: the operation is prompted
under the broadest owner, not silently allowed.

**`hosts: ['*']` and `paths: ['*']` are deny-by-default markers.** These
literal strings mean "unknown/any". A resolver must NEVER treat `'*'` as an
allowlistable pattern. Deny or prompt the user.

**Multi-effect commands** (e.g. `curl` = `process.exec` + `net.egress`;
`tee /f` = `process.exec` + `fs.write`) produce a multi-element `effects[]`.
The seam mints ONE `requestId` and ONE `paramsDigest` over the **whole effect
set**, and dispatches a SINGLE resolver call — no double-prompt.

## Proof ledger — single-use + audit retention

The proof ledger (`ProofLedger`) has two responsibilities that are explicitly
separate:

- **consume** (single-use / replay gate) — `consumeOnce(proof, requestId,
paramsDigest, outcome)`: atomic under a proper-lockfile advisory lock; a
  `{requestId, paramsDigest}` pair can be consumed at most once; a proof
  string already seen on any prior request is rejected as a replay.
- **retain** (audit retrieval) — `getAuditRecord(requestId)` returns the
  retained `ProofAuditRecord` for that requestId. The record carries
  `requestId`, `paramsDigest`, `outcome`, and `consumedAt`. It does **NOT**
  carry the raw proof (secret-at-rest invariant).

The `FileProofLedger` is durable across process restarts and uses
`acquireLockSyncWithRetry` (the same advisory-lock pattern as auth-storage.ts)
for cross-process lost-update safety. The index is committed first (atomic
temp+fsync+rename), then the audit line appended — so a consumed proof is
always durable even if the audit-line write crashes.

## Exclusivity — two mechanisms

The seam uses **two** exclusivity mechanisms, not one:

1. **Upstream-ordering** (codex + native): the resolver decision is taken
   before the human `/approve` tap or trusted-policy chain is reached. No
   `suppressDelivery` needed — the competing surface is never dispatched.
   This is the mechanism for the codex and native harnesses, and is
   live-confirmed for codex/process.exec.

2. **`suppressDelivery`** (ACP): the ACP `request_permission` event is a
   genuinely-parallel surface (multiple subscribers). The server-mode ACP
   adapter decides before the event is emitted and suppresses its delivery
   when a resolver denies or allows. The client-mode adapter decides inside
   the `onPermissionRequest` callback, which pre-empts the ACP client tap.

## Deliberate divergences from openclaw#97152

These divergences are intentional and documented openly.

1. **`scope` narrowed to `{capabilities: string[]}` + hard-throw-unknown.**
   The #97152 sketch allowed a `tools.*` wildcard scope. This seam uses
   capability strings only and hard-throws on any capability not in
   `KNOWN_CAPABILITIES`. More fail-closed and more by-effect-faithful.

2. **Exclusivity = two mechanisms** (upstream-ordering + `suppressDelivery`),
   not a single `suppressDelivery` everywhere. Codex and native exclusivity is
   structural (ordering), not flag-based.

3. **Approver-identity is provider-delivered** via the opaque `proof` field.
   Core records, retains, and enforces structural single-use/replay on the
   proof — it never parses or cryptographically validates it. Identity
   verification is provider-internal (AgentPass, Sigil sign-and-return).

4. **`paramsDigest` is computed over `effects[]`**, not raw tool params.
   `digestForEffects(effects)` is byte-identical to the legacy single-effect
   digest for current traffic (all single-effect), but switches to a sorted-
   array digest for multi-effect commands (re-approval required on capability
   set change).

5. **Proof ledger is durable + flock'd from the start.** The #97152 sketch
   implied in-memory replay-safety. This seam delivers cross-process
   lost-update safety at the same time as the seam itself.

## Operator-tap exclusivity residual

The ACP-client bypass is closed (server-mode: decide before `request_permission`
emit; client-mode: decide inside `onPermissionRequest` callback). However, the
**operator APPROVALS_SCOPE tap exclusivity** is ordering-based.

In the current implementation, the resolver runs first; if it allows/denies,
the human tap never fires. Exclusivity depends on the invariant that the
resolver's decision always lands before the tap is dispatched — which holds for
the Codex and native seams where the resolver runs at a single ordered point.
For parallel tap surfaces (ACP, future surfaces), `suppressDelivery` is the
correct mechanism and is wired for ACP server-mode.

**The residual**: for the ACP client-mode path, exclusivity depends on the
`onPermissionRequest` callback running synchronously before any concurrent tap
processes the same request. This is architecturally sound given the ACP
client-mode dispatch model, but is not separately live-drilled as an
exclusivity proof — it is structural. State this plainly to integrators:
ACP client-mode exclusivity is **integration-confirmed**, not live-drilled.

## Codex-executed harness-shell boundary

This seam gates codex-exec via the **codex app-server bridge** and native/ACP
via their adapters. It does NOT change the fact that a **codex-executed shell**
(a bash command run by Codex natively, not through the app-server approval
bridge) ignores a native `before_tool_call` block.

That is a separate, open harness-enforcement gap: openclaw#97152's remaining
piece. Codex-executed shell commands that bypass the app-server bridge (e.g.
Codex running `bash` internally rather than as an approval-escalated exec) are
not gated by this seam. Do not claim this seam closes that gap — it does not.

## Per-leg grade table

Honest coverage grades per harness × capability. "LIVE" means deny blocks the
real effect and allow permits it on a live system with a real resolver receiving
the effect-tagged request.

| Harness × Capability                              | Grade                                                    | Evidence                                                                                                                                                                                                                                                                 |
| ------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| codex × process.exec                              | **LIVE**                                                 | OAuth drill on real Codex 0.144.6: deny blocked an auto-run exec, allow ran it; resolver saw `{requestId, effects:[{kind:"process.exec",...}], paramsDigest}`                                                                                                            |
| codex × net.egress (curl)                         | **LIVE**                                                 | OAuth drill: deny blocked a real `curl` command; resolver saw `net.egress` effect with extracted hosts                                                                                                                                                                   |
| codex × fs.write (write cmds)                     | classified (Tier-C) + rides the live-confirmed exec seam | Tier-C refines `touch /f`, `tee`, `cp`, `>` redirection to `fs.write paths`; the exec gate is live-confirmed; the `fs.write` effect label itself is not separately live-drilled — a write command arrives as process.exec + fs.write but the gate fires on the exec seam |
| native × net.egress (web_fetch)                   | **LIVE-enforced in-harness**                             | Block honored via the front-stage `decideCapabilityApproval` short-circuit in `runBeforeToolCallHook`; network mocked in tests — enforcement path is live, egress network call is simulated                                                                              |
| native × process.exec (OpenClaw-owned exec tools) | **LIVE-enforced in-harness**                             | Same front-stage wrapper; confirmed via integration test with real `decideCapabilityApproval` calling the real resolver                                                                                                                                                  |
| native × fs.write                                 | classified; no dedicated native write tool               | OpenClaw has no dedicated native write tool; file writes go through the exec `command` tool (process.exec), refined by Tier-C to add `fs.write` effect. The write label is classified; the gate fires on the exec seam                                                   |
| ACP server-mode (#97152 ACP-client bypass)        | **CLOSED, integration-confirmed**                        | Real ACP-server translator + mock connection: `requestPermission` is bypassed when a resolver denies; `resolveGatewayApproval` carries the resolver decision. Two-terminal stdio drill is available but was not run for this seam delivery                               |
| ACP client-mode                                   | **STRUCTURAL**                                           | `onPermissionRequest` callback wired; callback fires before the ACP client tap. Inert without a server-side registry; activates only in an embedded ACP host. Not live-drilled                                                                                           |
| Durable proof/audit ledger                        | **LIVE + concurrency falsification-proven**              | 8-process concurrent double-consume test with `FileProofLedger`: lock proven load-bearing (removing it causes the second consume to succeed, breaking single-use invariant)                                                                                              |
| Classifier soundness (never [])                   | **adversarially verified**                               | Fuzzing with unparseable/spoofed toolNames confirms `assertSuperset` floor returns the conservative superset, not `[]`; the empty-`[]` path is structurally unreachable after the floor                                                                                  |
| Audit retrieval (getAuditRecord)                  | **implemented + tested**                                 | `InMemoryProofLedger.getAuditRecord` and `FileProofLedger.getAuditRecord` tested by the parametrized ledger suite; the conformance factory test runs the audit-retrieval case end-to-end                                                                                 |

## Conformance suite

`approval-resolver-conformance.ts` is the provider-neutral conformance suite.
Any resolver implementation (Sigil, AgentPass) runs it to prove conformance.
It asserts, provider-neutrally:

- The full fail-closed matrix (deny on: no-decision, requestId mismatch,
  timeout, replay/double-consume, malformed decision value).
- Clean policy deny has **no** `failureDisposition`; failure denies carry it.
- Single-use via the durable ledger (a proof consumed once; re-consume denied).
- `getAuditRecord` retrievability — after a consume, the record is queryable by
  `requestId`, carries NO raw proof. This case runs only when the provider
  supplies `deps.getAuditRecord`.
- Effect-set / capability tagging (`effects[]` is non-empty; `effects[i].kind`
  matches `capability`).
- A **fail-open self-test**: a deliberately fail-open resolver seam (one that
  always runs the command regardless of verdict) FAILS the suite's deny/block
  cases. This confirms the suite actually detects non-conformance — the suite
  does not merely pass any implementation that happens to return the right type.

## Related

- [Codex harness runtime](/plugins/codex-harness) — Codex-specific wiring, version floor, exclusive-over-scope detail
- [Plugin hooks](/plugins/hooks) — `before_tool_call` hook that the native front-stage wraps
- [Agent harness plugins](/plugins/sdk-agent-harness) — `registerApprovalResolver` API surface
- [Plugin permission requests](/plugins/plugin-permission-requests) — the plugin approval flow that ACP elicitations route through
