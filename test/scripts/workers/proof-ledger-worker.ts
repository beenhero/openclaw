/**
 * Child worker for proof-ledger-double-consume.test.ts.
 *
 * Protocol (all messages are JSON via IPC):
 *   Parent → Child  {kind:'config', dir, requestId, paramsDigest, proof}
 *   Child  → Parent {kind:'ready'}
 *   Parent → Child  {kind:'go'}
 *   Child  → Parent {kind:'result', ok, reason?}
 *
 * The worker creates its own FileProofLedger over the shared dir, waits for
 * the 'go' signal, then calls consumeOnce and sends the result back.
 */
import { FileProofLedger } from "../../../src/plugins/proof-ledger.js";

type ConfigMessage = {
  kind: "config";
  dir: string;
  requestId: string;
  paramsDigest: string;
  proof: string;
};

type GoMessage = {
  kind: "go";
};

type InboundMessage = ConfigMessage | GoMessage;

type ResultMessage = {
  kind: "result";
  ok: boolean;
  reason?: string;
};

type ReadyMessage = {
  kind: "ready";
};

type OutboundMessage = ReadyMessage | ResultMessage;

function send(msg: OutboundMessage): void {
  if (process.send) {
    process.send(msg);
  }
}

let ledger: FileProofLedger | null = null;
let config: ConfigMessage | null = null;

process.on("message", (msg: unknown) => {
  const m = msg as InboundMessage;

  if (m.kind === "config") {
    config = m;
    // Eagerly construct the ledger so file creation happens before 'go'.
    ledger = new FileProofLedger(m.dir);
    send({ kind: "ready" });
    return;
  }

  if (m.kind === "go") {
    if (!config || !ledger) {
      send({ kind: "result", ok: false, reason: "not_configured" });
      process.exit(1);
      return;
    }
    try {
      const result = ledger.consumeOnce(
        config.proof,
        config.requestId,
        config.paramsDigest,
        "allow",
      );
      if (result.ok) {
        send({ kind: "result", ok: true });
      } else {
        send({ kind: "result", ok: false, reason: result.reason });
      }
    } catch (err) {
      send({ kind: "result", ok: false, reason: `threw:${String(err)}` });
    }
    return;
  }
});
