/**
 * Multi-process double-consume atomicity test for FileProofLedger (L2.8).
 *
 * Proves that the proper-lockfile advisory lock on proof-index.json closes the
 * cross-process TOCTOU window: across N=8 concurrent child processes racing to
 * consume the SAME {requestId, paramsDigest, proof}, EXACTLY ONE succeeds
 * (ok:true) and the rest get already_consumed or replayed.
 *
 * FALSIFICATION contract (mandatory per L2.8 spec):
 *   With the lock neutered in FileProofLedger (acquireLockSyncWithRetry
 *   commented out) the test MUST observe multiple ok:true results across
 *   processes, proving the lock is load-bearing. See Step 5 in the plan.
 *
 * Usage:
 *   node scripts/run-vitest.mjs test/scripts/proof-ledger-double-consume.test.ts
 */
import { fork, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Helpers matching bench-sqlite-reliability.test.ts patterns
// ---------------------------------------------------------------------------

const WORKER_PATH = fileURLToPath(new URL("./workers/proof-ledger-worker.ts", import.meta.url));

const CHILD_TIMEOUT_MS = 10_000;

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-proof-ledger-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { force: true, recursive: true });
  }
});

type ReadyMessage = { kind: "ready" };
type ResultMessage = { kind: "result"; ok: boolean; reason?: string };
type ChildMessage = ReadyMessage | ResultMessage;

function spawnWorker(): ChildProcess {
  return fork(WORKER_PATH, [], {
    execArgv: ["--import", "tsx"],
    serialization: "json",
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
}

async function waitForChildReady(child: ChildProcess): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(
        new Error(`worker pid=${child.pid} did not send 'ready' within ${CHILD_TIMEOUT_MS}ms`),
      );
    }, CHILD_TIMEOUT_MS);

    const onMessage = (message: unknown) => {
      const m = message as ChildMessage;
      if (m.kind === "ready") {
        cleanup();
        resolve();
      }
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onExit = () => {
      cleanup();
      reject(new Error(`worker pid=${child.pid} exited before ready`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    child.on("message", onMessage);
    child.on("error", onError);
    child.on("exit", onExit);
  });
}

async function waitForChildResult(child: ChildProcess): Promise<ResultMessage> {
  return new Promise<ResultMessage>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(
        new Error(`worker pid=${child.pid} did not send 'result' within ${CHILD_TIMEOUT_MS}ms`),
      );
    }, CHILD_TIMEOUT_MS);

    const onMessage = (message: unknown) => {
      const m = message as ChildMessage;
      if (m.kind === "result") {
        cleanup();
        resolve(m);
      }
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(new Error(`worker pid=${child.pid} exited (code=${String(code)}) before result`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    child.on("message", onMessage);
    child.on("error", onError);
    child.on("exit", onExit);
  });
}

// ---------------------------------------------------------------------------
// One racing round: N children all try to consume the SAME pair simultaneously.
// Returns results array (length N).
// ---------------------------------------------------------------------------

async function runRacingRound(
  dir: string,
  requestId: string,
  paramsDigest: string,
  proof: string,
  n: number,
): Promise<ResultMessage[]> {
  const children: ChildProcess[] = [];
  try {
    // Spawn all children.
    for (let i = 0; i < n; i++) {
      children.push(spawnWorker());
    }

    // Send config to each and wait for all to be ready before firing 'go'.
    await Promise.all(
      children.map(async (child) => {
        child.send({ kind: "config", dir, requestId, paramsDigest, proof });
        await waitForChildReady(child);
      }),
    );

    // Fire 'go' to ALL children simultaneously.
    const resultPromises = children.map((child) => {
      child.send({ kind: "go" });
      return waitForChildResult(child);
    });

    return await Promise.all(resultPromises);
  } finally {
    // Always kill surviving children.
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
      }
    }
  }
}

// ---------------------------------------------------------------------------
// One distinct-pair round: each child gets a UNIQUE {requestId,paramsDigest}.
// All N should succeed.
// ---------------------------------------------------------------------------

async function runDistinctPairRound(
  dir: string,
  baseId: string,
  n: number,
): Promise<ResultMessage[]> {
  const children: ChildProcess[] = [];
  try {
    for (let i = 0; i < n; i++) {
      children.push(spawnWorker());
    }

    // Each child gets a unique pair.
    await Promise.all(
      children.map(async (child, i) => {
        child.send({
          kind: "config",
          dir,
          requestId: `${baseId}-distinct-req-${String(i)}`,
          paramsDigest: `${baseId}-distinct-dig-${String(i)}`,
          proof: `${baseId}-distinct-proof-${String(i)}`,
        });
        await waitForChildReady(child);
      }),
    );

    const resultPromises = children.map((child) => {
      child.send({ kind: "go" });
      return waitForChildResult(child);
    });

    return await Promise.all(resultPromises);
  } finally {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const N_PROCESSES = 8;
const N_ROUNDS = 30;

describe("FileProofLedger cross-process double-consume (L2.8)", () => {
  it(`EXACTLY ONE ok:true across ${N_PROCESSES} concurrent processes over ${N_ROUNDS} rounds`, async () => {
    const dir = makeTempDir();

    for (let round = 0; round < N_ROUNDS; round++) {
      // Fresh pair each round so the previous round's consumed entry does not
      // interfere. We want to observe the RACE for each new pair independently.
      const requestId = `req-round-${String(round)}-${String(Date.now())}`;
      const paramsDigest = `dig-round-${String(round)}`;
      const proof = `proof-round-${String(round)}`;

      const results = await runRacingRound(dir, requestId, paramsDigest, proof, N_PROCESSES);

      const okCount = results.filter((r) => r.ok).length;
      const rejectedCount = results.filter((r) => !r.ok).length;

      // PRIMARY ASSERTION: exactly one process wins per round.
      expect(
        okCount,
        `round=${String(round)}: expected exactly 1 ok:true, got ${String(okCount)}. ` +
          `Results: ${JSON.stringify(results)}`,
      ).toBe(1);

      // ALL rejections must be 'already_consumed' or 'replayed' — never a throw.
      for (const r of results) {
        if (!r.ok) {
          expect(
            r.reason === "already_consumed" || r.reason === "replayed",
            `round=${String(round)}: unexpected rejection reason '${r.reason ?? "undefined"}'`,
          ).toBe(true);
        }
      }

      expect(rejectedCount).toBe(N_PROCESSES - 1);
    }
  }, 60_000); // 30 rounds × 8 children × ~500ms per round worst-case

  it(`distinct-pair control: all ${N_PROCESSES} processes succeed when each has a unique pair`, async () => {
    const dir = makeTempDir();

    // Run 5 distinct-pair rounds to confirm no false already_consumed.
    for (let round = 0; round < 5; round++) {
      const baseId = `base-round-${String(round)}-${String(Date.now())}`;
      const results = await runDistinctPairRound(dir, baseId, N_PROCESSES);

      const okCount = results.filter((r) => r.ok).length;
      expect(
        okCount,
        `distinct-pair round=${String(round)}: expected all ${String(N_PROCESSES)} to succeed, got ${String(okCount)}. ` +
          `Results: ${JSON.stringify(results)}`,
      ).toBe(N_PROCESSES);
    }
  }, 30_000);
});
