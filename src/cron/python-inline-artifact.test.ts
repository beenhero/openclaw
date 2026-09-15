import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCronCommandJob } from "./command-runner.js";
import {
  parsePythonInlineFrame,
  publishPythonInlineArtifact,
  PYTHON_INLINE_BOOTSTRAP_SHA256,
} from "./python-inline-artifact.js";
import type { CronJob } from "./types.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function fixture(source: string) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "openclaw-python-publish-"));
  dirs.push(dir);
  const sourcePath = path.join(dir, "job.py");
  await writeFile(sourcePath, source);
  return { dir, sourcePath };
}

describe("immutable Python artifact publisher", () => {
  it("freezes source bytes and never reopens the display path at runtime", async () => {
    const { dir, sourcePath } = await fixture("print('published-v1')\n");
    const payload = await publishPythonInlineArtifact({
      sourcePath,
      pythonPath: "/usr/bin/python3",
      cwd: dir,
      env: {},
      continuation: {
        kind: "agentTurn",
        on: "command-success",
        instructions: "Summarize the result.",
        input: "stdout",
        inputMaxBytes: 4096,
        inputTrust: "external",
        toolsAllow: [],
      },
    });
    await writeFile(sourcePath, "print('mutated-v2')\n");

    const result = await runCronCommandJob({
      job: {
        id: "python-artifact",
        name: "python artifact",
        enabled: true,
        createdAtMs: 1,
        updatedAtMs: 1,
        schedule: { kind: "every", everyMs: 60_000 },
        sessionTarget: "isolated",
        wakeMode: "now",
        payload,
        state: {},
      } satisfies CronJob,
    });

    expect(result.status).toBe("ok");
    expect(result.outputText?.trim()).toBe("published-v1");
    expect(payload.artifact?.bootstrapSha256).toBe(PYTHON_INLINE_BOOTSTRAP_SHA256);
  });

  it("rejects any frame/source commitment mismatch", async () => {
    const { dir, sourcePath } = await fixture("print('safe')\n");
    const payload = await publishPythonInlineArtifact({
      sourcePath,
      pythonPath: "/usr/bin/python3",
      cwd: dir,
    });
    const frame = JSON.parse(payload.input!);
    frame.sourceSha256 = "0".repeat(64);
    expect(() => parsePythonInlineFrame(JSON.stringify(frame))).toThrow(/digest mismatch/);
  });

  it("rejects NUL-containing source during publication", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "openclaw-python-nul-"));
    dirs.push(dir);
    const sourcePath = path.join(dir, "job.py");
    await writeFile(sourcePath, Buffer.from([112, 114, 105, 110, 116, 40, 49, 41, 0]));

    await expect(
      publishPythonInlineArtifact({
        sourcePath,
        pythonPath: "/usr/bin/python3",
        cwd: dir,
      }),
    ).rejects.toThrow(/NUL/);
  });
});
