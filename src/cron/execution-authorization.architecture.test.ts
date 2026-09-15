import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

async function productionTypeScriptFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await productionTypeScriptFiles(absolute)));
    } else if (
      entry.isFile() &&
      entry.name.endsWith(".ts") &&
      !entry.name.includes(".test.") &&
      !entry.name.includes(".fixture.")
    ) {
      files.push(absolute);
    }
  }
  return files;
}

async function findCallSites(pattern: RegExp): Promise<Array<{ file: string; count: number }>> {
  const matches: Array<{ file: string; count: number }> = [];
  for (const file of await productionTypeScriptFiles(SRC_ROOT)) {
    const source = await readFile(file, "utf8");
    const count = [...source.matchAll(pattern)].length;
    if (count > 0) {
      matches.push({ file: path.relative(SRC_ROOT, file), count });
    }
  }
  return matches.toSorted((left, right) => left.file.localeCompare(right.file));
}

describe("cron command authorization architecture", () => {
  it("keeps one native runner adapter behind one authorized admission call", async () => {
    await expect(findCallSites(/\brunCronCommandJob\s*\(/g)).resolves.toEqual([
      { file: "cron/command-runner.ts", count: 1 },
      { file: "gateway/server-cron.ts", count: 1 },
    ]);
    await expect(findCallSites(/\.runCommandJob\s*\(/g)).resolves.toEqual([
      { file: "cron/service/timer-execution.ts", count: 1 },
    ]);

    const admission = await readFile(
      path.join(SRC_ROOT, "cron/service/timer-execution.ts"),
      "utf8",
    );
    const authorize = admission.indexOf(
      "const authorization = await authorizeCronCommandExecution({",
    );
    const commit = admission.indexOf("recordServiceCronRunAuthorization({", authorize);
    const proofRef = admission.indexOf("proofRef: authorization.authorization.proofRef", commit);
    const current = admission.indexOf("options.assertRunCurrent?.()", commit);
    const run = admission.indexOf("state.deps.runCommandJob({", commit);
    expect(authorize).toBeGreaterThan(-1);
    expect(commit).toBeGreaterThan(authorize);
    expect(proofRef).toBeGreaterThan(commit);
    expect(current).toBeGreaterThan(proofRef);
    expect(run).toBeGreaterThan(current);
  });
});
