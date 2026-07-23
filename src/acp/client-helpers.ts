import { randomUUID } from "node:crypto";
/** Permission, environment, and spawn helpers for the standalone ACP client. */
import * as readline from "node:readline";
import type { RequestPermissionRequest, RequestPermissionResponse } from "@agentclientprotocol/sdk";
import {
  normalizeLowercaseStringOrEmpty,
  normalizeOptionalString,
} from "@openclaw/normalization-core/string-coerce";
import { sanitizeTerminalText } from "../../packages/terminal-core/src/safe-text.js";
import {
  materializeWindowsSpawnProgram,
  resolveWindowsSpawnProgram,
} from "../plugin-sdk/windows-spawn.js";
import { hasApprovalResolverForScope } from "../plugins/approval-resolver.js";
import { decideCapabilityApproval } from "../plugins/capability-approval.js";
import {
  classifyEffects,
  digestForEffects,
  SUPERSET_EFFECTS,
} from "../plugins/effect-classifier.js";
import type { ApprovalRequest } from "../plugins/host-hooks.js";
import {
  listKnownProviderAuthEnvVarNames,
  omitEnvKeysCaseInsensitive,
} from "../secrets/provider-env-vars.js";
import { classifyAcpToolApproval, type AcpApprovalClass } from "./approval-classifier.js";
import { pickOwner } from "./resolver-first.js";

type PermissionOption = RequestPermissionRequest["options"][number];

// ACP permission resolution keeps readonly tool classes noninteractive and prompts for risky tools.
type PermissionResolverDeps = {
  prompt?: (toolName: string | undefined, toolTitle?: string) => Promise<boolean>;
  log?: (line: string) => void;
  cwd?: string;
};

function resolveToolKindForPermission(
  toolName: string | undefined,
  approvalClass: AcpApprovalClass,
): string | undefined {
  if (!toolName && approvalClass === "unknown") {
    return undefined;
  }
  if (approvalClass === "readonly_scoped") {
    return "readonly_scoped";
  }
  if (approvalClass === "readonly_search") {
    return "readonly_search";
  }
  return approvalClass;
}

function pickOption(
  options: PermissionOption[],
  kinds: PermissionOption["kind"][],
): PermissionOption | undefined {
  for (const kind of kinds) {
    const match = options.find((option) => option.kind === kind);
    if (match) {
      return match;
    }
  }
  return undefined;
}

function selectedPermission(optionId: string): RequestPermissionResponse {
  return { outcome: { outcome: "selected", optionId } };
}

function cancelledPermission(): RequestPermissionResponse {
  return { outcome: { outcome: "cancelled" } };
}

function promptUserPermission(toolName: string | undefined, toolTitle?: string): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    console.error(`[permission denied] ${toolName ?? "unknown"}: non-interactive terminal`);
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    let settled = false;
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    });

    const finish = (approved: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      rl.close();
      resolve(approved);
    };

    const timeout = setTimeout(() => {
      console.error(`\n[permission timeout] denied: ${toolName ?? "unknown"}`);
      finish(false);
    }, 30_000);

    const label = toolTitle
      ? toolName
        ? `${toolTitle} (${toolName})`
        : toolTitle
      : (toolName ?? "unknown tool");
    rl.question(`\n[permission] Allow "${label}"? (y/N) `, (answer) => {
      const approved = normalizeLowercaseStringOrEmpty(answer) === "y";
      console.error(`[permission ${approved ? "approved" : "denied"}] ${toolName ?? "unknown"}`);
      finish(approved);
    });
  });
}

/** Converts an ACP permission request into a selected allow/reject option or cancellation. */
export async function resolvePermissionRequest(
  params: RequestPermissionRequest,
  deps: PermissionResolverDeps = {},
): Promise<RequestPermissionResponse> {
  const log = deps.log ?? ((line: string) => console.error(line));
  const prompt = deps.prompt ?? promptUserPermission;
  const cwd = deps.cwd ?? process.cwd();
  const options = params.options ?? [];
  const toolTitle = sanitizeTerminalText(params.toolCall?.title ?? "tool");
  const classification = classifyAcpToolApproval({ toolCall: params.toolCall, cwd });
  const toolName = classification.toolName;
  const toolKind = resolveToolKindForPermission(toolName, classification.approvalClass);

  if (options.length === 0) {
    log(`[permission cancelled] ${toolName ?? "unknown"}: no options available`);
    return cancelledPermission();
  }

  const allowOption = pickOption(options, ["allow_once", "allow_always"]);
  const rejectOption = pickOption(options, ["reject_once", "reject_always"]);

  // -------------------------------------------------------------------------
  // L5.4 — Client-mode resolver-first (STRUCTURAL — see note below)
  //
  // Insert resolver-first AFTER allowOption/rejectOption are computed so the
  // same option objects can be returned directly, keeping new code minimal.
  //
  // STRUCTURAL GRADE: in the standalone `openclaw acp client` process the
  // plugin registry is NOT loaded (it lives server-side only), so
  // hasApprovalResolverForScope() returns false and this block is inert —
  // the existing classifyAcpToolApproval + prompt logic runs byte-unchanged.
  //
  // The resolver-first branch only fires when resolvePermissionRequest runs
  // IN a process that has loaded the plugin registry (embedded ACP host or
  // in-process test). It does NOT close the #97152 ACP bypass on its own —
  // that is done by the server-mode adapter in translator.ts (L5.2, Grade A).
  //
  // NO suppressDelivery here — the callback OWNS the response entirely.
  // -------------------------------------------------------------------------
  {
    // Derive the tool name and raw input from the ACP toolCall for classifyEffects.
    // toolName falls back to 'exec' for the gateway exec surface (rawInput may carry
    // name:'exec' but toolName might be undefined if identity is ambiguous).
    const resolverToolName = toolName ?? "exec";
    const rawInput = params.toolCall?.rawInput;

    // FAIL-CLOSED: classifier throw → SUPERSET_EFFECTS (broadest gate, never empty).
    const effects = await classifyEffects("acp", resolverToolName, rawInput, undefined).catch(
      () => SUPERSET_EFFECTS,
    );
    const capability = pickOwner(effects);

    if (hasApprovalResolverForScope(capability)) {
      const req: ApprovalRequest = {
        requestId: randomUUID(),
        capability,
        toolName: resolverToolName,
        effects,
        paramsDigest: digestForEffects(effects),
        ...(params.toolCall?.toolCallId ? { toolCallId: params.toolCall.toolCallId } : {}),
      };

      let verdict: Awaited<ReturnType<typeof decideCapabilityApproval>> | undefined;
      try {
        // Match the promptUserPermission 30 s deadline (client-helpers.ts:90).
        verdict = await decideCapabilityApproval(req, { deadlineMs: 30_000 });
      } catch {
        // Resolver threw unexpectedly — fail-open to existing human prompt.
        verdict = undefined;
      }

      if (verdict?.kind === "allow") {
        // allow → return the allow option (mirrors existing auto-approve path).
        log(`[permission auto-approved-by-resolver] ${resolverToolName} (${capability})`);
        if (allowOption) {
          return selectedPermission(allowOption.optionId);
        }
        // Resolver approved but the request has no allow option — cancel (not error).
        log(`[permission cancelled] ${resolverToolName}: resolver allow but missing allow option`);
        return cancelledPermission();
      }

      if (verdict?.kind === "deny") {
        // deny (clean policy or failure-disposition) → return reject option.
        // NOTE: deny uses selectedPermission(rejectOption), NOT cancelledPermission.
        // This is a POLICY decision, not a protocol failure.
        const reason = "reason" in verdict ? verdict.reason : undefined;
        log(
          `[permission denied-by-resolver] ${resolverToolName} (${capability})${reason ? `: ${reason}` : ""}`,
        );
        if (rejectOption) {
          return selectedPermission(rejectOption.optionId);
        }
        // Resolver denied but the request has no reject option — cancel.
        log(`[permission cancelled] ${resolverToolName}: resolver deny but missing reject option`);
        return cancelledPermission();
      }

      // verdict?.kind === 'fallthrough', undefined (throw), or resolver didn't own
      // this scope — fall through to the existing classifyAcpToolApproval logic.
    }
  }

  const promptRequired = !classification.autoApprove;

  if (!promptRequired) {
    if (!allowOption) {
      log(`[permission cancelled] ${toolName ?? "unknown"}: missing allow option`);
      return cancelledPermission();
    }
    log(`[permission auto-approved] ${toolName} (${toolKind ?? "unknown"})`);
    return selectedPermission(allowOption.optionId);
  }

  log(
    `\n[permission requested] ${toolTitle}${toolName ? ` (${toolName})` : ""}${toolKind ? ` [${toolKind}]` : ""}`,
  );
  const approved = await prompt(toolName, toolTitle);

  if (approved && allowOption) {
    return selectedPermission(allowOption.optionId);
  }
  if (!approved && rejectOption) {
    return selectedPermission(rejectOption.optionId);
  }

  log(
    `[permission cancelled] ${toolName ?? "unknown"}: missing ${approved ? "allow" : "reject"} option`,
  );
  return cancelledPermission();
}

type AcpClientSpawnEnvOptions = {
  stripKeys?: Iterable<string>;
};

/** Builds the sanitized environment used when spawning an ACP client process. */
export function resolveAcpClientSpawnEnv(
  baseEnv: NodeJS.ProcessEnv = process.env,
  options: AcpClientSpawnEnvOptions = {},
): NodeJS.ProcessEnv {
  const env = omitEnvKeysCaseInsensitive(baseEnv, options.stripKeys ?? []);
  env.OPENCLAW_SHELL = "acp-client";
  return env;
}

/** Returns true when the client should hide provider credentials from the spawned server. */
export function shouldStripProviderAuthEnvVarsForAcpServer(
  params: {
    serverCommand?: string;
    serverArgs?: string[];
    defaultServerCommand?: string;
    defaultServerArgs?: string[];
  } = {},
): boolean {
  const serverCommand = normalizeOptionalString(params.serverCommand);
  if (!serverCommand) {
    return true;
  }
  const defaultServerCommand = normalizeOptionalString(params.defaultServerCommand);
  if (!defaultServerCommand || serverCommand !== defaultServerCommand) {
    return false;
  }
  const serverArgs = params.serverArgs ?? [];
  const defaultServerArgs = params.defaultServerArgs ?? [];
  return (
    serverArgs.length === defaultServerArgs.length &&
    serverArgs.every((arg, index) => arg === defaultServerArgs[index])
  );
}

/** Builds the exact environment variable denylist used for ACP client subprocesses. */
export function buildAcpClientStripKeys(params: {
  stripProviderAuthEnvVars?: boolean;
  activeSkillEnvKeys?: Iterable<string>;
}): Set<string> {
  const stripKeys = new Set<string>(params.activeSkillEnvKeys ?? []);
  if (params.stripProviderAuthEnvVars) {
    for (const key of listKnownProviderAuthEnvVarNames()) {
      stripKeys.add(key);
    }
  }
  return stripKeys;
}

type AcpSpawnRuntime = {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  execPath: string;
};

const DEFAULT_ACP_SPAWN_RUNTIME: AcpSpawnRuntime = {
  platform: process.platform,
  env: process.env,
  execPath: process.execPath,
};

/** Resolves the executable/args used to spawn an ACP server, including Windows shims. */
export function resolveAcpClientSpawnInvocation(
  params: { serverCommand: string; serverArgs: string[] },
  runtime: AcpSpawnRuntime = DEFAULT_ACP_SPAWN_RUNTIME,
): { command: string; args: string[]; shell?: boolean; windowsHide?: boolean } {
  const program = resolveWindowsSpawnProgram({
    command: params.serverCommand,
    platform: runtime.platform,
    env: runtime.env,
    execPath: runtime.execPath,
    packageName: "openclaw",
  });
  const resolved = materializeWindowsSpawnProgram(program, params.serverArgs);
  return {
    command: resolved.command,
    args: resolved.argv,
    shell: resolved.shell,
    windowsHide: resolved.windowsHide,
  };
}
