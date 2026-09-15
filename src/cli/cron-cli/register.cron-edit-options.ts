import path from "node:path";
import { parseStrictPositiveInteger } from "@openclaw/normalization-core/number-coercion";
import {
  normalizeOptionalLowercaseString,
  normalizeOptionalString,
} from "@openclaw/normalization-core/string-coerce";
import { publishPythonInlineArtifact } from "../../cron/python-inline-artifact.js";
import { isSystemMonitorDeclaration } from "../../cron/system-owned-declaration.js";
import {
  CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES,
  type CronJob,
  isSystemOwnedCronPayloadKind,
} from "../../cron/types.js";
import {
  parseCronCommandArgv,
  parseCronCommandEnv,
  parseCronDisclosureList,
  parseCronFallbacks,
  parseCronToolsAllow,
} from "./shared.js";
import { parseCronThreadIdOption } from "./thread-id-shared.js";
import { readCronPayloadScript } from "./trigger-options.js";

const assignIf = (
  target: Record<string, unknown>,
  key: string,
  value: unknown,
  shouldAssign: boolean,
) => {
  if (shouldAssign) {
    target[key] = value;
  }
};

export async function resolveCronEditPayloadDeliveryPatch(
  opts: Record<string, unknown>,
  loadExistingJob: () => Promise<CronJob>,
  webhookUrl: string | undefined,
  commandCwd: string | undefined,
): Promise<Record<string, unknown>> {
  const patch: Record<string, unknown> = {};
  const hasSystemEventPatch = typeof opts.systemEvent === "string";
  const scriptPath = normalizeOptionalString(opts.script);
  const commandShell = normalizeOptionalString(opts.command);
  const commandArgv = parseCronCommandArgv(opts.commandArgv);
  const pythonFile = normalizeOptionalString(opts.pythonFile);
  if (!pythonFile && (opts.pythonBin !== undefined || opts.pythonArg !== undefined)) {
    throw new Error("--python-bin and --python-arg require --python-file.");
  }
  if (
    [Boolean(commandShell), Boolean(commandArgv), Boolean(pythonFile)].filter(Boolean).length > 1
  ) {
    throw new Error(
      "Pass command payload with exactly one of --command, --command-argv, or --python-file.",
    );
  }
  // Raw flag presence owns the set/clear mutex even when normalization omits a blank value.
  const hasModel = typeof opts.model === "string";
  const model = normalizeOptionalString(opts.model);
  if (hasModel && opts.clearModel) {
    throw new Error("Use --model or --clear-model, not both");
  }
  const hasThinking = typeof opts.thinking === "string";
  const thinking = normalizeOptionalString(opts.thinking);
  if (hasThinking && opts.clearThinking) {
    throw new Error("Use --thinking or --clear-thinking, not both");
  }
  const fallbacks = parseCronFallbacks(opts.fallbacks);
  if (typeof opts.fallbacks === "string" && opts.clearFallbacks) {
    throw new Error("Use --fallbacks or --clear-fallbacks, not both");
  }
  const toolsAllow = parseCronToolsAllow(opts.tools);
  const timeoutSecondsValue = opts.timeoutSeconds;
  const rawTimeoutSeconds =
    timeoutSecondsValue === undefined
      ? undefined
      : typeof timeoutSecondsValue === "string" || typeof timeoutSecondsValue === "number"
        ? String(timeoutSecondsValue).trim()
        : "";
  if (rawTimeoutSeconds !== undefined && !/^\d+$/u.test(rawTimeoutSeconds)) {
    throw new Error("Invalid --timeout-seconds (must be a positive integer).");
  }
  const timeoutSeconds = rawTimeoutSeconds === undefined ? undefined : Number(rawTimeoutSeconds);
  const hasTimeoutSeconds =
    typeof timeoutSeconds === "number" &&
    Number.isSafeInteger(timeoutSeconds) &&
    timeoutSeconds > 0;
  if (rawTimeoutSeconds !== undefined && !hasTimeoutSeconds) {
    throw new Error("Invalid --timeout-seconds (must be a positive integer).");
  }
  const rawNoOutputTimeoutSeconds =
    opts.noOutputTimeoutSeconds ??
    (typeof opts.outputTimeoutSeconds === "string" || typeof opts.outputTimeoutSeconds === "number"
      ? opts.outputTimeoutSeconds
      : undefined);
  const noOutputTimeoutSeconds = parseStrictPositiveInteger(rawNoOutputTimeoutSeconds);
  if (rawNoOutputTimeoutSeconds !== undefined && noOutputTimeoutSeconds === undefined) {
    throw new Error("Invalid --no-output-timeout-seconds (must be a positive integer).");
  }
  const outputMaxBytes = parseStrictPositiveInteger(opts.outputMaxBytes);
  if (opts.outputMaxBytes !== undefined && outputMaxBytes === undefined) {
    throw new Error("Invalid --output-max-bytes (must be a positive integer).");
  }
  const continuationInstructions = normalizeOptionalString(opts.continueMessage);
  const continuationModel = normalizeOptionalString(opts.continueModel);
  const continuationInputMaxBytes =
    parseStrictPositiveInteger(opts.continueInputMaxBytes) ?? 256 * 1024;
  if (
    opts.continueInputMaxBytes !== undefined &&
    parseStrictPositiveInteger(opts.continueInputMaxBytes) === undefined
  ) {
    throw new Error("Invalid --continue-input-max-bytes (must be a positive integer).");
  }
  if (continuationInputMaxBytes > CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES) {
    throw new Error(
      `--continue-input-max-bytes must not exceed ${CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES}.`,
    );
  }
  const hasContinuationOption =
    opts.continueMessage !== undefined ||
    opts.continueInputMaxBytes !== undefined ||
    opts.continueTools !== undefined ||
    opts.continueModel !== undefined;
  const hasContinuationField = hasContinuationOption || Boolean(opts.clearContinuation);
  if (opts.clearContinuation && hasContinuationOption) {
    throw new Error("Use --clear-continuation or continuation options, not both.");
  }
  if (hasContinuationField && !opts.clearContinuation && !continuationInstructions) {
    throw new Error("--continue-message must be non-blank when using continuation options.");
  }
  const commandEnvMode = normalizeOptionalLowercaseString(opts.commandEnvMode);
  if (
    opts.commandEnvMode !== undefined &&
    commandEnvMode !== "inherit" &&
    commandEnvMode !== "replace"
  ) {
    throw new Error("--command-env-mode must be inherit or replace.");
  }
  const consequenceSummary = normalizeOptionalString(opts.consequenceSummary);
  const hasConsequenceOption =
    opts.consequenceSummary !== undefined ||
    opts.filesystemDisclosure !== undefined ||
    opts.networkDisclosure !== undefined ||
    opts.dependencyDisclosure !== undefined;
  if (hasConsequenceOption && !consequenceSummary) {
    throw new Error("--consequence-summary must be non-blank when using consequence disclosures.");
  }
  const consequences = consequenceSummary
    ? {
        summary: consequenceSummary,
        filesystem: {
          access: "ambient-host-user" as const,
          disclosures: parseCronDisclosureList(
            opts.filesystemDisclosure,
            "--filesystem-disclosure",
          ),
        },
        network: {
          access: "ambient-host-user" as const,
          disclosures: parseCronDisclosureList(opts.networkDisclosure, "--network-disclosure"),
        },
        dependencies: parseCronDisclosureList(opts.dependencyDisclosure, "--dependency-disclosure"),
      }
    : undefined;
  const scriptTimeoutSeconds = parseStrictPositiveInteger(opts.scriptTimeoutSeconds);
  if (opts.scriptTimeoutSeconds !== undefined && scriptTimeoutSeconds === undefined) {
    throw new Error("Invalid --script-timeout-seconds (must be a positive integer).");
  }
  const scriptToolBudget = parseStrictPositiveInteger(opts.scriptToolBudget);
  if (opts.scriptToolBudget !== undefined && scriptToolBudget === undefined) {
    throw new Error("Invalid --script-tool-budget (must be a positive integer).");
  }

  const hasWebhookDelivery = Boolean(webhookUrl);
  const hasDeliveryModeFlag =
    opts.announce || typeof opts.deliver === "boolean" || hasWebhookDelivery;
  const threadId = parseCronThreadIdOption(opts.threadId);
  const hasDeliveryThreadId = typeof threadId === "number";
  const hasDeliveryTarget =
    typeof opts.channel === "string" ||
    typeof opts.to === "string" ||
    hasDeliveryThreadId ||
    Boolean(opts.clearChannel) ||
    Boolean(opts.clearTo) ||
    Boolean(opts.clearThreadId);
  const hasDeliveryAccount = typeof opts.account === "string" || Boolean(opts.clearAccount);
  const hasBestEffort = typeof opts.bestEffortDeliver === "boolean";
  if (hasWebhookDelivery && (hasDeliveryTarget || hasDeliveryAccount)) {
    throw new Error("--webhook cannot be combined with chat delivery options.");
  }
  if (typeof opts.channel === "string" && opts.clearChannel) {
    throw new Error("Use --channel or --clear-channel, not both");
  }
  if (typeof opts.to === "string" && opts.clearTo) {
    throw new Error("Use --to or --clear-to, not both");
  }
  if (hasDeliveryThreadId && opts.clearThreadId) {
    throw new Error("Use --thread-id or --clear-thread-id, not both");
  }
  if (typeof opts.account === "string" && opts.clearAccount) {
    throw new Error("Use --account or --clear-account, not both");
  }

  // Unlike cwd, command stdin intentionally accepts empty and whitespace strings.
  const hasCommandInput = typeof opts.commandInput === "string";
  const hasCommandSpecificPayloadField =
    Boolean(commandShell) ||
    Boolean(commandArgv) ||
    Boolean(pythonFile) ||
    Boolean(commandCwd) ||
    hasCommandInput ||
    opts.commandEnv !== undefined ||
    opts.commandEnvMode !== undefined ||
    hasContinuationField ||
    hasConsequenceOption ||
    noOutputTimeoutSeconds !== undefined ||
    outputMaxBytes !== undefined;
  const hasToolsAllowPatch =
    typeof opts.tools === "string" || Array.isArray(opts.tools) || Boolean(opts.clearTools);
  const hasAgentTurnSpecificPayloadField =
    typeof opts.message === "string" ||
    Boolean(model) ||
    Boolean(opts.clearModel) ||
    typeof opts.fallbacks === "string" ||
    Boolean(opts.clearFallbacks) ||
    Boolean(thinking) ||
    Boolean(opts.clearThinking) ||
    typeof opts.lightContext === "boolean";
  const hasScriptSpecificPayloadField =
    Boolean(scriptPath) || scriptTimeoutSeconds !== undefined || scriptToolBudget !== undefined;
  if (hasTimeoutSeconds && hasScriptSpecificPayloadField) {
    throw new Error("Use --script-timeout-seconds for script jobs, not --timeout-seconds.");
  }
  if (hasTimeoutSeconds && hasSystemEventPatch) {
    throw new Error("--timeout-seconds is not supported for systemEvent jobs.");
  }
  let timeoutOnlyPayloadKind: "agentTurn" | "command" | undefined;
  if (hasTimeoutSeconds && !hasCommandSpecificPayloadField && !hasAgentTurnSpecificPayloadField) {
    const existingJob = await loadExistingJob();
    const existingKind = existingJob.payload.kind;
    if (existingKind === "script") {
      throw new Error("Use --script-timeout-seconds for script jobs, not --timeout-seconds.");
    }
    if (
      existingKind === "systemEvent" ||
      isSystemOwnedCronPayloadKind(existingKind) ||
      isSystemMonitorDeclaration(existingJob.declarationKey)
    ) {
      throw new Error(`--timeout-seconds is not supported for ${existingKind} jobs.`);
    }
    timeoutOnlyPayloadKind = existingKind;
  }
  let toolsOnlyPayloadKind: CronJob["payload"]["kind"] | undefined;
  if (
    hasToolsAllowPatch &&
    !hasSystemEventPatch &&
    !hasAgentTurnSpecificPayloadField &&
    !hasCommandSpecificPayloadField &&
    !hasScriptSpecificPayloadField &&
    !hasTimeoutSeconds
  ) {
    // Tool grants are shared by every payload kind; a policy-only edit must
    // preserve the stored execution kind instead of creating an agent turn.
    const existingJob = await loadExistingJob();
    if (isSystemMonitorDeclaration(existingJob.declarationKey)) {
      throw new Error("System-owned cron jobs cannot be edited by cron clients.");
    }
    toolsOnlyPayloadKind = existingJob.payload.kind;
  }
  const hasAgentTurnPayloadField =
    hasAgentTurnSpecificPayloadField ||
    timeoutOnlyPayloadKind === "agentTurn" ||
    (hasToolsAllowPatch && toolsOnlyPayloadKind === "agentTurn");
  const hasCommandPayloadField =
    hasCommandSpecificPayloadField ||
    timeoutOnlyPayloadKind === "command" ||
    toolsOnlyPayloadKind === "command";
  const hasAgentTurnPatch = hasAgentTurnPayloadField;
  const hasCommandPatch = hasCommandPayloadField;
  const hasScriptPatch = hasScriptSpecificPayloadField || toolsOnlyPayloadKind === "script";
  const hasSystemEventOrToolsPatch = hasSystemEventPatch || toolsOnlyPayloadKind === "systemEvent";
  if (
    [hasSystemEventOrToolsPatch, hasAgentTurnPatch, hasCommandPatch, hasScriptPatch].filter(Boolean)
      .length > 1
  ) {
    throw new Error("Choose at most one payload change");
  }

  const assignToolsAllowPatch = (payload: Record<string, unknown>): void => {
    if (opts.clearTools) {
      // Clearing a restriction means an explicit unrestricted grant. Persisting
      // a wildcard avoids creating a new capless legacy job at the upgrade boundary.
      payload.toolsAllow = ["*"];
    } else if (toolsAllow) {
      payload.toolsAllow = toolsAllow;
    }
  };

  if (hasSystemEventOrToolsPatch) {
    const payload: Record<string, unknown> = { kind: "systemEvent" };
    assignIf(payload, "text", String(opts.systemEvent), hasSystemEventPatch);
    assignToolsAllowPatch(payload);
    patch.payload = payload;
  } else if (hasAgentTurnPatch) {
    const payload: Record<string, unknown> = { kind: "agentTurn" };
    assignIf(payload, "message", String(opts.message), typeof opts.message === "string");
    if (opts.clearModel) {
      payload.model = null;
    } else {
      assignIf(payload, "model", model, Boolean(model));
    }
    assignIf(payload, "fallbacks", fallbacks, typeof opts.fallbacks === "string");
    assignIf(payload, "fallbacks", null, Boolean(opts.clearFallbacks));
    if (opts.clearThinking) {
      payload.thinking = null;
    } else {
      assignIf(payload, "thinking", thinking, Boolean(thinking));
    }
    assignIf(payload, "timeoutSeconds", timeoutSeconds, hasTimeoutSeconds);
    assignIf(payload, "lightContext", opts.lightContext, typeof opts.lightContext === "boolean");
    assignToolsAllowPatch(payload);
    patch.payload = payload;
  } else if (hasCommandPatch) {
    if (pythonFile) {
      const pythonPath = normalizeOptionalString(opts.pythonBin);
      if (!pythonPath || !path.isAbsolute(pythonPath)) {
        throw new Error("--python-bin must be an absolute path with --python-file.");
      }
      if (hasCommandInput) {
        throw new Error("--command-input cannot be combined with --python-file.");
      }
      if (opts.commandEnvMode !== undefined && commandEnvMode !== "replace") {
        throw new Error("--python-file requires --command-env-mode replace.");
      }
      // Force an optimistic config-revision read before doing local publication.
      await loadExistingJob();
      const published = await publishPythonInlineArtifact({
        sourcePath: path.resolve(pythonFile),
        pythonPath,
        cwd: path.resolve(commandCwd ?? process.cwd()),
        env: {
          ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
          ...(process.env.PATH ? { PATH: process.env.PATH } : {}),
          ...(process.env.LANG ? { LANG: process.env.LANG } : {}),
          ...parseCronCommandEnv(opts.commandEnv),
        },
        scriptArgv: Array.isArray(opts.pythonArg)
          ? opts.pythonArg.filter((item): item is string => typeof item === "string")
          : [],
        ...(hasTimeoutSeconds ? { timeoutSeconds } : {}),
        ...(noOutputTimeoutSeconds !== undefined ? { noOutputTimeoutSeconds } : {}),
        ...(outputMaxBytes !== undefined ? { outputMaxBytes } : {}),
        ...(continuationInstructions
          ? {
              continuation: {
                kind: "agentTurn",
                on: "command-success",
                instructions: continuationInstructions,
                input: "stdout",
                inputMaxBytes: continuationInputMaxBytes,
                inputTrust: "external",
                toolsAllow: parseCronToolsAllow(opts.continueTools) ?? [],
                ...(continuationModel ? { model: continuationModel } : {}),
              },
            }
          : {}),
        ...(consequences ? { consequences } : {}),
      });
      patch.payload = opts.clearContinuation ? { ...published, continuation: null } : published;
    } else {
      const payload: Record<string, unknown> = { kind: "command" };
      assignIf(payload, "argv", commandArgv, Boolean(commandArgv));
      assignIf(payload, "argv", ["sh", "-lc", commandShell], Boolean(commandShell));
      assignIf(payload, "cwd", commandCwd, Boolean(commandCwd));
      assignIf(payload, "env", parseCronCommandEnv(opts.commandEnv), opts.commandEnv !== undefined);
      assignIf(payload, "envMode", commandEnvMode, opts.commandEnvMode !== undefined);
      assignIf(payload, "input", opts.commandInput, hasCommandInput);
      assignIf(payload, "timeoutSeconds", timeoutSeconds, hasTimeoutSeconds);
      assignIf(
        payload,
        "noOutputTimeoutSeconds",
        noOutputTimeoutSeconds,
        noOutputTimeoutSeconds !== undefined,
      );
      assignIf(payload, "outputMaxBytes", outputMaxBytes, outputMaxBytes !== undefined);
      if (opts.clearContinuation) {
        payload.continuation = null;
      } else if (continuationInstructions) {
        payload.continuation = {
          kind: "agentTurn",
          on: "command-success",
          instructions: continuationInstructions,
          input: "stdout",
          inputMaxBytes: continuationInputMaxBytes,
          inputTrust: "external",
          toolsAllow: parseCronToolsAllow(opts.continueTools) ?? [],
          ...(continuationModel ? { model: continuationModel } : {}),
        };
      }
      if (consequences) {
        payload.consequences = consequences;
      }
      assignToolsAllowPatch(payload);
      patch.payload = payload;
    }
  } else if (hasScriptPatch) {
    const payload: Record<string, unknown> = { kind: "script" };
    if (scriptPath) {
      payload.script = await readCronPayloadScript(scriptPath);
    }
    assignIf(payload, "timeoutSeconds", scriptTimeoutSeconds, scriptTimeoutSeconds !== undefined);
    assignIf(payload, "toolBudget", scriptToolBudget, scriptToolBudget !== undefined);
    assignToolsAllowPatch(payload);
    patch.payload = payload;
  }

  if (hasDeliveryModeFlag || hasDeliveryTarget || hasDeliveryAccount || hasBestEffort) {
    const delivery: Record<string, unknown> = {};
    if (hasDeliveryModeFlag) {
      delivery.mode = hasWebhookDelivery
        ? "webhook"
        : opts.announce || opts.deliver === true
          ? "announce"
          : "none";
    } else if (opts.bestEffortDeliver === true) {
      // Back-compat: enabling best-effort historically implied announce mode.
      delivery.mode = "announce";
    }
    if (opts.clearChannel) {
      delivery.channel = null;
    } else if (typeof opts.channel === "string") {
      const channel = opts.channel.trim();
      delivery.channel = channel ? channel : undefined;
    }
    if (hasWebhookDelivery) {
      delivery.to = webhookUrl;
    } else if (opts.clearTo) {
      delivery.to = null;
    } else if (typeof opts.to === "string") {
      const to = opts.to.trim();
      delivery.to = to ? to : undefined;
    }
    if (opts.clearThreadId) {
      delivery.threadId = null;
    } else if (hasDeliveryThreadId) {
      delivery.threadId = threadId;
    }
    if (opts.clearAccount) {
      delivery.accountId = null;
    } else if (typeof opts.account === "string") {
      const account = opts.account.trim();
      delivery.accountId = account ? account : undefined;
    }
    if (typeof opts.bestEffortDeliver === "boolean") {
      delivery.bestEffort = opts.bestEffortDeliver;
    }
    patch.delivery = delivery;
  }

  return patch;
}
