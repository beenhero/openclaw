import path from "node:path";
// Cron status/list/add command registration and create-payload normalization.
import { parseStrictPositiveInteger } from "@openclaw/normalization-core/number-coercion";
import {
  normalizeLowercaseStringOrEmpty,
  normalizeOptionalString,
} from "@openclaw/normalization-core/string-coerce";
import type { Command } from "commander";
import { theme } from "../../../packages/terminal-core/src/theme.js";
import { publishPythonInlineArtifact } from "../../cron/python-inline-artifact.js";
import { CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES, type CronJob } from "../../cron/types.js";
import { normalizeHttpWebhookUrl } from "../../cron/webhook-url.js";
import { sanitizeAgentId } from "../../routing/session-key.js";
import { defaultRuntime } from "../../runtime.js";
import type { GatewayRpcOpts } from "../gateway-rpc.js";
import { addGatewayClientOptions, callGatewayFromCli } from "../gateway-rpc.js";
import { listCronJobsFromGateway } from "./list-jobs.js";
import { createCronOutputCommand } from "./output-mode.js";
import { registerCronMutationOptions } from "./register.cron-options.js";
import { resolveCronCreateScheduleFromArgs } from "./schedule-options.js";
import {
  coerceCronDeliveryPreviews,
  enrichCronJsonWithStatus,
  handleCronCliError,
  parseCronCommandArgv,
  parseCronCommandEnv,
  parseCronDisclosureList,
  parseCronFallbacks,
  parseCronToolsAllow,
  printCronJson,
  printCronList,
  warnIfCronSchedulerDisabled,
} from "./shared.js";
import { normalizeCronSessionTargetOption, parseCronThreadIdOption } from "./thread-id-shared.js";
import { readCronPayloadScript, readCronTriggerScript } from "./trigger-options.js";

export function registerCronStatusCommand(cron: Command) {
  addGatewayClientOptions(
    createCronOutputCommand(cron, "status")
      .description("Show automations scheduler status")
      .action(async (opts) => {
        try {
          const res = await callGatewayFromCli("cron.status", opts, {});
          printCronJson(res);
        } catch (err) {
          handleCronCliError(err);
        }
      }),
  );
}

export function registerCronListCommand(cron: Command) {
  addGatewayClientOptions(
    cron
      .command("list")
      .description("List automations")
      .option("--all", "Include disabled jobs", false)
      .option("--agent <id>", "Filter by agent id")
      .option("--json", "Output JSON", false)
      .action(async (opts) => {
        try {
          const listParams: { includeDisabled: boolean; agentId?: string } = {
            includeDisabled: Boolean(opts.all),
          };
          const agentId = normalizeOptionalString(opts.agent);
          if (typeof opts.agent === "string" && !agentId) {
            throw new Error("--agent must not be blank");
          }
          if (agentId) {
            listParams.agentId = sanitizeAgentId(agentId);
          }
          const res = await listCronJobsFromGateway(opts, listParams);
          if (opts.json) {
            printCronJson(enrichCronJsonWithStatus(res));
            return;
          }
          const jobs = (res as { jobs?: CronJob[] } | null)?.jobs ?? [];
          const deliveryPreviews = coerceCronDeliveryPreviews(res);
          printCronList(jobs, defaultRuntime, { deliveryPreviews });
        } catch (err) {
          handleCronCliError(err);
        }
      }),
  );
}

export function registerCronAddCommand(cron: Command) {
  addGatewayClientOptions(
    registerCronMutationOptions(
      createCronOutputCommand(cron, "add")
        .description("Add an automation")
        .argument("[scheduleOrName]", "Schedule string, or job name when using --at/--every/--cron")
        .argument("[message]", "Agent message when using a positional schedule"),
      "add",
    )
      .option("--declaration-key <key>", "Idempotent declaration identity key")
      .option("--disabled", "Create job disabled", false)
      .action(
        async (
          nameArg: string | undefined,
          messageArg: string | undefined,
          opts: GatewayRpcOpts & Record<string, unknown>,
          cmd: Command,
        ) => {
          try {
            if (opts.clearContinuation) {
              throw new Error("--clear-continuation is only valid for cron edit.");
            }
            const hasScheduleFlag =
              typeof opts.at === "string" ||
              typeof opts.cron === "string" ||
              typeof opts.every === "string" ||
              typeof opts.onExit === "string" ||
              typeof opts.streamCommand === "string";
            const positionalSchedule = hasScheduleFlag ? undefined : nameArg;
            const schedule = resolveCronCreateScheduleFromArgs({ ...opts, positionalSchedule });

            const wakeMode = normalizeOptionalString(opts.wake) ?? "now";
            if (wakeMode !== "now" && wakeMode !== "next-heartbeat") {
              throw new Error("--wake must be now or next-heartbeat");
            }

            const rawAgentId = normalizeOptionalString(opts.agent);
            const agentId = rawAgentId ? sanitizeAgentId(rawAgentId) : undefined;

            const hasAnnounce = Boolean(opts.announce) || opts.deliver === true;
            const hasNoDeliver = opts.deliver === false;
            const webhookUrl =
              typeof opts.webhook === "string" ? normalizeHttpWebhookUrl(opts.webhook) : null;
            if (typeof opts.webhook === "string" && !webhookUrl) {
              throw new Error("--webhook must be a valid http(s) URL");
            }
            const hasWebhook = Boolean(webhookUrl);
            const deliveryFlagCount = [hasAnnounce, hasNoDeliver, hasWebhook].filter(
              Boolean,
            ).length;
            if (deliveryFlagCount > 1) {
              throw new Error("Choose at most one of --announce, --no-deliver, or --webhook");
            }

            const payload = (() => {
              // Main-session jobs use system events; isolated/current/session jobs use messages.
              const systemEvent = normalizeOptionalString(opts.systemEvent) ?? "";
              const optionMessage = normalizeOptionalString(opts.message);
              const positionalMessage = normalizeOptionalString(messageArg);
              const commandShell = normalizeOptionalString(opts.command);
              const commandArgv = parseCronCommandArgv(opts.commandArgv);
              const pythonFile = normalizeOptionalString(opts.pythonFile);
              const scriptPath = normalizeOptionalString(opts.script);
              const toolsAllow = parseCronToolsAllow(opts.tools);
              const hasCommandPayload = Boolean(commandShell || commandArgv || pythonFile);
              const hasCommandOnlyOption =
                opts.pythonBin !== undefined ||
                opts.pythonArg !== undefined ||
                opts.commandCwd !== undefined ||
                opts.commandEnv !== undefined ||
                opts.commandEnvMode !== undefined ||
                opts.commandInput !== undefined ||
                opts.noOutputTimeoutSeconds !== undefined ||
                typeof opts.outputTimeoutSeconds === "string" ||
                typeof opts.outputTimeoutSeconds === "number" ||
                opts.outputMaxBytes !== undefined ||
                opts.continueMessage !== undefined ||
                opts.continueInputMaxBytes !== undefined ||
                opts.continueTools !== undefined ||
                opts.continueModel !== undefined ||
                opts.consequenceSummary !== undefined ||
                opts.filesystemDisclosure !== undefined ||
                opts.networkDisclosure !== undefined ||
                opts.dependencyDisclosure !== undefined;
              if (optionMessage && positionalMessage && optionMessage !== positionalMessage) {
                throw new Error(
                  "Pass the automation message either positionally or with --message, not both.",
                );
              }
              const message = optionMessage ?? positionalMessage ?? "";
              if (
                [Boolean(commandShell), Boolean(commandArgv), Boolean(pythonFile)].filter(Boolean)
                  .length > 1
              ) {
                throw new Error(
                  "Pass command payload with exactly one of --command, --command-argv, or --python-file.",
                );
              }
              if (!hasCommandPayload && hasCommandOnlyOption) {
                throw new Error(
                  "Command-specific options require --command, --command-argv, or --python-file.",
                );
              }
              const chosen = [
                Boolean(systemEvent),
                Boolean(message),
                hasCommandPayload,
                Boolean(scriptPath),
              ].filter(Boolean).length;
              if (chosen !== 1) {
                throw new Error(
                  "Choose exactly one payload: --system-event, --message, --command/--python-file, or --script",
                );
              }
              if (systemEvent) {
                return {
                  kind: "systemEvent" as const,
                  text: systemEvent,
                  ...(toolsAllow ? { toolsAllow } : {}),
                };
              }
              if (scriptPath) {
                if (opts.timeoutSeconds !== undefined) {
                  throw new Error(
                    "Use --script-timeout-seconds for script jobs, not --timeout-seconds.",
                  );
                }
                const scriptTimeoutSeconds = parseStrictPositiveInteger(opts.scriptTimeoutSeconds);
                if (opts.scriptTimeoutSeconds !== undefined && scriptTimeoutSeconds === undefined) {
                  throw new Error("Invalid --script-timeout-seconds (must be a positive integer).");
                }
                const scriptToolBudget = parseStrictPositiveInteger(opts.scriptToolBudget);
                if (opts.scriptToolBudget !== undefined && scriptToolBudget === undefined) {
                  throw new Error("Invalid --script-tool-budget (must be a positive integer).");
                }
                return {
                  kind: "script" as const,
                  scriptPath,
                  timeoutSeconds: scriptTimeoutSeconds,
                  toolBudget: scriptToolBudget,
                  toolsAllow,
                };
              }
              const timeoutSeconds = parseStrictPositiveInteger(opts.timeoutSeconds);
              if (opts.timeoutSeconds !== undefined && timeoutSeconds === undefined) {
                throw new Error("Invalid --timeout-seconds (must be a positive integer).");
              }
              if (commandShell || commandArgv || pythonFile) {
                const rawNoOutputTimeoutSeconds =
                  opts.noOutputTimeoutSeconds ??
                  (typeof opts.outputTimeoutSeconds === "string" ||
                  typeof opts.outputTimeoutSeconds === "number"
                    ? opts.outputTimeoutSeconds
                    : undefined);
                const noOutputTimeoutSeconds =
                  parseStrictPositiveInteger(rawNoOutputTimeoutSeconds);
                if (
                  rawNoOutputTimeoutSeconds !== undefined &&
                  noOutputTimeoutSeconds === undefined
                ) {
                  throw new Error(
                    "Invalid --no-output-timeout-seconds (must be a positive integer).",
                  );
                }
                const outputMaxBytes = parseStrictPositiveInteger(opts.outputMaxBytes);
                if (opts.outputMaxBytes !== undefined && outputMaxBytes === undefined) {
                  throw new Error("Invalid --output-max-bytes (must be a positive integer).");
                }
                const continuationInstructions = normalizeOptionalString(opts.continueMessage);
                const hasContinuationOption =
                  opts.continueMessage !== undefined ||
                  opts.continueInputMaxBytes !== undefined ||
                  opts.continueTools !== undefined ||
                  opts.continueModel !== undefined;
                if (hasContinuationOption && !continuationInstructions) {
                  throw new Error(
                    "--continue-message must be non-blank when using continuation options.",
                  );
                }
                const continuationInputMaxBytes =
                  parseStrictPositiveInteger(opts.continueInputMaxBytes) ?? 256 * 1024;
                if (
                  opts.continueInputMaxBytes !== undefined &&
                  parseStrictPositiveInteger(opts.continueInputMaxBytes) === undefined
                ) {
                  throw new Error(
                    "Invalid --continue-input-max-bytes (must be a positive integer).",
                  );
                }
                if (continuationInputMaxBytes > CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES) {
                  throw new Error(
                    `--continue-input-max-bytes must not exceed ${CRON_COMMAND_CONTINUATION_MAX_INPUT_BYTES}.`,
                  );
                }
                const continuationModel = normalizeOptionalString(opts.continueModel);
                const continuation = continuationInstructions
                  ? {
                      kind: "agentTurn" as const,
                      on: "command-success" as const,
                      instructions: continuationInstructions,
                      input: "stdout" as const,
                      inputMaxBytes: continuationInputMaxBytes,
                      inputTrust: "external" as const,
                      toolsAllow: parseCronToolsAllow(opts.continueTools) ?? [],
                      ...(continuationModel ? { model: continuationModel } : {}),
                    }
                  : undefined;
                const consequenceSummary = normalizeOptionalString(opts.consequenceSummary);
                const hasConsequenceOption =
                  opts.consequenceSummary !== undefined ||
                  opts.filesystemDisclosure !== undefined ||
                  opts.networkDisclosure !== undefined ||
                  opts.dependencyDisclosure !== undefined;
                if (hasConsequenceOption && !consequenceSummary) {
                  throw new Error(
                    "--consequence-summary must be non-blank when using consequence disclosures.",
                  );
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
                        disclosures: parseCronDisclosureList(
                          opts.networkDisclosure,
                          "--network-disclosure",
                        ),
                      },
                      dependencies: parseCronDisclosureList(
                        opts.dependencyDisclosure,
                        "--dependency-disclosure",
                      ),
                    }
                  : undefined;
                const envMode = normalizeLowercaseStringOrEmpty(opts.commandEnvMode) || "inherit";
                if (envMode !== "inherit" && envMode !== "replace") {
                  throw new Error("--command-env-mode must be inherit or replace.");
                }
                if (pythonFile) {
                  const pythonPath = normalizeOptionalString(opts.pythonBin);
                  if (!pythonPath || !path.isAbsolute(pythonPath)) {
                    throw new Error("--python-bin must be an absolute path with --python-file.");
                  }
                  if (opts.commandInput !== undefined) {
                    throw new Error("--command-input cannot be combined with --python-file.");
                  }
                  if (opts.commandEnvMode !== undefined && envMode !== "replace") {
                    throw new Error("--python-file requires --command-env-mode replace.");
                  }
                  const explicitEnv = parseCronCommandEnv(opts.commandEnv);
                  return {
                    kind: "pythonArtifact" as const,
                    sourcePath: path.resolve(pythonFile),
                    pythonPath,
                    cwd: path.resolve(normalizeOptionalString(opts.commandCwd) ?? process.cwd()),
                    env: {
                      ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
                      ...(process.env.PATH ? { PATH: process.env.PATH } : {}),
                      ...(process.env.LANG ? { LANG: process.env.LANG } : {}),
                      ...explicitEnv,
                    },
                    scriptArgv: Array.isArray(opts.pythonArg)
                      ? opts.pythonArg.filter((item): item is string => typeof item === "string")
                      : [],
                    timeoutSeconds,
                    noOutputTimeoutSeconds,
                    outputMaxBytes,
                    continuation,
                    consequences,
                  };
                }
                return {
                  kind: "command" as const,
                  argv: commandArgv ?? ["sh", "-lc", commandShell ?? ""],
                  cwd: normalizeOptionalString(opts.commandCwd),
                  env: parseCronCommandEnv(opts.commandEnv),
                  envMode,
                  input: typeof opts.commandInput === "string" ? opts.commandInput : undefined,
                  timeoutSeconds,
                  noOutputTimeoutSeconds,
                  outputMaxBytes,
                  continuation,
                  consequences,
                  ...(toolsAllow ? { toolsAllow } : {}),
                };
              }
              return {
                kind: "agentTurn" as const,
                message,
                model: normalizeOptionalString(opts.model),
                fallbacks: parseCronFallbacks(opts.fallbacks),
                thinking: normalizeOptionalString(opts.thinking),
                timeoutSeconds,
                lightContext: opts.lightContext === true ? true : undefined,
                toolsAllow,
              };
            })();
            const resolvedPayload = await (async () => {
              if (payload.kind === "pythonArtifact") {
                const { kind: _kind, ...publish } = payload;
                return await publishPythonInlineArtifact(publish);
              }
              if (payload.kind !== "script") {
                return payload;
              }
              const { scriptPath, ...scriptPayload } = payload;
              return {
                ...scriptPayload,
                script: await readCronPayloadScript(scriptPath),
              };
            })();

            const sessionSource = cmd.getOptionValueSource("session");
            const sessionTargetRaw = normalizeOptionalString(opts.session) ?? "";
            const inferredSessionTarget =
              resolvedPayload.kind === "agentTurn" ||
              resolvedPayload.kind === "command" ||
              resolvedPayload.kind === "script"
                ? "isolated"
                : "main";
            const sessionTarget =
              sessionSource === "cli"
                ? normalizeCronSessionTargetOption(sessionTargetRaw) || ""
                : inferredSessionTarget;
            const isCustomSessionTarget =
              normalizeLowercaseStringOrEmpty(sessionTarget).startsWith("session:") &&
              Boolean(normalizeOptionalString(sessionTarget.slice(8)));
            const isIsolatedLikeSessionTarget =
              sessionTarget === "isolated" || sessionTarget === "current" || isCustomSessionTarget;
            if (sessionTarget !== "main" && !isIsolatedLikeSessionTarget) {
              throw new Error("--session must be main, isolated, current, or session:<id>");
            }

            if (opts.deleteAfterRun && opts.keepAfterRun) {
              throw new Error("Choose --delete-after-run or --keep-after-run, not both");
            }

            if (
              sessionTarget === "main" &&
              resolvedPayload.kind !== "systemEvent" &&
              resolvedPayload.kind !== "script"
            ) {
              throw new Error("Main jobs require --system-event or --script.");
            }
            if (
              resolvedPayload.kind === "script" &&
              sessionTarget !== "main" &&
              sessionTarget !== "isolated"
            ) {
              throw new Error("Script jobs require --session main or --session isolated.");
            }
            if (
              isIsolatedLikeSessionTarget &&
              resolvedPayload.kind !== "agentTurn" &&
              resolvedPayload.kind !== "command" &&
              resolvedPayload.kind !== "script"
            ) {
              throw new Error("Isolated jobs require --message, --command, or --script.");
            }
            if (
              (opts.announce || typeof opts.deliver === "boolean") &&
              (!isIsolatedLikeSessionTarget ||
                (resolvedPayload.kind !== "agentTurn" &&
                  resolvedPayload.kind !== "command" &&
                  resolvedPayload.kind !== "script"))
            ) {
              throw new Error(
                "--announce/--no-deliver require a non-main agentTurn, command, or script session target.",
              );
            }

            const accountId = normalizeOptionalString(opts.account);
            const threadId = parseCronThreadIdOption(opts.threadId);
            const hasThreadId = typeof threadId === "number";
            const hasChatDeliveryTarget =
              cmd.getOptionValueSource("channel") === "cli" ||
              typeof opts.to === "string" ||
              Boolean(accountId) ||
              hasThreadId;

            if (
              hasChatDeliveryTarget &&
              (!isIsolatedLikeSessionTarget ||
                (resolvedPayload.kind !== "agentTurn" &&
                  resolvedPayload.kind !== "command" &&
                  resolvedPayload.kind !== "script"))
            ) {
              throw new Error(
                "--channel, --to, --account, and --thread-id require a non-main agentTurn, command, or script job with delivery.",
              );
            }
            if (hasWebhook && hasChatDeliveryTarget) {
              throw new Error("--webhook cannot be combined with chat delivery options.");
            }

            const deliveryMode = hasWebhook
              ? "webhook"
              : isIsolatedLikeSessionTarget &&
                  (resolvedPayload.kind === "agentTurn" ||
                    resolvedPayload.kind === "command" ||
                    resolvedPayload.kind === "script")
                ? hasAnnounce
                  ? "announce"
                  : hasNoDeliver
                    ? "none"
                    : "announce"
                : undefined;

            const optionName = normalizeOptionalString(opts.name);
            const positionalName = hasScheduleFlag ? normalizeOptionalString(nameArg) : undefined;
            if (optionName && positionalName && optionName !== positionalName) {
              throw new Error(
                "Pass the automation name either positionally or with --name, not both.",
              );
            }
            const name = optionName ?? positionalName ?? "";
            if (!name) {
              throw new Error("Cron job name is required. Pass a name or --name <name>.");
            }

            const description = normalizeOptionalString(opts.description);
            const declarationKey = normalizeOptionalString(opts.declarationKey);
            if (typeof opts.declarationKey === "string" && !declarationKey) {
              throw new Error("--declaration-key must not be blank");
            }
            const displayName = normalizeOptionalString(opts.displayName);
            if (typeof opts.displayName === "string" && !displayName) {
              throw new Error("--display-name must not be blank");
            }
            const pacingMin = normalizeOptionalString(opts.pacingMin);
            const pacingMax = normalizeOptionalString(opts.pacingMax);
            if (typeof opts.pacingMin === "string" && !pacingMin) {
              throw new Error("--pacing-min must not be blank");
            }
            if (typeof opts.pacingMax === "string" && !pacingMax) {
              throw new Error("--pacing-max must not be blank");
            }

            const sessionKey = normalizeOptionalString(opts.sessionKey);
            const triggerScriptPath = normalizeOptionalString(opts.triggerScript);
            if ((opts.triggerOnce || opts.triggerScript !== undefined) && !triggerScriptPath) {
              throw new Error(
                `--trigger-${opts.triggerOnce ? "once requires --trigger-script" : "script must not be blank"}`,
              );
            }
            const trigger = triggerScriptPath && {
              script: await readCronTriggerScript(triggerScriptPath),
              ...(opts.triggerOnce ? { once: true } : {}),
            };

            if (
              (resolvedPayload.kind === "agentTurn" || resolvedPayload.kind === "script") &&
              !agentId
            ) {
              defaultRuntime.error(
                theme.warn(
                  "No --agent specified; the job will run with the configured default agent. " +
                    "Specify --agent to choose a specific agent, or set agents.defaults.systemAgent.agentId.",
                ),
              );
            }

            const params = {
              name,
              declarationKey,
              displayName,
              description,
              ...(declarationKey && cmd.getOptionValueSource("disabled") !== "cli"
                ? {}
                : { enabled: !opts.disabled }),
              deleteAfterRun: opts.deleteAfterRun ? true : opts.keepAfterRun ? false : undefined,
              agentId,
              sessionKey,
              schedule,
              ...(pacingMin || pacingMax
                ? {
                    pacing: {
                      ...(pacingMin ? { min: pacingMin } : {}),
                      ...(pacingMax ? { max: pacingMax } : {}),
                    },
                  }
                : {}),
              trigger,
              sessionTarget,
              wakeMode,
              payload: resolvedPayload,
              delivery: deliveryMode
                ? {
                    mode: deliveryMode,
                    channel: hasWebhook ? undefined : normalizeOptionalString(opts.channel),
                    to: hasWebhook ? webhookUrl : normalizeOptionalString(opts.to),
                    threadId: hasWebhook ? undefined : threadId,
                    accountId: hasWebhook ? undefined : accountId,
                    bestEffort: opts.bestEffortDeliver ? true : undefined,
                  }
                : undefined,
            };

            const res = await callGatewayFromCli("cron.add", opts, params);
            printCronJson(res);
            await warnIfCronSchedulerDisabled(opts);
          } catch (err) {
            handleCronCliError(err);
          }
        },
      ),
  );
}
