/**
 * Tier-C path/param refiner for fs.write effects (Layer 6, L6.1).
 *
 * Parses process.exec commands to extract target paths written by write-capable
 * shell commands (`touch`, `tee`, `cp`, `mv`, `dd`, `mkdir`, `rm`, `sed -i`,
 * `install`, `>` / `>>` redirection) and native write-tool params (`path`,
 * `file_path`).
 *
 * REFINE/WIDEN-ONLY contract (mirrors net-egress.ts):
 *   - refineWriteFsPaths returns `undefined` when the command is NOT a write
 *     command, and `{paths:['*']}` when the target path is unparseable.
 *   - These functions NEVER remove effects; callers see at least what they had before.
 *   - paths:['*'] means "unknown/any path" and MUST be treated as deny-by-default.
 *     A resolver MUST NEVER treat the literal string '*' as an allowlistable glob.
 *
 * Purity constraints (same as net-egress.ts):
 *   - NO imports from src/agents/embedded-agent-runner/* or src/gateway/*
 *   - NO side effects, no async, no I/O
 */

import { splitShellArgs } from "../../utils/shell-argv.js";

/** Shell interpreters that run a command string passed via a `-c`-family flag. */
const SHELL_WRAPPER_TOKENS = new Set(["bash", "sh", "zsh", "dash", "ash", "ksh"]);

/**
 * Basename of a token: `/bin/touch` → `touch`, `tee` → `tee` (lowercased).
 */
function basename(token: string): string {
  const slash = token.lastIndexOf("/");
  return (slash >= 0 ? token.slice(slash + 1) : token).toLowerCase();
}

/**
 * Tokenize a shell command string or argv array into tokens.
 * Returns null if the string cannot be tokenized or if the input is not
 * a string or array (gracefully handles null/undefined/non-string inputs).
 */
function tokenize(command: string | string[]): string[] | null {
  if (!command && command !== "") return null;
  if (Array.isArray(command)) {
    return command.filter((t) => typeof t === "string" && t.length > 0);
  }
  if (typeof command !== "string") return null;
  return splitShellArgs(command);
}

/**
 * Unwrap shell wrappers so the write tool is visible. Real agents (codex
 * included) dispatch as `/bin/bash -lc '<actual command>'`, hiding the
 * write command behind the `bash` head token. Mirrors the net-egress refiner's
 * unwrapShell with the same depth-limited recursion.
 */
function unwrapShell(argv: string[], depth: number): string[] {
  if (depth <= 0 || argv.length === 0) return argv;
  if (!SHELL_WRAPPER_TOKENS.has(basename(argv[0] ?? ""))) return argv;
  for (let i = 1; i < argv.length; i += 1) {
    const tok = argv[i] ?? "";
    // A `-c`-family flag (`-c`, `-lc`, `-ic`, `-lic`, …) takes the command string next.
    if (tok.startsWith("-") && tok.slice(1).includes("c")) {
      const inner = argv[i + 1];
      if (inner) {
        const innerArgv = tokenize(inner);
        if (innerArgv && innerArgv.length > 0) return unwrapShell(innerArgv, depth - 1);
      }
      return argv;
    }
  }
  return argv;
}

// ---------------------------------------------------------------------------
// Write-command identification
// ---------------------------------------------------------------------------

/**
 * Command basenames (and aliases) that write to, create, move, or delete
 * filesystem paths. `rm` is included (a write/delete to the namespace).
 *
 * Conservatism: over-labeling a command as fs.write is never unsound (deny-
 * by-default), while under-labeling silently allows a write.
 */
const WRITE_HEAD_TOKENS = new Set([
  "touch",
  "tee",
  "cp",
  "mv",
  "dd",
  "mkdir",
  "rm",
  "rmdir",
  "sed",
  "install",
  "ln",
  "truncate",
  "mktemp",
  "rsync",
  // Common write-wrappers agents use
  "write",
  // NOTE: `cat` is NOT in this set. `cat > file` writes via shell redirection,
  // which is detected by extractRedirectTargets before the write-head check runs.
  // Adding `cat` here would make `cat /etc/hosts` (read-only!) emit fs.write.
]);

// ---------------------------------------------------------------------------
// Path extraction helpers
// ---------------------------------------------------------------------------

/**
 * Detect shell redirection operators (`>` / `>>`) in the token list and
 * extract the target paths that follow them.
 *
 * Handles:
 *   - Bare `>` or `>>` — next token is the path
 *   - Combined `>path` or `>>path` (no space)
 *   - fd-prefixed `2>/path` or `2>>/path` (stderr redirect, common pattern)
 *
 * Does NOT support `<<`, `<<<`, `<` (read, not write).
 */
function extractRedirectTargets(argv: string[]): string[] {
  const paths: string[] = [];
  // Regex: optional fd digits, then >> or >, then the path (must be non-empty)
  // Matches: `>path`, `>>path`, `2>path`, `2>>path`, `1>path`, etc.
  const REDIRECT_RE = /^[0-9]*(>>?)(.+)$/;

  for (let i = 0; i < argv.length; i += 1) {
    const tok = argv[i] ?? "";

    // Bare `>` or `>>` or `2>` or `2>>` (no path attached) — next token is the path
    if (/^[0-9]*(>>?)$/.test(tok)) {
      const next = argv[i + 1];
      if (next && !next.startsWith("-")) {
        paths.push(next);
      }
      continue;
    }

    // Combined redirect: `>path`, `>>path`, `2>path`, `2>>path`
    const m = REDIRECT_RE.exec(tok);
    if (m) {
      const candidate = m[2];
      if (candidate && candidate.length > 0) {
        paths.push(candidate);
      }
    }
  }
  return paths;
}

/**
 * Extract target paths from a `touch` / `tee` / `mkdir` / `rm` / `rmdir` /
 * `truncate` / `mktemp` / `sed` / `ln` / `install` / `rsync` invocation.
 *
 * Strategy: skip leading flags (tokens starting with `-`), collect
 * non-flag positional arguments as path candidates.
 *
 * For `cp` and `mv`: the LAST positional argument is the destination.
 * For `dd`: scan for `of=<path>`.
 * For `sed -i`: the LAST positional is the file being edited in-place.
 * For `install`: the LAST positional is the destination.
 * For `rsync`: the LAST positional is the destination.
 * For all others: every positional is a potential write target.
 *
 * Conservative default: return all positionals (may over-include, never
 * under-include) so the resolver sees at least the affected paths.
 *
 * Returns null to signal "this invocation is actually NOT a write" (e.g.,
 * `sed` without `-i` is read-only). Caller must return `undefined` in this case.
 */
function extractPositionalPaths(headBasename: string, argv: string[]): string[] | null {
  // dd: scan for of=<path>
  if (headBasename === "dd") {
    const paths: string[] = [];
    for (const tok of argv) {
      if (tok.startsWith("of=")) {
        const p = tok.slice(3);
        if (p) paths.push(p);
      }
    }
    return paths;
  }

  // Collect positional arguments (skip flags and their option-values)
  const positionals: string[] = [];
  let i = 1; // skip the head command
  while (i < argv.length) {
    const tok = argv[i] ?? "";
    if (tok.startsWith("-")) {
      // Check if this flag is known to consume a next token (short form)
      // Conservative: skip only single-char flags that commonly take a value.
      // We do NOT enumerate exhaustively — miss → over-include all remaining.
      i += 1;
      continue;
    }
    // Stop collecting at shell control operators
    if (tok === "&&" || tok === "||" || tok === ";" || tok === "|") break;
    positionals.push(tok);
    i += 1;
  }

  if (positionals.length === 0) return [];

  // For cp / mv / install / rsync: only the LAST positional is the write target.
  if (
    headBasename === "cp" ||
    headBasename === "mv" ||
    headBasename === "install" ||
    headBasename === "rsync"
  ) {
    const last = positionals[positionals.length - 1];
    return last ? [last] : [];
  }

  // For sed -i: the LAST positional is the in-place file (options + pattern are earlier).
  // sed WITHOUT -i is a read-only transform — signal "not a write" by returning null.
  if (headBasename === "sed") {
    // Only emit if -i was present (in-place edit)
    const inPlace = argv.slice(1).some((t) => t.startsWith("-") && t.includes("i"));
    if (!inPlace) return null; // null = "not a write command" — caller returns undefined
    const last = positionals[positionals.length - 1];
    return last ? [last] : [];
  }

  // For all others (touch, tee, mkdir, rm, rmdir, ln, truncate, mktemp, write, cat):
  // every positional is a target.
  return positionals;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type FsWriteTarget = {
  paths: string[];
};

/**
 * Tier-C refiner: parse a shell command/argv and extract fs.write target paths
 * if the command is a write-capable shell command.
 *
 * Returns:
 *   - A FsWriteTarget with extracted paths if the command is a write command.
 *   - A FsWriteTarget with paths:['*'] if the command looks like a write command
 *     but no concrete path can be extracted (conservative superset).
 *   - `undefined` if the command is NOT a write command (caller adds nothing).
 *
 * REFINE-ONLY: never throws, never returns an empty result for a write command.
 * parse-failure/unknown-path → paths:['*'] (deny-by-default, conservative).
 *
 * @param command - a shell command string or argv array
 */
export function refineWriteFsPaths(command: string | string[]): FsWriteTarget | undefined {
  // Guard non-string/non-array inputs (null, undefined, number, etc.)
  if (command === null || command === undefined) return undefined;
  if (typeof command !== "string" && !Array.isArray(command)) return undefined;

  const rawArgv = tokenize(command);
  if (!rawArgv || rawArgv.length === 0) {
    // Untokenizable or empty — not identified as a write command.
    return undefined;
  }

  // Unwrap `bash -lc '...'` / `sh -c '...'` so write commands hidden behind
  // shell interpreters (the shape real agents emit) are visible.
  const argv = unwrapShell(rawArgv, 3);

  const head = argv[0] ?? "";
  const headBase = basename(head);

  // --- Redirection scan (before write-head check) ---
  // A command like `echo hi > /out` is a write even if the head is `echo`.
  // Also catches `cat > /out`.
  const redirectPaths = extractRedirectTargets(argv);
  if (redirectPaths.length > 0) {
    return { paths: [...new Set(redirectPaths)].sort() };
  }

  // --- Write-head check ---
  if (!WRITE_HEAD_TOKENS.has(headBase)) {
    return undefined;
  }

  // It IS a write command — extract paths.
  const extracted = extractPositionalPaths(headBase, argv);

  // null means "actually not a write invocation" (e.g. sed without -i)
  if (extracted === null) {
    return undefined;
  }

  if (extracted.length === 0) {
    // Write command but no parseable path → conservative superset.
    // paths:['*'] signals "unknown target path" — deny-by-default.
    return { paths: ["*"] };
  }

  return { paths: [...new Set(extracted)].sort() };
}

/**
 * Extract fs.write target paths from a native write-tool params object.
 * Covers tools whose params carry a `path` or `file_path` field.
 *
 * Returns:
 *   - {paths: [path]} if a path field is found and is a non-empty string.
 *   - {paths: ['*']} if the params carry no recognizable path field.
 *
 * NEVER throws.
 */
export function extractNativeWritePaths(params: unknown): FsWriteTarget {
  if (params && typeof params === "object" && !Array.isArray(params)) {
    const p = params as Record<string, unknown>;
    const path =
      typeof p["path"] === "string" && p["path"]
        ? p["path"]
        : typeof p["file_path"] === "string" && p["file_path"]
          ? p["file_path"]
          : undefined;
    if (path) {
      return { paths: [path] };
    }
  }
  return { paths: ["*"] };
}
