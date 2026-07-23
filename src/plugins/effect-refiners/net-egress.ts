/**
 * Tier-C host argv/param refiner for net.egress effects (Layer 3, L3.7).
 *
 * Parses process.exec commands and web_fetch params to extract precise host/port
 * information for net.egress EffectDescriptors.
 *
 * REFINE/WIDEN-ONLY contract:
 *   - refineCurlNetEgress returns `undefined` (no effect change) if the command
 *     is not a fetch tool, and {hosts:['*']} if the URL is unparseable.
 *   - extractWebFetchEgress returns {hosts:['*']} for unparseable URLs, never throws.
 *   - These functions NEVER remove effects; callers see at least what they had before.
 *
 * Purity constraints (same as effect-classifier.ts):
 *   - NO imports from src/agents/embedded-agent-runner/* or src/gateway/*
 *   - NO side effects, no async, no I/O
 */

import { splitShellArgs } from "../../utils/shell-argv.js";

/** Head tokens that identify fetch-capable commands. */
const FETCH_HEAD_TOKENS = new Set(["curl", "wget", "http", "https"]);

/** Parsed net.egress target info from a curl/wget/http command. */
export type NetEgressTarget = {
  hosts: string[];
  ports: number[];
  url?: string;
};

/**
 * Extract the scheme-default port for a URL protocol.
 * Returns 443 for https, 80 for http, 0 for unknown.
 */
function defaultPortForScheme(protocol: string): number {
  if (protocol === "https:") return 443;
  if (protocol === "http:") return 80;
  return 0;
}

/**
 * Parse a single URL string into host+port. Returns undefined if unparseable.
 * host is lowercased and port-stripped (port goes into ports[]).
 */
function parseUrl(rawUrl: string): { host: string; port: number; url: string } | undefined {
  try {
    const u = new URL(rawUrl);
    const host = u.hostname.toLowerCase();
    if (!host) return undefined;
    const explicitPort = u.port ? parseInt(u.port, 10) : undefined;
    const port = explicitPort ?? defaultPortForScheme(u.protocol);
    return { host, port, url: rawUrl };
  } catch {
    return undefined;
  }
}

/**
 * Tokenize a shell command string or argv array into tokens.
 * Returns null if the string cannot be tokenized (unterminated quotes, etc.).
 */
function tokenize(command: string | string[]): string[] | null {
  if (Array.isArray(command)) {
    // Already tokenized — filter out empty strings
    return command.filter((t) => t.length > 0);
  }
  return splitShellArgs(command);
}

/**
 * Extract URLs from a curl/wget argv token list.
 *
 * Handles:
 *   - Bare http(s):// tokens
 *   - --url <x> flag
 *
 * Returns an array of parsed targets (host+port+url).
 */
function extractUrlsFromArgv(argv: string[]): { host: string; port: number; url: string }[] {
  const results: { host: string; port: number; url: string }[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token) continue;
    // --url <next-token>
    if (token === "--url" && i + 1 < argv.length) {
      const next = argv[i + 1];
      if (next) {
        const parsed = parseUrl(next);
        if (parsed) results.push(parsed);
        i += 1; // consume the next token
      }
      continue;
    }
    // Bare http:// or https:// token
    if (token.startsWith("http://") || token.startsWith("https://")) {
      const parsed = parseUrl(token);
      if (parsed) results.push(parsed);
    }
  }
  return results;
}

/**
 * Tier-C refiner: parse a shell command/argv and extract net.egress target info
 * if the command is a curl/wget/http fetch.
 *
 * Returns:
 *   - A NetEgressTarget with extracted hosts+ports if the command is a fetch tool.
 *   - A NetEgressTarget with hosts:['*'] if the command looks like a fetch tool
 *     but no parseable URL is found (conservative superset).
 *   - `undefined` if the command is NOT a fetch tool (caller adds nothing).
 *
 * REFINE-ONLY: never throws, never returns an empty result for a fetch command.
 */
export function refineCurlNetEgress(command: string | string[]): NetEgressTarget | undefined {
  const argv = tokenize(command);
  if (!argv || argv.length === 0) {
    // Untokenizable or empty — not identified as a fetch tool, return undefined.
    // The process.exec floor already covers this.
    return undefined;
  }

  // Check head token (argv[0]) — is this a fetch-capable command?
  const head = argv[0]?.toLowerCase();
  if (!head || !FETCH_HEAD_TOKENS.has(head)) {
    return undefined;
  }

  // It IS a fetch tool. Extract URLs from the argv.
  const targets = extractUrlsFromArgv(argv.slice(1));

  if (targets.length === 0) {
    // Fetch tool but no parseable URL → conservative superset for this fetch.
    // hosts:['*'] signals "unknown target host" — deny-by-default.
    return { hosts: ["*"], ports: [] };
  }

  const hosts = [...new Set(targets.map((t) => t.host))].sort();
  const ports = [...new Set(targets.map((t) => t.port).filter((p) => p > 0))].sort((a, b) => a - b);
  const url = targets.length === 1 ? targets[0]?.url : undefined;

  return { hosts, ports, url };
}

/**
 * Extract net.egress target info from a web_fetch params.url string.
 * Used in Tier-C for the L4 web_fetch path (structural in L3, live in L4).
 *
 * Returns:
 *   - {hosts, ports, url} extracted from the URL if parseable.
 *   - {hosts:['*']} if the URL is missing or unparseable (conservative superset).
 *
 * NEVER throws.
 */
export function extractWebFetchEgress(url: string | null | undefined): NetEgressTarget {
  if (!url || typeof url !== "string") {
    return { hosts: ["*"], ports: [] };
  }
  const parsed = parseUrl(url);
  if (!parsed) {
    return { hosts: ["*"], ports: [] };
  }
  return {
    hosts: [parsed.host],
    ports: parsed.port > 0 ? [parsed.port] : [],
    url: parsed.url,
  };
}
