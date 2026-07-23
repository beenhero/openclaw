/**
 * Tests ACP tool approval classification and spoofing backstops.
 *
 * GOLDEN SNAPSHOT (L3.12): The corpus below is EXHAUSTIVE over every entry in
 * the three ACP discriminator sets:
 *   EXEC_CAPABLE_TOOL_IDS  — exec, spawn, shell, bash, process, code_execution, nodes
 *   SAFE_SEARCH_TOOL_IDS   — search, web_search, memory_search
 *   CONTROL_PLANE_TOOL_IDS — cron, gateway, sessions_spawn, sessions_send, session_status
 * plus interactive/other/unknown/CWD-scoped examples.
 *
 * The golden snapshot must be BYTE-IDENTICAL before and after the fold that
 * derives exec/net classification from the shared core classifyEffectsSync table.
 * If any corpus input's class changes, that is a behavior regression.
 */
import { vi, describe, expect, it, beforeEach, afterEach } from "vitest";
import { classifyAcpToolApproval } from "./approval-classifier.js";

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

function classify(params: {
  title: string;
  locations?: Array<{ path: string; line?: number }>;
  rawInput?: Record<string, unknown>;
  meta?: Record<string, unknown>;
  cwd?: string;
}) {
  return classifyAcpToolApproval({
    cwd: params.cwd ?? "/workspace",
    toolCall: {
      title: params.title,
      locations: params.locations,
      rawInput: params.rawInput,
      _meta: params.meta,
    },
  });
}

// ---------------------------------------------------------------------------
// Original tests (preserved exactly)
// ---------------------------------------------------------------------------

describe("classifyAcpToolApproval", () => {
  it("auto-approves scoped readonly reads", () => {
    expect(
      classify({
        title: "read: src/index.ts",
        rawInput: { path: "src/index.ts" },
      }),
    ).toEqual({
      toolName: "read",
      approvalClass: "readonly_scoped",
      autoApprove: true,
    });
  });

  it("does not auto-approve reads outside cwd", () => {
    expect(
      classify({
        title: "read: ~/.ssh/id_rsa",
        rawInput: { path: "~/.ssh/id_rsa" },
      }),
    ).toEqual({
      toolName: "read",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("does not auto-approve reads from locations-only metadata", () => {
    expect(
      classify({
        title: "read",
        locations: [{ path: "src/index.ts" }],
      }),
    ).toEqual({
      toolName: "read",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("auto-approves readonly search tools", () => {
    expect(
      classify({
        title: "memory_search: vectors",
        rawInput: { name: "memory_search", query: "vectors" },
      }),
    ).toEqual({
      toolName: "memory_search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("auto-approves alias search when its path stays inside cwd", () => {
    expect(
      classify({
        title: "search: query: TODO, path: src",
        rawInput: { name: "search", query: "TODO", path: "src" },
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("does not auto-approve alias search when its rawInput path escapes cwd", () => {
    expect(
      classify({
        title: "search: ignored-by-raw-input",
        rawInput: { name: "search", query: "key", path: "~/.ssh" },
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("auto-approves alias search when query-like title text contains a path label", () => {
    expect(
      classify({
        title: "search: query: literal text, path: /etc",
        rawInput: { name: "search", query: "literal text, path: /etc" },
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("does not auto-approve alias search when explicit title path escapes cwd", () => {
    expect(
      classify({
        title: "search: path: /etc",
        rawInput: { name: "search", query: "shadow" },
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("does not auto-approve alias search when only locations escape cwd", () => {
    expect(
      classify({
        title: "search: TODO",
        rawInput: { name: "search", query: "TODO" },
        locations: [{ path: "/etc/passwd" }],
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("does not auto-approve alias search when any location escapes cwd", () => {
    expect(
      classify({
        title: "search: TODO",
        rawInput: { name: "search", query: "TODO" },
        locations: [{ path: "src/index.ts" }, { path: "/etc/passwd" }],
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  it("classifies process as exec-capable even for readonly-like actions", () => {
    expect(
      classify({
        title: "process: list",
        rawInput: { name: "process", action: "list" },
      }),
    ).toEqual({
      toolName: "process",
      approvalClass: "exec_capable",
      autoApprove: false,
    });
  });

  it.each([
    {
      title: "cron: status",
      rawInput: { name: "cron", action: "status" },
      expectedToolName: "cron",
      expectedClass: "control_plane",
    },
    {
      title: "nodes: list",
      rawInput: { name: "nodes", action: "list" },
      expectedToolName: "nodes",
      expectedClass: "exec_capable",
    },
  ] as const)(
    "classifies shared ACP backstop tools for $expectedToolName",
    ({ title, rawInput, expectedToolName, expectedClass }) => {
      expect(
        classify({
          title,
          rawInput,
        }),
      ).toEqual({
        toolName: expectedToolName,
        approvalClass: expectedClass,
        autoApprove: false,
      });
    },
  );

  it("classifies gateway as control-plane", () => {
    expect(
      classify({
        title: "gateway: status",
        rawInput: { name: "gateway", action: "status" },
      }),
    ).toEqual({
      toolName: "gateway",
      approvalClass: "control_plane",
      autoApprove: false,
    });
  });

  it("classifies mutating messaging tools as mutating", () => {
    expect(
      classify({
        title: "message: send",
        rawInput: { name: "message", action: "send", message: "hi" },
      }),
    ).toEqual({
      toolName: "message",
      approvalClass: "mutating",
      autoApprove: false,
    });
  });

  it("fails closed on spoofed metadata and title mismatches", () => {
    expect(
      classify({
        title: "exec: uname -a",
        rawInput: { name: "search", query: "uname -a" },
      }),
    ).toEqual({
      toolName: undefined,
      approvalClass: "unknown",
      autoApprove: false,
    });
  });
});

// ---------------------------------------------------------------------------
// GOLDEN SNAPSHOT — exhaustive corpus (L3.12)
//
// MUST be byte-identical before AND after the fold that derives exec/net from
// classifyEffectsSync. If any entry drifts, it is a behavior regression.
//
// Corpus covers:
//   EXEC_CAPABLE_TOOL_IDS  (7 entries): exec, spawn, shell, bash, process, code_execution, nodes
//   SAFE_SEARCH_TOOL_IDS   (3 entries): search, web_search, memory_search
//   CONTROL_PLANE_TOOL_IDS (5 entries): cron, gateway, sessions_spawn, sessions_send, session_status
//   Plus: unknown, other, CWD-scoped, spoofed
// ---------------------------------------------------------------------------

describe("golden snapshot — exhaustive corpus (L3.12 behavior-preservation)", () => {
  // --- EXEC_CAPABLE_TOOL_IDS (7 entries) ---

  it.each(["exec", "spawn", "shell", "bash", "process", "code_execution", "nodes"] as const)(
    "EXEC_CAPABLE: %s → exec_capable/false",
    (toolId) => {
      expect(
        classify({
          title: `${toolId}: run cmd`,
          rawInput: { name: toolId, command: "echo hi" },
        }),
      ).toEqual({
        toolName: toolId,
        approvalClass: "exec_capable",
        autoApprove: false,
      });
    },
  );

  // --- SAFE_SEARCH_TOOL_IDS (3 entries) — trust + in-cwd path ---

  it("SAFE_SEARCH: web_search → readonly_search/true (no path, core tool)", () => {
    expect(
      classify({
        title: "web_search: latest news",
        rawInput: { name: "web_search", query: "latest news" },
      }),
    ).toEqual({
      toolName: "web_search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("SAFE_SEARCH: memory_search → readonly_search/true (no path, core tool)", () => {
    expect(
      classify({
        title: "memory_search: context",
        rawInput: { name: "memory_search", query: "context" },
      }),
    ).toEqual({
      toolName: "memory_search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("SAFE_SEARCH: search alias (trusted alias) → readonly_search/true when path in cwd", () => {
    expect(
      classify({
        title: "search: TODO",
        rawInput: { name: "search", query: "TODO", path: "src" },
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "readonly_search",
      autoApprove: true,
    });
  });

  it("SAFE_SEARCH: search with locations escaping cwd → other/false", () => {
    expect(
      classify({
        title: "search: TODO",
        rawInput: { name: "search", query: "TODO" },
        locations: [{ path: "/etc" }],
      }),
    ).toEqual({
      toolName: "search",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  // --- CONTROL_PLANE_TOOL_IDS (5 entries) ---

  it.each(["cron", "gateway", "sessions_spawn", "sessions_send", "session_status"] as const)(
    "CONTROL_PLANE: %s → control_plane/false",
    (toolId) => {
      expect(
        classify({
          title: `${toolId}: action`,
          rawInput: { name: toolId, action: "status" },
        }),
      ).toEqual({
        toolName: toolId,
        approvalClass: "control_plane",
        autoApprove: false,
      });
    },
  );

  // --- unknown (spoofed / missing tool name) ---

  it("unknown: spoofed meta vs title → unknown/false", () => {
    expect(
      classify({
        title: "bash: rm -rf /",
        rawInput: { name: "read", path: "/etc/passwd" },
      }),
    ).toEqual({
      toolName: undefined,
      approvalClass: "unknown",
      autoApprove: false,
    });
  });

  it("unknown: empty title → unknown/false", () => {
    expect(
      classify({
        title: "",
        rawInput: {},
      }),
    ).toEqual({
      toolName: undefined,
      approvalClass: "unknown",
      autoApprove: false,
    });
  });

  // --- CWD-scoped reads ---

  it("CWD-scoped: read inside cwd → readonly_scoped/true", () => {
    expect(
      classify({
        title: "read: src/utils.ts",
        rawInput: { path: "src/utils.ts" },
        cwd: "/workspace",
      }),
    ).toEqual({
      toolName: "read",
      approvalClass: "readonly_scoped",
      autoApprove: true,
    });
  });

  it("CWD-scoped: read outside cwd → other/false", () => {
    expect(
      classify({
        title: "read: /etc/passwd",
        rawInput: { path: "/etc/passwd" },
        cwd: "/workspace",
      }),
    ).toEqual({
      toolName: "read",
      approvalClass: "other",
      autoApprove: false,
    });
  });

  // --- other (non-mutating, non-exec, unknown type) ---

  it("other: unknown custom tool → other/false", () => {
    expect(
      classify({
        title: "custom_tool: do something",
        rawInput: { name: "custom_tool", action: "something" },
      }),
    ).toEqual({
      toolName: "custom_tool",
      approvalClass: "other",
      autoApprove: false,
    });
  });
});

// ---------------------------------------------------------------------------
// NET-NEW behavior (L3.12): plugin custom tool with capabilities:['net.egress']
// now routes to prompt-required in ACP (was previously 'other'/false, which was
// already prompt-required — but now derivation is from the shared core table).
//
// This test requires the registry mock to simulate a Tier-B plugin declaration.
// We mock the getActivePluginRegistry import used by classifyEffectsSync/classifyTierB.
// ---------------------------------------------------------------------------

describe("net.egress — plugin-declared custom tool (L3.12 net-new)", () => {
  beforeEach(() => {
    vi.mock("../plugins/runtime.js", () => ({
      getActivePluginRegistry: () => ({
        toolMetadata: [
          {
            metadata: {
              toolName: "my_http_client",
              capabilities: ["net.egress"],
            },
          },
        ],
      }),
    }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("plugin tool with net.egress capability is prompt-required (not auto-approved)", () => {
    const result = classify({
      title: "my_http_client: fetch data",
      rawInput: { name: "my_http_client", url: "https://api.example.com/data" },
    });
    // Must be prompt-required (autoApprove: false) — net.egress is never auto-approved.
    // The class must NOT be readonly_search or readonly_scoped (auto-approve classes).
    expect(result.autoApprove).toBe(false);
    expect(result.toolName).toBe("my_http_client");
    expect(["exec_capable", "other"]).toContain(result.approvalClass);
  });

  it("plugin tool with net.egress does not fall to readonly_search even if query-shaped rawInput", () => {
    const result = classify({
      title: "my_http_client: search query",
      rawInput: { name: "my_http_client", query: "something" },
    });
    expect(result.autoApprove).toBe(false);
  });
});
