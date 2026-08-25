// Unit tests for the fs-write Tier-C refiner (Layer 6, L6.1).
import { describe, expect, it } from "vitest";
import { extractNativeWritePaths, refineWriteFsPaths } from "./fs-write.js";

// ---------------------------------------------------------------------------
// refineWriteFsPaths — write-command identification
// ---------------------------------------------------------------------------

describe("refineWriteFsPaths — non-write commands → undefined", () => {
  it("ls → undefined (not a write command)", () => {
    expect(refineWriteFsPaths("ls -la /tmp")).toBeUndefined();
  });

  it("cat (no redirection) → undefined", () => {
    expect(refineWriteFsPaths("cat /etc/hosts")).toBeUndefined();
  });

  it("grep → undefined", () => {
    expect(refineWriteFsPaths("grep foo /tmp/bar")).toBeUndefined();
  });

  it("echo (no redirection) → undefined", () => {
    expect(refineWriteFsPaths("echo hello")).toBeUndefined();
  });

  it("curl → undefined (not a write command)", () => {
    expect(refineWriteFsPaths("curl https://example.com")).toBeUndefined();
  });

  it("empty string → undefined", () => {
    expect(refineWriteFsPaths("")).toBeUndefined();
  });

  it("empty argv → undefined", () => {
    expect(refineWriteFsPaths([])).toBeUndefined();
  });
});

describe("refineWriteFsPaths — touch", () => {
  it("touch /tmp/x → paths:['/tmp/x']", () => {
    expect(refineWriteFsPaths("touch /tmp/x")).toEqual({ paths: ["/tmp/x"] });
  });

  it("touch multiple files → all paths included", () => {
    const result = refineWriteFsPaths("touch /tmp/a /tmp/b");
    expect(result?.paths).toContain("/tmp/a");
    expect(result?.paths).toContain("/tmp/b");
  });

  it("touch with no path → paths:['*'] (conservative superset)", () => {
    expect(refineWriteFsPaths("touch")).toEqual({ paths: ["*"] });
  });

  it("/bin/touch /tmp/x → basename recognized (absolute path)", () => {
    expect(refineWriteFsPaths("/bin/touch /tmp/x")).toEqual({ paths: ["/tmp/x"] });
  });
});

describe("refineWriteFsPaths — tee", () => {
  it("tee /a/b → paths:['/a/b']", () => {
    expect(refineWriteFsPaths("tee /a/b")).toEqual({ paths: ["/a/b"] });
  });

  it("tee with no path → paths:['*']", () => {
    expect(refineWriteFsPaths("tee")).toEqual({ paths: ["*"] });
  });
});

describe("refineWriteFsPaths — cp / mv", () => {
  it("cp /src /dst → last positional only (/dst)", () => {
    expect(refineWriteFsPaths("cp /src /dst")).toEqual({ paths: ["/dst"] });
  });

  it("mv /old /new → last positional only (/new)", () => {
    expect(refineWriteFsPaths("mv /old /new")).toEqual({ paths: ["/new"] });
  });

  it("cp -r /a /b/c → /b/c (last positional)", () => {
    expect(refineWriteFsPaths("cp -r /a /b/c")).toEqual({ paths: ["/b/c"] });
  });

  it("cp with no positionals → paths:['*']", () => {
    expect(refineWriteFsPaths("cp")).toEqual({ paths: ["*"] });
  });
});

describe("refineWriteFsPaths — dd", () => {
  it("dd if=/dev/zero of=/tmp/out → extracts of= path", () => {
    expect(refineWriteFsPaths("dd if=/dev/zero of=/tmp/out bs=1M count=10")).toEqual({
      paths: ["/tmp/out"],
    });
  });

  it("dd without of= → paths:['*']", () => {
    expect(refineWriteFsPaths("dd if=/dev/zero")).toEqual({ paths: ["*"] });
  });
});

describe("refineWriteFsPaths — mkdir / rm / rmdir", () => {
  it("mkdir /new/dir → paths:['/new/dir']", () => {
    expect(refineWriteFsPaths("mkdir /new/dir")).toEqual({ paths: ["/new/dir"] });
  });

  it("mkdir -p /a/b/c → paths:['/a/b/c']", () => {
    expect(refineWriteFsPaths("mkdir -p /a/b/c")).toEqual({ paths: ["/a/b/c"] });
  });

  it("rm /tmp/f → paths:['/tmp/f'] (rm is a write/delete)", () => {
    expect(refineWriteFsPaths("rm /tmp/f")).toEqual({ paths: ["/tmp/f"] });
  });

  it("rm -rf /tmp → paths:['/tmp']", () => {
    expect(refineWriteFsPaths("rm -rf /tmp")).toEqual({ paths: ["/tmp"] });
  });
});

describe("refineWriteFsPaths — sed -i (in-place edit)", () => {
  it("sed -i 's/a/b/' /etc/cfg → paths:['/etc/cfg']", () => {
    expect(refineWriteFsPaths("sed -i 's/a/b/' /etc/cfg")).toEqual({ paths: ["/etc/cfg"] });
  });

  it("sed -i.bak 's/a/b/' /etc/cfg → paths:['/etc/cfg']", () => {
    expect(refineWriteFsPaths("sed -i.bak 's/a/b/' /etc/cfg")).toEqual({ paths: ["/etc/cfg"] });
  });

  it("sed without -i (not in-place) → undefined (read-only)", () => {
    expect(refineWriteFsPaths("sed 's/foo/bar/' /etc/cfg")).toBeUndefined();
  });
});

describe("refineWriteFsPaths — install / rsync", () => {
  it("install -m 755 src /usr/local/bin/foo → last positional", () => {
    expect(refineWriteFsPaths("install -m 755 src /usr/local/bin/foo")).toEqual({
      paths: ["/usr/local/bin/foo"],
    });
  });

  it("rsync /a /b → last positional (/b)", () => {
    expect(refineWriteFsPaths("rsync /a /b")).toEqual({ paths: ["/b"] });
  });
});

describe("refineWriteFsPaths — redirection operators", () => {
  it("echo hi > /out → fs.write via redirection", () => {
    expect(refineWriteFsPaths("echo hi > /out")).toEqual({ paths: ["/out"] });
  });

  it("echo hi >> /out → fs.write via >> redirection", () => {
    expect(refineWriteFsPaths("echo hi >> /out")).toEqual({ paths: ["/out"] });
  });

  it(">>/out (no space) → path extracted", () => {
    expect(refineWriteFsPaths(["echo", "hi", ">>/out"])).toEqual({ paths: ["/out"] });
  });

  it(">/out (no space) → path extracted", () => {
    expect(refineWriteFsPaths(["echo", "hi", ">/out"])).toEqual({ paths: ["/out"] });
  });

  it("2>/dev/null → redirection path extracted", () => {
    expect(refineWriteFsPaths(["some_cmd", "2>/dev/null"])).toEqual({ paths: ["/dev/null"] });
  });
});

describe("refineWriteFsPaths — bash -lc shell unwrap", () => {
  it("bash -lc 'tee /a/b' → fs.write (unwrapped, path extracted)", () => {
    expect(refineWriteFsPaths(`/bin/bash -lc 'tee /a/b'`)).toEqual({ paths: ["/a/b"] });
  });

  it("sh -c 'touch /tmp/x' → fs.write (unwrapped)", () => {
    expect(refineWriteFsPaths(`sh -c 'touch /tmp/x'`)).toEqual({ paths: ["/tmp/x"] });
  });

  it("bash -lc 'ls -la /tmp' → undefined (not a write command after unwrap)", () => {
    expect(refineWriteFsPaths(`bash -lc 'ls -la /tmp'`)).toBeUndefined();
  });

  it("bash -lc 'curl https://x.com' → undefined (curl is not a write command)", () => {
    expect(refineWriteFsPaths(`bash -lc 'curl https://x.com'`)).toBeUndefined();
  });

  it("bash -lc 'echo hi > /out' → fs.write (redirection after unwrap)", () => {
    expect(refineWriteFsPaths(`bash -lc 'echo hi > /out'`)).toEqual({ paths: ["/out"] });
  });

  it("/bin/bash -lc 'rm /tmp/f' → fs.write (rm is write/delete)", () => {
    expect(refineWriteFsPaths(`/bin/bash -lc 'rm /tmp/f'`)).toEqual({ paths: ["/tmp/f"] });
  });
});

describe("refineWriteFsPaths — malformed / conservative fallback", () => {
  it("unterminated quote string → undefined (not parsed as write)", () => {
    // splitShellArgs returns null for unterminated quotes — not identified as write
    const result = refineWriteFsPaths("touch '/tmp/bad");
    // Either undefined (not identified) or conservative paths:['*']
    if (result !== undefined) {
      expect(result.paths).toContain("*");
    }
  });

  it("write command with no parseable path → paths:['*'] (no crash)", () => {
    expect(refineWriteFsPaths("rm")).toEqual({ paths: ["*"] });
  });

  it("never throws on any input (arbitrary strings)", () => {
    const inputs = [
      "touch",
      "mv",
      "rm -rf",
      "dd if=/dev/zero",
      "",
      "   ",
      "touch '/",
      null as unknown as string,
      undefined as unknown as string,
      42 as unknown as string,
    ];
    for (const input of inputs) {
      expect(() => refineWriteFsPaths(input)).not.toThrow();
    }
  });

  it("WIDEN-ONLY: result always has paths.length >= 1 for a write command", () => {
    const writeCommands = ["touch /a", "rm /b", "tee /c", "mkdir /d"];
    for (const cmd of writeCommands) {
      const result = refineWriteFsPaths(cmd);
      expect(result).toBeDefined();
      expect(result!.paths.length).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// extractNativeWritePaths — native write-tool params extraction
// ---------------------------------------------------------------------------

describe("extractNativeWritePaths", () => {
  it("params.path string → {paths:[path]}", () => {
    expect(extractNativeWritePaths({ path: "/tmp/x" })).toEqual({ paths: ["/tmp/x"] });
  });

  it("params.file_path string → {paths:[file_path]}", () => {
    expect(extractNativeWritePaths({ file_path: "/etc/hosts" })).toEqual({
      paths: ["/etc/hosts"],
    });
  });

  it("params.path takes precedence over file_path when both present", () => {
    const result = extractNativeWritePaths({ path: "/a", file_path: "/b" });
    // path is checked first
    expect(result).toEqual({ paths: ["/a"] });
  });

  it("null params → {paths:['*']}", () => {
    expect(extractNativeWritePaths(null)).toEqual({ paths: ["*"] });
  });

  it("undefined params → {paths:['*']}", () => {
    expect(extractNativeWritePaths(undefined)).toEqual({ paths: ["*"] });
  });

  it("empty object → {paths:['*']}", () => {
    expect(extractNativeWritePaths({})).toEqual({ paths: ["*"] });
  });

  it("path is empty string → {paths:['*']}", () => {
    expect(extractNativeWritePaths({ path: "" })).toEqual({ paths: ["*"] });
  });

  it("path is non-string → {paths:['*']}", () => {
    expect(extractNativeWritePaths({ path: 42 })).toEqual({ paths: ["*"] });
    expect(extractNativeWritePaths({ path: null })).toEqual({ paths: ["*"] });
  });

  it("never throws", () => {
    const inputs = [null, undefined, 42, "string", [], true, { path: 123 }];
    for (const input of inputs) {
      expect(() => extractNativeWritePaths(input)).not.toThrow();
    }
  });
});
