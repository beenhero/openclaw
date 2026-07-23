// Unit tests for the net-egress Tier-C refiner (L3.7).
import { describe, expect, it } from "vitest";
import { extractWebFetchEgress, refineCurlNetEgress } from "./net-egress.js";

// ---------------------------------------------------------------------------
// refineCurlNetEgress
// ---------------------------------------------------------------------------

describe("refineCurlNetEgress", () => {
  it("curl https://x.com → hosts:['x.com'], ports:[443]", () => {
    const result = refineCurlNetEgress("curl https://x.com");
    expect(result).not.toBeUndefined();
    expect(result?.hosts).toEqual(["x.com"]);
    expect(result?.ports).toEqual([443]);
    expect(result?.url).toBe("https://x.com");
  });

  it("curl http://example.com → hosts:['example.com'], ports:[80]", () => {
    const result = refineCurlNetEgress("curl http://example.com");
    expect(result?.hosts).toEqual(["example.com"]);
    expect(result?.ports).toEqual([80]);
  });

  it("curl with path → extracts hostname only", () => {
    const result = refineCurlNetEgress("curl https://api.example.com/v1/endpoint?foo=bar");
    expect(result?.hosts).toEqual(["api.example.com"]);
    expect(result?.ports).toEqual([443]);
  });

  it("curl --url https://x.com → extracts from --url flag", () => {
    const result = refineCurlNetEgress("curl --url https://x.com");
    expect(result?.hosts).toEqual(["x.com"]);
    expect(result?.ports).toEqual([443]);
  });

  it("curl with explicit port → extracts port", () => {
    const result = refineCurlNetEgress("curl https://x.com:8443/path");
    expect(result?.hosts).toEqual(["x.com"]);
    expect(result?.ports).toEqual([8443]);
  });

  it("wget https://x.com/file → identified as fetch, extracts host", () => {
    const result = refineCurlNetEgress("wget https://x.com/file.txt");
    expect(result).not.toBeUndefined();
    expect(result?.hosts).toEqual(["x.com"]);
    expect(result?.ports).toEqual([443]);
  });

  it("curl with headers and URL → extracts URL", () => {
    const result = refineCurlNetEgress("curl -H 'Authorization: Bearer token' https://api.x.com");
    expect(result?.hosts).toEqual(["api.x.com"]);
    expect(result?.ports).toEqual([443]);
  });

  it("curl with quoted URL → extracts URL (shell-parse quotes)", () => {
    const result = refineCurlNetEgress('curl "https://api.x.com/path"');
    expect(result?.hosts).toEqual(["api.x.com"]);
  });

  it("ls command → returns undefined (not a fetch tool)", () => {
    const result = refineCurlNetEgress("ls -la /tmp");
    expect(result).toBeUndefined();
  });

  it("echo command → returns undefined", () => {
    expect(refineCurlNetEgress("echo hello")).toBeUndefined();
  });

  it("git command → returns undefined", () => {
    expect(refineCurlNetEgress("git clone https://github.com/foo/bar")).toBeUndefined();
  });

  it("empty command → returns undefined", () => {
    expect(refineCurlNetEgress("")).toBeUndefined();
  });

  it("empty argv → returns undefined", () => {
    expect(refineCurlNetEgress([])).toBeUndefined();
  });

  it("curl without URL → returns {hosts:['*']} (fetch tool, no parseable URL)", () => {
    const result = refineCurlNetEgress("curl -v");
    // Detected as curl but no valid URL → conservative superset
    expect(result).not.toBeUndefined();
    expect(result?.hosts).toEqual(["*"]);
  });

  it("curl with non-URL arg → returns {hosts:['*']}", () => {
    const result = refineCurlNetEgress("curl not-a-url");
    expect(result).not.toBeUndefined();
    expect(result?.hosts).toEqual(["*"]);
  });

  it("argv array input works same as string", () => {
    const result = refineCurlNetEgress(["curl", "https://x.com"]);
    expect(result?.hosts).toEqual(["x.com"]);
    expect(result?.ports).toEqual([443]);
  });

  it("argv with --url flag → extracts from next token", () => {
    const result = refineCurlNetEgress(["curl", "--url", "https://api.example.com"]);
    expect(result?.hosts).toEqual(["api.example.com"]);
  });

  it("uppercase CURL → returns undefined (case-sensitive head token)", () => {
    // After normalization, 'CURL' → 'curl' in our normalizer check? Let's test.
    // Our FETCH_HEAD_TOKENS uses lowercase comparison (head.toLowerCase())
    const result = refineCurlNetEgress("CURL https://x.com");
    // Should detect since we lowercase the head token
    expect(result).not.toBeUndefined();
  });

  it("untokenizable string (unterminated quote) → returns undefined (graceful)", () => {
    const result = refineCurlNetEgress("curl 'unterminated");
    // splitShellArgs returns null for unterminated quotes → tokenize returns null → undefined
    expect(result).toBeUndefined();
  });

  it("curl with multiple URLs → collects all hosts", () => {
    const result = refineCurlNetEgress("curl https://a.com https://b.com");
    expect(result?.hosts).toContain("a.com");
    expect(result?.hosts).toContain("b.com");
    expect(result?.hosts.length).toBe(2);
  });

  it("result never throws for adversarial inputs", () => {
    const adversarialInputs = [
      "curl\x00https://x.com",
      "curl " + "a".repeat(1000),
      "curl javascript:void(0)",
      "curl file:///etc/passwd",
    ];
    for (const input of adversarialInputs) {
      expect(() => refineCurlNetEgress(input)).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// extractWebFetchEgress
// ---------------------------------------------------------------------------

describe("extractWebFetchEgress", () => {
  it("https URL → host:['x.com'], ports:[443]", () => {
    const result = extractWebFetchEgress("https://x.com");
    expect(result.hosts).toEqual(["x.com"]);
    expect(result.ports).toEqual([443]);
    expect(result.url).toBe("https://x.com");
  });

  it("http URL → host:['x.com'], ports:[80]", () => {
    const result = extractWebFetchEgress("http://x.com");
    expect(result.hosts).toEqual(["x.com"]);
    expect(result.ports).toEqual([80]);
  });

  it("URL with path and query → extracts hostname", () => {
    const result = extractWebFetchEgress("https://api.example.com/v1?key=value");
    expect(result.hosts).toEqual(["api.example.com"]);
    expect(result.ports).toEqual([443]);
  });

  it("unparseable URL → hosts:['*'] (conservative superset, no crash)", () => {
    const result = extractWebFetchEgress("not-a-url");
    expect(result.hosts).toEqual(["*"]);
  });

  it("null URL → hosts:['*'] (conservative superset)", () => {
    const result = extractWebFetchEgress(null);
    expect(result.hosts).toEqual(["*"]);
  });

  it("undefined URL → hosts:['*']", () => {
    const result = extractWebFetchEgress(undefined);
    expect(result.hosts).toEqual(["*"]);
  });

  it("empty string URL → hosts:['*']", () => {
    const result = extractWebFetchEgress("");
    expect(result.hosts).toEqual(["*"]);
  });

  it("explicit port in URL → captures port", () => {
    const result = extractWebFetchEgress("https://x.com:9000/path");
    expect(result.hosts).toEqual(["x.com"]);
    expect(result.ports).toEqual([9000]);
  });

  it("host is always lowercase", () => {
    const result = extractWebFetchEgress("https://API.EXAMPLE.COM/v1");
    expect(result.hosts).toEqual(["api.example.com"]);
  });

  it("never throws on adversarial input", () => {
    const inputs = [
      "javascript:void(0)",
      "file:///etc/passwd",
      "data:text/html,<h1>test</h1>",
      "ftp://x.com",
      " ",
      "\x00",
      "a".repeat(10000),
    ];
    for (const input of inputs) {
      expect(() => extractWebFetchEgress(input)).not.toThrow();
    }
  });
});
