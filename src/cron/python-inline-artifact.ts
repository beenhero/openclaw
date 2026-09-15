import crypto from "node:crypto";
import type { BigIntStats } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import type { CronPayload } from "./types.js";

export const PYTHON_INLINE_ARTIFACT_FORMAT = "python-inline-stdin-v1" as const;
export const PYTHON_INLINE_FRAME_FORMAT = "python-source-v1" as const;
export const PYTHON_INLINE_SOURCE_MAX_BYTES = 64 * 1024;
export const PYTHON_INLINE_FRAME_MAX_BYTES = 128 * 1024;

/**
 * The only Python loader emitted by the publisher. It reads one bounded JSON
 * frame from stdin, validates every field and digest, then compiles the exact
 * published bytes. In particular, displayPath is never opened at runtime.
 */
export const PYTHON_INLINE_BOOTSTRAP_V1 = String.raw`import base64,binascii,hashlib,json,sys
_MAX=131072
_raw=sys.stdin.buffer.read(_MAX+1)
if len(_raw)>_MAX: raise SystemExit("openclaw: python artifact frame exceeds limit")
try:
 _o=json.loads(_raw.decode("utf-8"))
except Exception as _e:
 raise SystemExit("openclaw: invalid python artifact frame") from _e
_keys={"v","format","virtualFilename","displayPath","sourceBytes","sourceSha256","sourceBase64","scriptArgv"}
if type(_o) is not dict or set(_o)!=_keys: raise SystemExit("openclaw: invalid python artifact fields")
if _o["v"]!=1 or _o["format"]!="python-source-v1": raise SystemExit("openclaw: unsupported python artifact frame")
if type(_o["virtualFilename"]) is not str or not _o["virtualFilename"]: raise SystemExit("openclaw: invalid virtual filename")
if type(_o["displayPath"]) is not str or not _o["displayPath"]: raise SystemExit("openclaw: invalid display path")
if type(_o["sourceBytes"]) is not int or _o["sourceBytes"]<0 or _o["sourceBytes"]>65536: raise SystemExit("openclaw: invalid source size")
if type(_o["sourceSha256"]) is not str or len(_o["sourceSha256"])!=64: raise SystemExit("openclaw: invalid source digest")
if type(_o["sourceBase64"]) is not str: raise SystemExit("openclaw: invalid source encoding")
if type(_o["scriptArgv"]) is not list or any(type(_a) is not str for _a in _o["scriptArgv"]): raise SystemExit("openclaw: invalid script argv")
try:
 _src=base64.b64decode(_o["sourceBase64"],validate=True)
except (ValueError,binascii.Error) as _e:
 raise SystemExit("openclaw: invalid source base64") from _e
if len(_src)!=_o["sourceBytes"] or hashlib.sha256(_src).hexdigest()!=_o["sourceSha256"]: raise SystemExit("openclaw: python artifact digest mismatch")
sys.argv=[_o["virtualFilename"],*_o["scriptArgv"]]
_g={"__name__":"__main__","__file__":_o["virtualFilename"],"__package__":None,"__cached__":None}
exec(compile(_src,_o["virtualFilename"],"exec"),_g,_g)`;

export const PYTHON_INLINE_BOOTSTRAP_SHA256 = crypto
  .createHash("sha256")
  .update(PYTHON_INLINE_BOOTSTRAP_V1)
  .digest("hex");

export type PythonInlineFrame = {
  v: 1;
  format: typeof PYTHON_INLINE_FRAME_FORMAT;
  virtualFilename: string;
  displayPath: string;
  sourceBytes: number;
  sourceSha256: string;
  sourceBase64: string;
  scriptArgv: string[];
};

type PythonCommandPayload = Extract<CronPayload, { kind: "command" }>;

function sha256Hex(value: string | Uint8Array): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sameFileSnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function assertAbsolute(label: string, value: string): void {
  if (!path.isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
}

/** Parse and independently verify a persisted inline-Python stdin frame. */
export function parsePythonInlineFrame(input: string): PythonInlineFrame {
  if (Buffer.byteLength(input, "utf8") > PYTHON_INLINE_FRAME_MAX_BYTES) {
    throw new Error("python artifact frame exceeds limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error("invalid python artifact frame JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid python artifact frame");
  }
  const frame = parsed as Record<string, unknown>;
  const expectedKeys = [
    "displayPath",
    "format",
    "scriptArgv",
    "sourceBase64",
    "sourceBytes",
    "sourceSha256",
    "v",
    "virtualFilename",
  ];
  if (Object.keys(frame).toSorted().join("\0") !== expectedKeys.join("\0")) {
    throw new Error("invalid python artifact frame fields");
  }
  if (
    frame.v !== 1 ||
    frame.format !== PYTHON_INLINE_FRAME_FORMAT ||
    typeof frame.virtualFilename !== "string" ||
    frame.virtualFilename.length === 0 ||
    typeof frame.displayPath !== "string" ||
    frame.displayPath.length === 0 ||
    typeof frame.sourceBytes !== "number" ||
    !Number.isSafeInteger(frame.sourceBytes) ||
    frame.sourceBytes < 0 ||
    frame.sourceBytes > PYTHON_INLINE_SOURCE_MAX_BYTES ||
    typeof frame.sourceSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(frame.sourceSha256) ||
    typeof frame.sourceBase64 !== "string" ||
    !Array.isArray(frame.scriptArgv) ||
    frame.scriptArgv.some((item) => typeof item !== "string")
  ) {
    throw new Error("invalid python artifact frame values");
  }
  const source = Buffer.from(frame.sourceBase64, "base64");
  if (
    source.toString("base64") !== frame.sourceBase64 ||
    source.byteLength !== frame.sourceBytes ||
    sha256Hex(source) !== frame.sourceSha256
  ) {
    throw new Error("python artifact source digest mismatch");
  }
  return {
    v: 1,
    format: PYTHON_INLINE_FRAME_FORMAT,
    virtualFilename: frame.virtualFilename,
    displayPath: frame.displayPath,
    sourceBytes: frame.sourceBytes,
    sourceSha256: frame.sourceSha256,
    sourceBase64: frame.sourceBase64,
    scriptArgv: [...frame.scriptArgv] as string[],
  };
}

/**
 * Freeze an existing Python file into a command payload. Publication is the
 * sole path read: one descriptor is checked before and after the bounded read.
 */
export async function publishPythonInlineArtifact(params: {
  sourcePath: string;
  pythonPath: string;
  cwd: string;
  env?: Record<string, string>;
  scriptArgv?: string[];
  timeoutSeconds?: number;
  noOutputTimeoutSeconds?: number;
  outputMaxBytes?: number;
  continuation?: PythonCommandPayload["continuation"];
  consequences?: PythonCommandPayload["consequences"];
}): Promise<PythonCommandPayload> {
  assertAbsolute("python source path", params.sourcePath);
  assertAbsolute("python executable", params.pythonPath);
  assertAbsolute("command cwd", params.cwd);
  const handle = await open(params.sourcePath, "r");
  let source: Buffer;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      throw new Error("python source must be a regular file");
    }
    if (before.size > BigInt(PYTHON_INLINE_SOURCE_MAX_BYTES)) {
      throw new Error(`python source exceeds ${PYTHON_INLINE_SOURCE_MAX_BYTES} bytes`);
    }
    source = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!sameFileSnapshot(before, after) || BigInt(source.byteLength) !== after.size) {
      throw new Error("python source changed while it was being published");
    }
    if (source.includes(0)) {
      throw new Error("python source must not contain NUL bytes");
    }
  } finally {
    await handle.close();
  }

  const sourceSha256 = sha256Hex(source);
  const virtualFilename = `openclaw-python://${sourceSha256}/${path.basename(params.sourcePath)}`;
  const frame: PythonInlineFrame = {
    v: 1,
    format: PYTHON_INLINE_FRAME_FORMAT,
    virtualFilename,
    displayPath: params.sourcePath,
    sourceBytes: source.byteLength,
    sourceSha256,
    sourceBase64: source.toString("base64"),
    scriptArgv: [...(params.scriptArgv ?? [])],
  };
  const input = JSON.stringify(frame);
  parsePythonInlineFrame(input);

  return {
    kind: "command",
    argv: [params.pythonPath, "-I", "-S", "-c", PYTHON_INLINE_BOOTSTRAP_V1],
    cwd: params.cwd,
    envMode: "replace",
    env: { ...(params.env ?? {}) },
    input,
    artifact: {
      format: PYTHON_INLINE_ARTIFACT_FORMAT,
      sourceSha256,
      sourceBytes: source.byteLength,
      virtualFilename,
      displayPath: params.sourcePath,
      bootstrapSha256: PYTHON_INLINE_BOOTSTRAP_SHA256,
    },
    ...(params.timeoutSeconds !== undefined ? { timeoutSeconds: params.timeoutSeconds } : {}),
    ...(params.noOutputTimeoutSeconds !== undefined
      ? { noOutputTimeoutSeconds: params.noOutputTimeoutSeconds }
      : {}),
    ...(params.outputMaxBytes !== undefined ? { outputMaxBytes: params.outputMaxBytes } : {}),
    ...(params.continuation ? { continuation: params.continuation } : {}),
    ...(params.consequences ? { consequences: params.consequences } : {}),
  };
}
