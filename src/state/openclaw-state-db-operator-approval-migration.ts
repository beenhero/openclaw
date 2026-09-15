// Doctor-only repair for closed operator-approval schema enums.
import type { DatabaseSync } from "node:sqlite";
import { runSqliteImmediateTransactionSync } from "../infra/sqlite-transaction.js";
import { tableExists } from "./openclaw-state-db-schema-helpers.js";
import { OPENCLAW_STATE_SCHEMA_SQL } from "./openclaw-state-schema.js";

const COLUMNS = [
  "approval_id",
  "resolution_ref",
  "kind",
  "status",
  "presentation_json",
  "requested_by_device_id",
  "requested_by_client_id",
  "requested_by_device_token_auth",
  "reviewer_device_ids_json",
  "source_agent_id",
  "source_session_key",
  "source_session_id",
  "source_run_id",
  "source_tool_call_id",
  "source_tool_name",
  "audience_session_keys_json",
  "runtime_epoch",
  "created_at_ms",
  "expires_at_ms",
  "updated_at_ms",
  "decision",
  "terminal_reason",
  "resolved_at_ms",
  "resolver_kind",
  "resolver_id",
  "consumed_at_ms",
  "consumed_by",
] as const;

function tableSql(db: DatabaseSync): string | undefined {
  const row = db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'operator_approvals'")
    .get() as { sql?: unknown } | undefined;
  return typeof row?.sql === "string" ? row.sql : undefined;
}

function hasCanonicalOperatorApprovalKinds(db: DatabaseSync): boolean {
  if (!tableExists(db, "operator_approvals")) {
    return true;
  }
  return /kind\s+text\s+not\s+null\s+check\s*\(\s*kind\s+in\s*\(\s*'exec'\s*,\s*'plugin'\s*,\s*'system-agent'\s*\)\s*\)/.test(
    tableSql(db)?.toLowerCase() ?? "",
  );
}

function hasCanonicalOperatorApprovalTerminalReasons(db: DatabaseSync): boolean {
  if (!tableExists(db, "operator_approvals")) {
    return true;
  }
  const sql = tableSql(db)?.toLowerCase() ?? "";
  return (
    /terminal_reason\s+text\s+check\s*\(\s*terminal_reason\s+in\s*\(\s*'user'\s*,\s*'auto-review'\s*,\s*'policy-handoff'/.test(
      sql,
    ) &&
    /status\s*=\s*'allowed'\s+and\s*\(\s*\(\s*decision\s+in\s*\(\s*'allow-once'\s*,\s*'allow-always'\s*\)\s+and\s+terminal_reason\s*=\s*'user'\s*\)\s+or\s*\(\s*decision\s*=\s*'allow-once'\s+and\s+terminal_reason\s+in\s*\(\s*'auto-review'\s*,\s*'policy-handoff'\s*\)\s*\)\s*\)/.test(
      sql,
    )
  );
}

function hasCanonicalOperatorApprovalSchema(db: DatabaseSync): boolean {
  return hasCanonicalOperatorApprovalKinds(db) && hasCanonicalOperatorApprovalTerminalReasons(db);
}

export function assertCanonicalOperatorApprovalKinds(db: DatabaseSync, pathname: string): void {
  if (!hasCanonicalOperatorApprovalSchema(db)) {
    throw new Error(
      `OpenClaw state database ${pathname} has a legacy operator approval schema; run openclaw doctor --fix to migrate it.`,
    );
  }
}

export function isCanonicalOperatorApprovalKind(
  value: unknown,
): value is "exec" | "plugin" | "system-agent" {
  return value === "exec" || value === "plugin" || value === "system-agent";
}

export function detectOperatorApprovalSchemaMigration(db: DatabaseSync, path: string) {
  return hasCanonicalOperatorApprovalSchema(db)
    ? []
    : [{ kind: "operator-approvals-system-agent" as const, path }];
}

function normalizeDdl(sql: string): string {
  // sqlite_master stores the CREATE statement without a trailing semicolon.
  return sql.replace(/\s+/g, " ").trim().replace(/;$/, "");
}

function canonicalOperatorApprovalCreateSql(): string {
  const marker = "CREATE TABLE IF NOT EXISTS operator_approvals (";
  const tableTerminator = "\n) STRICT;";
  const start = OPENCLAW_STATE_SCHEMA_SQL.indexOf(marker);
  const end = OPENCLAW_STATE_SCHEMA_SQL.indexOf(
    `${tableTerminator}\n\nCREATE INDEX IF NOT EXISTS idx_operator_approvals_status_expiry`,
    start,
  );
  if (start < 0 || end < 0) {
    throw new Error("canonical operator approval schema is unavailable");
  }
  return OPENCLAW_STATE_SCHEMA_SQL.slice(start, end + tableTerminator.length);
}

function alterAppendedResolutionRefCreateSql(sql: string): string {
  const resolutionRefStart = sql.indexOf("\n  resolution_ref ");
  const followingColumnStart = sql.indexOf("\n  kind ", resolutionRefStart);
  const tailColumn = "\n  consumed_by TEXT,";
  const tailColumnStart = sql.indexOf(tailColumn, followingColumnStart);
  if (resolutionRefStart < 0 || followingColumnStart < 0 || tailColumnStart < 0) {
    throw new Error("canonical operator approval resolution reference schema is unavailable");
  }
  const withoutResolutionRef = sql.slice(0, resolutionRefStart) + sql.slice(followingColumnStart);
  return withoutResolutionRef.replace(tailColumn, `${tailColumn} resolution_ref TEXT,`);
}

function removeAutomatedTerminalReasons(sql: string): string {
  return replaceAllowedDecisionReasonRule(sql, [
    "      AND decision IN ('allow-once', 'allow-always')",
    "      AND terminal_reason = 'user'",
  ]).replace(/\n\s*'auto-review',\n\s*'policy-handoff',/u, "");
}

function restoreBroadAutomatedTerminalReasons(sql: string): string {
  return replaceAllowedDecisionReasonRule(sql, [
    "      AND decision IN ('allow-once', 'allow-always')",
    "      AND terminal_reason IN ('user', 'auto-review', 'policy-handoff')",
  ]);
}

function replaceAllowedDecisionReasonRule(sql: string, replacement: string[]): string {
  const canonicalRule = [
    "      AND (",
    "        (",
    "          decision IN ('allow-once', 'allow-always')",
    "          AND terminal_reason = 'user'",
    "        )",
    "        OR (",
    "          decision = 'allow-once'",
    "          AND terminal_reason IN ('auto-review', 'policy-handoff')",
    "        )",
    "      )",
  ].join("\n");
  const replaced = sql.replace(canonicalRule, replacement.join("\n"));
  if (replaced === sql) {
    throw new Error("canonical operator approval lifecycle rule is unavailable");
  }
  return replaced;
}

// The only legacy shapes this repair may destructively replace are the exact
// prior canonical table with the two-kind constraint (before 'system-agent')
// and its shipped ALTER-appended resolution_ref variant.
// Matching column names alone is not fail-closed: a table with the same names
// but different constraints/defaults/types would get its rows copied under a
// schema that silently discards those semantics.
function hasExactLegacyOperatorApprovalSchema(db: DatabaseSync): boolean {
  const live = tableSql(db);
  if (!live) {
    return false;
  }
  const exactStrictCanonical = canonicalOperatorApprovalCreateSql().replace(
    "CREATE TABLE IF NOT EXISTS operator_approvals (",
    "CREATE TABLE operator_approvals (",
  );
  const exactStrictLegacy = exactStrictCanonical
    // sqlite_master stores the CREATE statement without "IF NOT EXISTS".
    .replace(/'exec',\s*'plugin',\s*'system-agent'/, "'exec', 'plugin'");
  const exactStrictBroadReasons = restoreBroadAutomatedTerminalReasons(exactStrictCanonical);
  const exactStrictLegacyKindsAndBroadReasons =
    restoreBroadAutomatedTerminalReasons(exactStrictLegacy);
  const exactStrictPreviousReasons = removeAutomatedTerminalReasons(exactStrictCanonical);
  const exactStrictLegacyKindsAndReasons = removeAutomatedTerminalReasons(exactStrictLegacy);
  const normalizedLive = normalizeDdl(live);
  const supportedLegacyShapes = [
    exactStrictLegacy,
    exactStrictBroadReasons,
    exactStrictLegacyKindsAndBroadReasons,
    exactStrictPreviousReasons,
    exactStrictLegacyKindsAndReasons,
  ];
  const alterAppendedLegacyShapes = supportedLegacyShapes.map(alterAppendedResolutionRefCreateSql);
  return [...supportedLegacyShapes, ...alterAppendedLegacyShapes].some((strictLegacy) =>
    [strictLegacy, strictLegacy.replace(/\) STRICT;$/u, ");")]
      .map(normalizeDdl)
      .includes(normalizedLive),
  );
}

function canonicalCreateSql(): string {
  return canonicalOperatorApprovalCreateSql().replace(
    "CREATE TABLE IF NOT EXISTS operator_approvals (",
    "CREATE TABLE operator_approvals_migration_new (",
  );
}

// Rebuilding the table drops its indexes. Replay only the operator-approval
// index statements: executing the full schema here fails on many-versions-
// behind databases whose other tables still lack columns the later additive
// and STRICT repairs add (e.g. "no such column: agent_id").
function operatorApprovalIndexSql(): string {
  const statements = OPENCLAW_STATE_SCHEMA_SQL.split(";")
    .map((statement) => statement.trim())
    .filter((statement) =>
      /^CREATE (?:UNIQUE )?INDEX IF NOT EXISTS idx_operator_approvals_/.test(statement),
    );
  if (statements.length === 0) {
    throw new Error("canonical operator approval index schema is unavailable");
  }
  return `${statements.join(";\n")};`;
}

function repairOperatorApprovalKinds(db: DatabaseSync): boolean {
  if (
    hasCanonicalOperatorApprovalSchema(db) ||
    tableExists(db, "operator_approvals_migration_new") ||
    !hasExactLegacyOperatorApprovalSchema(db)
  ) {
    return false;
  }
  const columns = COLUMNS.join(", ");
  // The copy/drop/rename must be atomic: a crash after DROP but before RENAME
  // would strand the rows in the temp table, and the next schema bootstrap would
  // recreate an empty canonical table and abandon them.
  runSqliteImmediateTransactionSync(db, () => {
    db.exec(canonicalCreateSql());
    // The ALTER-appended variant is nullable, so pre-ref rows can hold NULL or
    // junk that violates the canonical NOT NULL/shape CHECK. Approvals are
    // transient runtime state: drop nonconforming rows instead of aborting the
    // whole repair and re-wedging startup. The filter mirrors the canonical
    // CHECK exactly.
    db.exec(`
      INSERT INTO operator_approvals_migration_new (${columns})
      SELECT ${columns} FROM operator_approvals
      WHERE typeof(resolution_ref) = 'text'
        AND length(resolution_ref) = 43
        AND resolution_ref NOT GLOB '*[^A-Za-z0-9_-]*'
        AND NOT (
          status = 'allowed'
          AND terminal_reason IN ('auto-review', 'policy-handoff')
          AND decision != 'allow-once'
        );
      DROP TABLE operator_approvals;
      ALTER TABLE operator_approvals_migration_new RENAME TO operator_approvals;
    `);
    db.exec(operatorApprovalIndexSql());
  });
  return true;
}

export function repairOperatorApprovalSchema(db: DatabaseSync): string[] {
  return repairOperatorApprovalKinds(db)
    ? ["Migrated shared state operator approvals → OpenClaw system changes"]
    : [];
}
