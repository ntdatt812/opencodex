import { statSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Database, constants } from "bun:sqlite";

import {
  getCodexHome,
  resolveCodexLogsDbPath,
  resolveCodexSqliteHome,
  type CodexSqliteHomeDeps,
} from "../paths";

const IMMUTABLE_READONLY_FLAGS = constants.SQLITE_OPEN_READONLY | constants.SQLITE_OPEN_URI;

interface CurrentLogColumn {
  name: string;
  type: string;
  notnull: number;
  defaultValue: string | null;
  pk: number;
}

// Pinned to Codex logs migration 0002. Keep this schema private: inspection reports
// compatibility, not column names, so sensitive payload-bearing fields never leak through
// the management API. Any additive/rebuilt future schema is monitor-only until reviewed.
const CURRENT_LOG_SCHEMA: readonly CurrentLogColumn[] = [
  { name: "id", type: "INTEGER", notnull: 0, defaultValue: null, pk: 1 },
  { name: "ts", type: "INTEGER", notnull: 1, defaultValue: null, pk: 0 },
  { name: "ts_nanos", type: "INTEGER", notnull: 1, defaultValue: null, pk: 0 },
  { name: "level", type: "TEXT", notnull: 1, defaultValue: null, pk: 0 },
  { name: "target", type: "TEXT", notnull: 1, defaultValue: null, pk: 0 },
  { name: "feedback_log_body", type: "TEXT", notnull: 0, defaultValue: null, pk: 0 },
  { name: "module_path", type: "TEXT", notnull: 0, defaultValue: null, pk: 0 },
  { name: "file", type: "TEXT", notnull: 0, defaultValue: null, pk: 0 },
  { name: "line", type: "INTEGER", notnull: 0, defaultValue: null, pk: 0 },
  { name: "thread_id", type: "TEXT", notnull: 0, defaultValue: null, pk: 0 },
  { name: "process_uuid", type: "TEXT", notnull: 0, defaultValue: null, pk: 0 },
  { name: "estimated_bytes", type: "INTEGER", notnull: 1, defaultValue: "0", pk: 0 },
] as const;

const CURRENT_LOG_TABLE_SQL = `CREATE TABLE logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  ts_nanos INTEGER NOT NULL,
  level TEXT NOT NULL,
  target TEXT NOT NULL,
  feedback_log_body TEXT,
  module_path TEXT,
  file TEXT,
  line INTEGER,
  thread_id TEXT,
  process_uuid TEXT,
  estimated_bytes INTEGER NOT NULL DEFAULT 0
)`;

export type CodexLogGuardCapabilityReason =
  | "database_missing"
  | "database_unreadable"
  | "unknown_schema";

export type CodexLogGuardSchemaState =
  | { state: "compatible" }
  | { state: "missing"; reason: "database_missing" }
  | { state: "unreadable"; reason: "database_unreadable" }
  | { state: "unsupported"; reason: "unknown_schema" };

export type CodexLogGuardCapability =
  | { state: "supported" }
  | { state: "unsupported"; reason: CodexLogGuardCapabilityReason };

export interface CodexLogGuardMetrics {
  totalRows: number;
  rowsByLevel: Record<string, number>;
  traceRows: number;
  traceShare: number;
  topTargets: Array<{ target: string; rows: number }>;
  pageSize: number;
  pageCount: number;
  freelistPages: number;
  reclaimableBytes: number;
  estimatedLogBytes: number | null;
}

/**
 * Serializable, privacy-safe Log Guard inspection result.
 *
 * Canonical filesystem paths are deliberately kept local to the inspector. Consumers get
 * only the coarse location relation (`externalSqliteHome`) and aggregate file/SQLite data.
 */
export interface CodexLogGuardInspection {
  generatedAt: number;
  externalSqliteHome: boolean;
  snapshot: "checkpointed";
  files: {
    databaseBytes: number;
    walBytes: number;
    shmBytes: number;
  };
  schema: CodexLogGuardSchemaState;
  capabilities: {
    inspection: CodexLogGuardCapability;
    protection: CodexLogGuardCapability;
    reclaim: CodexLogGuardCapability;
  };
  metrics: CodexLogGuardMetrics | null;
}

interface ColumnRow {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
}
interface SchemaObjectRow { type: string; sql: string | null }
interface CountRow { n: number }
interface LevelRow { level: string; rows: number }
interface TargetRow { target: string; rows: number }
interface EstimatedBytesRow { bytes: number | null }

type CanonicalTargetState = "missing" | "file" | "unusable";

function canonicalTargetState(path: string): CanonicalTargetState {
  try {
    return statSync(path).isFile() ? "file" : "unusable";
  } catch (error) {
    return (error as NodeJS.ErrnoException | undefined)?.code === "ENOENT" ? "missing" : "unusable";
  }
}

function fileSize(path: string): number {
  try {
    const stat = statSync(path);
    return stat.isFile() ? stat.size : 0;
  } catch {
    return 0;
  }
}

function capabilityFor(schema: CodexLogGuardSchemaState): CodexLogGuardCapability {
  if (schema.state === "compatible") return { state: "supported" };
  return { state: "unsupported", reason: schema.reason };
}

function normalizeDeclaredType(type: string): string {
  return String(type ?? "").trim().toUpperCase();
}

function normalizeDefault(value: string | null): string | null {
  return value === null ? null : String(value).trim();
}

function normalizeSchemaSql(sql: string | null | undefined): string {
  return (sql ?? "").trim().replace(/;\s*$/, "").replace(/\s+/g, " ");
}

function sameColumns(columns: ColumnRow[]): boolean {
  if (columns.length !== CURRENT_LOG_SCHEMA.length) return false;
  return columns.every((column, index) => {
    const expected = CURRENT_LOG_SCHEMA[index];
    return column.cid === index
      && column.name === expected.name
      && normalizeDeclaredType(column.type) === expected.type
      && Number(column.notnull) === expected.notnull
      && normalizeDefault(column.dflt_value) === expected.defaultValue
      && Number(column.pk) === expected.pk;
  });
}

function hasCurrentLogsTable(db: Database, columns: ColumnRow[]): boolean {
  const object = db.query<SchemaObjectRow, []>(
    "SELECT type, sql FROM sqlite_schema WHERE name = 'logs' LIMIT 1",
  ).get();
  return object?.type === "table"
    && sameColumns(columns)
    && normalizeSchemaSql(object.sql) === normalizeSchemaSql(CURRENT_LOG_TABLE_SQL);
}

function pragmaNumber(db: Database, pragma: "page_size" | "page_count" | "freelist_count"): number {
  const row = db.query<Record<string, number>, []>(`PRAGMA ${pragma}`).get();
  return Number(row?.[pragma] ?? 0);
}

function readMetrics(db: Database, columns: string[]): CodexLogGuardMetrics | null {
  if (!columns.includes("level") || !columns.includes("target")) return null;

  try {
    const totalRows = Number(db.query<CountRow, []>("SELECT count(*) AS n FROM logs").get()?.n ?? 0);
    const rowsByLevel: Record<string, number> = {};
    for (const row of db.query<LevelRow, []>(
      "SELECT level, count(*) AS rows FROM logs GROUP BY level ORDER BY level",
    ).all()) {
      const level = String(row.level ?? "UNKNOWN").toUpperCase();
      rowsByLevel[level] = (rowsByLevel[level] ?? 0) + Number(row.rows ?? 0);
    }

    const topTargets = db.query<TargetRow, []>(
      "SELECT target, count(*) AS rows FROM logs GROUP BY target ORDER BY rows DESC, target ASC LIMIT 10",
    ).all().map(row => ({ target: String(row.target), rows: Number(row.rows ?? 0) }));

    const pageSize = pragmaNumber(db, "page_size");
    const pageCount = pragmaNumber(db, "page_count");
    const freelistPages = pragmaNumber(db, "freelist_count");
    const traceRows = rowsByLevel.TRACE ?? 0;
    const estimatedLogBytes = columns.includes("estimated_bytes")
      ? Number(db.query<EstimatedBytesRow, []>(
        "SELECT COALESCE(sum(estimated_bytes), 0) AS bytes FROM logs",
      ).get()?.bytes ?? 0)
      : null;

    return {
      totalRows,
      rowsByLevel,
      traceRows,
      traceShare: totalRows > 0 ? traceRows / totalRows : 0,
      topTargets,
      pageSize,
      pageCount,
      freelistPages,
      reclaimableBytes: pageSize * freelistPages,
      estimatedLogBytes,
    };
  } catch {
    // A future schema may still have a `logs` table but change aggregate-compatible
    // columns or virtual-table behaviour. Metadata inspection remains valid; metrics do
    // not become a reason to throw or to open a writable connection.
    return null;
  }
}

/**
 * Inspect the canonical Codex diagnostic log database without participating in SQLite's
 * write/locking protocol. `immutable=1` intentionally observes the last checkpointed
 * snapshot: file sizes include live sidecars, while SQL aggregates may lag a live WAL.
 * This is a zero-write health view, not an SSD/NAND write-rate measurement.
 */
export function inspectCodexLogs(deps: CodexSqliteHomeDeps = {}): CodexLogGuardInspection {
  const codexHome = deps.codexHome ?? getCodexHome();
  const resolutionDeps: CodexSqliteHomeDeps = { ...deps, codexHome };
  const sqliteHome = resolveCodexSqliteHome(resolutionDeps);
  const databasePath = resolveCodexLogsDbPath(resolutionDeps);
  const targetState = canonicalTargetState(databasePath);
  const files = {
    databaseBytes: fileSize(databasePath),
    walBytes: fileSize(`${databasePath}-wal`),
    shmBytes: fileSize(`${databasePath}-shm`),
  };

  const common = {
    generatedAt: Date.now(),
    externalSqliteHome: resolve(sqliteHome) !== resolve(codexHome),
    snapshot: "checkpointed" as const,
    files,
  };

  if (targetState === "missing") {
    const schema: CodexLogGuardSchemaState = { state: "missing", reason: "database_missing" };
    const mutation = capabilityFor(schema);
    return {
      ...common,
      schema,
      metrics: null,
      capabilities: {
        inspection: { state: "supported" },
        protection: mutation,
        reclaim: mutation,
      },
    };
  }

  if (targetState === "unusable") {
    const schema: CodexLogGuardSchemaState = { state: "unreadable", reason: "database_unreadable" };
    const mutation = capabilityFor(schema);
    return {
      ...common,
      schema,
      metrics: null,
      capabilities: {
        inspection: { state: "supported" },
        protection: mutation,
        reclaim: mutation,
      },
    };
  }

  // SQLite accepts a zero-byte file as an empty database. For Log Guard this is not a
  // compatible future schema: Codex's canonical logs database must already contain its
  // migrated `logs` table before any future mutation capability can be considered safe.
  if (files.databaseBytes === 0) {
    const schema: CodexLogGuardSchemaState = { state: "unreadable", reason: "database_unreadable" };
    const mutation = capabilityFor(schema);
    return {
      ...common,
      schema,
      metrics: null,
      capabilities: {
        inspection: { state: "supported" },
        protection: mutation,
        reclaim: mutation,
      },
    };
  }

  try {
    const uri = `${pathToFileURL(databasePath).href}?immutable=1`;
    const db = new Database(uri, IMMUTABLE_READONLY_FLAGS);
    try {
      const columnRows = db.query<ColumnRow, []>("PRAGMA table_info(logs)").all();
      const columns = columnRows.map(row => row.name);
      const schema: CodexLogGuardSchemaState = hasCurrentLogsTable(db, columnRows)
        ? { state: "compatible" }
        : { state: "unsupported", reason: "unknown_schema" };
      const mutation = capabilityFor(schema);
      return {
        ...common,
        schema,
        metrics: readMetrics(db, columns),
        capabilities: {
          inspection: { state: "supported" },
          protection: mutation,
          reclaim: mutation,
        },
      };
    } finally {
      db.close();
    }
  } catch {
    const schema: CodexLogGuardSchemaState = { state: "unreadable", reason: "database_unreadable" };
    const mutation = capabilityFor(schema);
    return {
      ...common,
      schema,
      metrics: null,
      capabilities: {
        inspection: { state: "supported" },
        protection: mutation,
        reclaim: mutation,
      },
    };
  }
}
